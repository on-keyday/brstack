use std::sync::RwLock;

pub mod packet;
pub struct RoutingEntry {
    pub prefix: net_common::Ipv4Prefix,
    pub next_hop: net_common::Ipv4Address,
    pub device: ethernet::NetworkInterface,
}

struct RoutingTrieNode {
    pub children: [Option<Box<RoutingTrieNode>>; 2],
    pub entry: Option<std::sync::Arc<RoutingEntry>>,
}
impl RoutingTrieNode {
    pub fn new() -> Self {
        RoutingTrieNode {
            children: [None, None],
            entry: None,
        }
    }
}

pub struct RoutingTable {
    root: tokio::sync::RwLock<RoutingTrieNode>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable {
            root: tokio::sync::RwLock::new(RoutingTrieNode::new()),
        }
    }

    pub async fn insert(
        &self,
        prefix: net_common::Ipv4Prefix,
        next_hop: net_common::Ipv4Address,
        device: ethernet::NetworkInterface,
    ) {
        let mut node = self.root.write().await;
        let mut node = &mut *node;
        for i in (0..prefix.prefix_length).rev() {
            let bit = (prefix.address.0[(i / 8) as usize] >> (7 - (i % 8))) & 1;
            if node.children[bit as usize].is_none() {
                node.children[bit as usize] = Some(Box::new(RoutingTrieNode::new()));
            }
            node = node.children[bit as usize].as_mut().unwrap();
        }
        node.entry = Some(std::sync::Arc::new(RoutingEntry {
            prefix,
            next_hop,
            device,
        }));
    }

    pub async fn lookup(
        &self,
        address: &net_common::Ipv4Address,
    ) -> Option<std::sync::Arc<RoutingEntry>> {
        let node = self.root.read().await;
        let mut node = &*node;
        let mut best_entry: Option<&std::sync::Arc<RoutingEntry>> = None;

        for i in (0..32).rev() {
            if let Some(entry) = &node.entry {
                best_entry = Some(entry);
            }
            let bit = (address.0[(i / 8) as usize] >> (7 - (i % 8))) & 1;
            if node.children[bit as usize].is_none() {
                break;
            }
            node = node.children[bit as usize].as_ref().unwrap();
        }

        best_entry.cloned()
    }
}

pub trait IPv4Receiver {
    fn receive(&self, pkt: packet::IPv4Packet<'static>) -> Result<(), Box<dyn std::error::Error>>;
}

struct RouterState {
    routing_table: RoutingTable,
    arp: arp::AddressResolutionTable,
    protocols: RwLock<std::collections::HashMap<u8, Box<dyn IPv4Receiver + Send + Sync>>>,
}

#[derive(Clone)]
pub struct Router {
    state: std::sync::Arc<RouterState>,
}

#[derive(Debug)]
pub enum Error {
    Packet(packet::Error),
    Ethernet(ethernet::Error),
    Arp(arp::Error),
    Protocol(String),
    UpperLayerError(Box<dyn std::error::Error>),
}

impl From<packet::Error> for Error {
    fn from(err: packet::Error) -> Self {
        Error::Packet(err)
    }
}
impl From<arp::Error> for Error {
    fn from(err: arp::Error) -> Self {
        Error::Arp(err)
    }
}
impl From<ethernet::Error> for Error {
    fn from(err: ethernet::Error) -> Self {
        Error::Ethernet(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Packet(e) => write!(f, "Packet error: {}", e),
            Error::Ethernet(e) => write!(f, "Ethernet error: {}", e),
            Error::Arp(e) => write!(f, "ARP error: {}", e),
            Error::Protocol(e) => write!(f, "Protocol error: {}", e),
            Error::UpperLayerError(e) => write!(f, "Upper layer error: {}", e),
        }
    }
}

fn check_checksum(hdr: &packet::IPv4Header<'_>) -> Result<(), Error> {
    let checksum = hdr.checksum;
    let mut hdr = hdr.clone();
    hdr.checksum = 0;
    let mut buffer = [0u8; 20];
    let checksum_target = hdr.encode_to_fixed(&mut buffer)?;
    let computed_checksum = packet::checkSum(std::borrow::Cow::Borrowed(&checksum_target));
    if checksum != computed_checksum {
        return Err(Error::Protocol("Checksum mismatch".to_string()));
    }
    Ok(())
}

impl Router {
    pub fn new(arp: arp::AddressResolutionTable) -> Self {
        Router {
            state: std::sync::Arc::new(RouterState {
                routing_table: RoutingTable::new(),
                arp,
                protocols: RwLock::new(std::collections::HashMap::new()),
            }),
        }
    }

    pub fn register_protocol(
        &mut self,
        proto: packet::ProtocolNumber,
        receiver: Box<dyn IPv4Receiver + Send + Sync>,
    ) {
        self.state.protocols.write().unwrap().insert(proto.into(), receiver);
    }

    pub async fn add_route(
        &mut self,
        prefix: net_common::Ipv4Prefix,
        next_hop: net_common::Ipv4Address,
        device: ethernet::NetworkInterface,
    ) {
        self.state.routing_table.insert(prefix, next_hop, device).await;
    }

    async fn send_direct(
        &self,
        proto: packet::ProtocolNumber,
        ttl: u8,
        dst_addr: net_common::Ipv4Address,
        dst_mac: &net_common::MacAddress,
        device: &ethernet::NetworkInterface,
        data: &[u8],
    ) -> Result<(), Error> {
        if data.len() > 2048 {
            return Err(Error::Protocol(format!(
                "Data length exceeds 2048 bytes: {}",
                data.len()
            )));
        }
        let mut pkt = packet::IPv4Packet::default();
        pkt.hdr.set_version(4);
        pkt.hdr.set_ihl(5);
        pkt.hdr.dst_addr = dst_addr.0;
        pkt.hdr.src_addr = device.ipv4_address().address.0;
        pkt.hdr.proto = proto;
        pkt.hdr.len = (data.len() + 20) as u16;
        pkt.hdr.checksum = 0;
        pkt.hdr.set_dont_fragment(true);
        pkt.hdr.ttl = ttl;
        let mut buffer = [0u8; 20];
        pkt.hdr.encode_to_fixed(&mut buffer)?;
        pkt.hdr.checksum = packet::checkSum(std::borrow::Cow::Borrowed(&buffer));
        pkt.data = std::borrow::Cow::Borrowed(data);
        let mut buffer = [0u8; 2048];
        let data = pkt.encode_to_fixed(&mut buffer)?;
        device
            .send(ethernet::frame::EtherType::IPv4, dst_mac, data)
            .await?;
        Ok(())
    }

    async fn send_routed(
        &self,
        proto: packet::ProtocolNumber,
        ttl: u8,
        dst_addr: net_common::Ipv4Address,
        data: &[u8],
    ) -> Result<(), Error> {
        let entry = self.state.routing_table.lookup(&dst_addr).await;
        if let Some(entry) = entry {
            let resolve_target = if entry.next_hop == net_common::Ipv4Address([0, 0, 0, 0]) {
                dst_addr
            } else {
                entry.next_hop
            };
            let dst_mac = self.state.arp.get_dst_mac(&entry.device, &resolve_target).await?;
            self.send_direct(proto, ttl, dst_addr, &dst_mac, &entry.device, data)
                .await
        } else {
            Err(Error::Protocol("No route to host".to_string()))
        }
    }

    pub async fn send(
        &self,
        proto: packet::ProtocolNumber,
        dst_addr: net_common::Ipv4Address,
        data: &[u8],
    ) -> Result<(), Error> {
        self.send_routed(proto, 64, dst_addr, data).await
    }

    async fn route(&self, pkt: packet::IPv4Packet<'_>) {
        if pkt.hdr.ttl <= 1 {
            log::warn!("TTL expired");
            return;
        }
        self.send_routed(
            pkt.hdr.proto,
            pkt.hdr.ttl - 1,
            net_common::Ipv4Address(pkt.hdr.dst_addr),
            pkt.data.as_ref(),
        )
        .await
        .unwrap_or_else(|e| {
            log::error!("Failed to route packet: {}", e);
        });
    }

    pub async fn receive(
        &self,
        device: &ethernet::NetworkInterface,
        frame: &ethernet::frame::EthernetFrame<'_>,
    ) -> Result<(), Error> {
        let data = frame.data().unwrap();
        let (pkt, _) = packet::IPv4Packet::decode_slice(&data)?;
        check_checksum(&pkt.hdr)?;
        let dst_addr = net_common::Ipv4Address(pkt.hdr.dst_addr);
        if device.ipv4_address().address != dst_addr
            && !device.ipv4_address().is_broadcast_address(dst_addr)
            && dst_addr != net_common::Ipv4Address([0xff; 4])
        {
            // ルーティングテーブルを参照してルーティングする
            self.route(pkt).await;
            return Ok(());
        }
        let proto = pkt.hdr.proto;
        let protocols = self.state.protocols.read().unwrap();
        if let Some(receiver) = protocols.get(&proto.into()) {
            receiver
                .receive(pkt)
                .map_err(|e| Error::UpperLayerError(e))?;
        } else {
            log::warn!("No protocol handler for protocol number {}", proto);
        }
        Ok(())
    }
}
