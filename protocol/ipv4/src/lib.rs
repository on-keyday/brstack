use core::net;
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
        for i in 0..prefix.prefix_length {
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

        for i in 0..32 {
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

pub trait ICMPSender {
    fn send_time_exceeded(
        &self,
        code :net_common::ICMPv4TimeExceededCode,
        original_packet: packet::IPv4Packet<'_>,
    );
    fn send_destination_unreachable(
        &self,
        next_hop_mtu: u16,
        code : net_common::ICMPv4DstUnreachableCode,
        original_packet: packet::IPv4Packet<'_>,
    );
}

struct RouterState {
    routing_table: RoutingTable,
    arp: arp::AddressResolutionTable,
    protocols: RwLock<std::collections::HashMap<u8, Box<dyn IPv4Receiver + Send + Sync>>>,
    icmp_sender: RwLock<Option<Box<dyn ICMPSender + Send + Sync>>>,
}

#[derive(Clone)]
pub struct Router {
    state: std::sync::Arc<RouterState>,
}

#[derive(Debug)]
pub enum ProtocolError {
    NoRouteToHost,
    ChecksumMismatch,
    PacketTooLarge(usize,usize),
}

#[derive(Debug)]
pub enum Error {
    Packet(packet::Error),
    Ethernet(ethernet::Error),
    Arp(arp::Error),
    Protocol(ProtocolError),
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

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::NoRouteToHost => write!(f, "No route to host"),
            ProtocolError::ChecksumMismatch => write!(f, "Checksum mismatch"),
            ProtocolError::PacketTooLarge(size,limit) => write!(f, "Packet too large: {} bytes (limit: {} bytes)", size, limit),
        }
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

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Packet(e) => Some(e),
            Error::Ethernet(e) => Some(e),
            Error::Arp(e) => Some(e),
            Error::Protocol(_) => None,
            Error::UpperLayerError(e) => None,
        }
    }
}

fn check_checksum(hdr: &packet::IPv4Header<'_>) -> Result<(), Error> {
    let checksum = hdr.checksum;
    let mut hdr = hdr.clone();
    hdr.checksum = 0;
    let mut buffer = [0u8; 100];
    let checksum_target = hdr.encode_to_fixed(&mut buffer)?;
    let computed_checksum = packet::checkSum(std::borrow::Cow::Borrowed(&checksum_target));
    if checksum != computed_checksum {
        return Err(Error::Protocol(ProtocolError::ChecksumMismatch));
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
                icmp_sender: RwLock::new(None),
            }),
        }
    }

    pub fn register_icmp_sender(
        &self,
        sender: Box<dyn ICMPSender + Send + Sync>,
    ) {
        *self.state.icmp_sender.write().unwrap() = Some(sender);
        log::info!("Registered ICMP sender");
    }

    pub fn register_protocol(
        &self,
        proto: packet::ProtocolNumber,
        receiver: Box<dyn IPv4Receiver + Send + Sync>,
    ) {
        self.state.protocols.write().unwrap().insert(proto.into(), receiver);
        log::info!(
            "Registered protocol: {}",
            proto,
        );
    }

    pub async fn get_route(
        &self,
        address: net_common::Ipv4Address,
    ) -> Option<std::sync::Arc<RoutingEntry>> {
        self.state.routing_table.lookup(&address).await
    }

    pub async fn add_route(
        &self,
        prefix: net_common::Ipv4Prefix,
        next_hop: net_common::Ipv4Address,
        device: ethernet::NetworkInterface,
    ) {
        let name = device.name().to_string();
        self.state.routing_table.insert(prefix, next_hop, device).await;
        if next_hop != net_common::Ipv4Address([0, 0, 0, 0]) {
            log::info!(
                "Added route: {} via {} at device {}",
                prefix,
                next_hop,
                name,
            );
        } else {
            log::info!(
                "Added route: {} is directly connected at device {}",
                prefix,
                name,
            );
        }
    }

    async fn send_direct(
        &self,
        proto: packet::ProtocolNumber,
        ttl: u8,
        src_addr: net_common::Ipv4Address,
        dst_addr: net_common::Ipv4Address,
        dst_mac: &net_common::MacAddress,
        device: &ethernet::NetworkInterface,
        data: &[u8],
    ) -> Result<(), Error> {
        if data.len() > 2048 {
            return Err(Error::Protocol(ProtocolError::PacketTooLarge(data.len(), 2048)));
        }
        let mut pkt = packet::IPv4Packet::default();
        pkt.hdr.set_version(4);
        pkt.hdr.set_ihl(5);
        pkt.hdr.dst_addr = dst_addr.0;
        pkt.hdr.src_addr = src_addr.0;
        pkt.hdr.proto = proto;
        pkt.hdr.len = (data.len() + 20) as u16;
        pkt.hdr.checksum = 0;
        pkt.hdr.set_dont_fragment(true);
        pkt.hdr.ttl = ttl;
        let mut buffer = [0u8; 20];
        pkt.hdr.encode_to_fixed(&mut buffer)?;
        pkt.hdr.checksum = packet::checkSum(std::borrow::Cow::Borrowed(&buffer));
        pkt.data = std::borrow::Cow::Borrowed(data);
        if device.mtu() < pkt.hdr.len as u32 { // フラグメンテーションをサポートしないので...
            return Err(Error::Protocol(ProtocolError::PacketTooLarge(
                pkt.hdr.len as usize,
                device.mtu() as usize,
            )));
        }
        assert!(pkt.hdr.len as usize <= 2048); // 今のところは!
        let mut buffer = [0u8; 2048];
        let data = pkt.encode_to_fixed(&mut buffer)?;
        device
            .send(ethernet::frame::EtherType::IPv4, dst_mac, data)
            .await?;    
        Ok(())
    }

    pub fn send_port_unreachable(
        &self,
        original_packet: packet::IPv4Packet<'_>,
    )  {
        if let Some(icmp_sender) = self.state.icmp_sender.read().unwrap().as_ref() {
            icmp_sender.send_destination_unreachable(
                0,
                net_common::ICMPv4DstUnreachableCode::port_unreachable,
                original_packet,
            );
        }
    }

    async fn send_routed(
        &self,
        proto: packet::ProtocolNumber,
        ttl: u8,
        src_addr: Option<net_common::Ipv4Address>,
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
            let src_addr = src_addr.unwrap_or_else(|| entry.device.ipv4_address().address);
            if resolve_target != dst_addr {
                log::debug!(
                    "Routing packet from {} to {} via {} at device {}",
                    src_addr,
                    dst_addr,
                    resolve_target,
                    entry.device.name(),
                );
            } else {
                log::debug!(
                    "Routing packet from {} to {} at device {}",
                    src_addr,
                    dst_addr,
                    entry.device.name(),
                );
            }
            self.send_direct(proto, ttl, src_addr, dst_addr, &dst_mac, &entry.device, data)
                .await
        } else {
            Err(Error::Protocol(ProtocolError::NoRouteToHost))
        }
    }

    pub async fn send(
        &self,
        proto: packet::ProtocolNumber,
        dst_addr: net_common::Ipv4Address,
        data: &[u8],
    ) -> Result<(), Error> {
        self.send_routed(proto, 64,None, dst_addr, data).await
    }

    async fn route(&self, pkt: packet::IPv4Packet<'_>) {
        if pkt.hdr.ttl <= 1 {
            log::warn!("TTL expired");
            if let Some(icmp_sender) = self.state.icmp_sender.read().unwrap().as_ref() {
                icmp_sender.send_time_exceeded(
                    net_common::ICMPv4TimeExceededCode::ttl_exceeded_in_transit,
                    pkt,
                );
            }
            return;
        }
        self.send_routed(
            pkt.hdr.proto,
            pkt.hdr.ttl - 1,
            Some(net_common::Ipv4Address(pkt.hdr.src_addr)),
            net_common::Ipv4Address(pkt.hdr.dst_addr),
            pkt.data.as_ref(),
        )
        .await
        .unwrap_or_else(|e| {
            log::error!("Failed to route packet from {} to {}: {}", 
                net_common::Ipv4Address(pkt.hdr.src_addr),
                net_common::Ipv4Address(pkt.hdr.dst_addr),
                e,
            );
            match e {
                Error::Protocol(ProtocolError::NoRouteToHost) => {
                    if let Some(icmp_sender) = self.state.icmp_sender.read().unwrap().as_ref() {
                        icmp_sender.send_destination_unreachable(
                            0,
                            net_common::ICMPv4DstUnreachableCode::net_unreachable,
                            pkt,
                        );
                    }
                }       
                Error::Protocol(ProtocolError::PacketTooLarge(_,limit)) => {
                    if let Some(icmp_sender) = self.state.icmp_sender.read().unwrap().as_ref() {
                        icmp_sender.send_destination_unreachable(
                            limit as u16,
                            net_common::ICMPv4DstUnreachableCode::fragmentation_needed_but_df_set,
                            pkt,
                        );
                    }
                }
                Error::Arp(_) => {
                    if let Some(icmp_sender) = self.state.icmp_sender.read().unwrap().as_ref() {
                        icmp_sender.send_destination_unreachable(
                            0,
                            net_common::ICMPv4DstUnreachableCode::host_unreachable,
                            pkt,
                        );
                    }
                }
                _ => {}
            }
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
            let ip = self.clone();
            // ルーティングテーブルを参照してルーティングする
            tokio::spawn(async move {
                ip.route(pkt).await;
            });        
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
            if let Some(icmp_sender) = self.state.icmp_sender.read().unwrap().as_ref() {
                icmp_sender.send_destination_unreachable(
                    0,
                    net_common::ICMPv4DstUnreachableCode::protocol_unreachable,
                    pkt,
                );
            }
        }
        Ok(())
    }
}
