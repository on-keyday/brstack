



pub mod datagram;

struct PortMapper {
    port_map: std::collections::HashMap<u16, // local port
                std::collections::HashMap<
                    net_common::Ipv4Address, // local address
                    std::collections::HashMap<net_common::AddrPort, // remote address/port
                            tokio::sync::mpsc::Sender<(Vec<u8>, net_common::AddrPort)>>>>
}

impl PortMapper {
    pub fn new() -> Self {
        Self {
            port_map: std::collections::HashMap::new(),
        }
    }

    // src=local address, dst=remote address
    // ref:
    // udp_lib_lport_inuse
    // https://github.com/torvalds/linux/blob/d0c22de9995b624f563bc5004d44ac2655712a56/net/ipv4/udp.c#L141
    // inet_rcv_saddr_equal
    // https://github.com/torvalds/linux/blob/d0c22de9995b624f563bc5004d44ac2655712a56/net/ipv4/inet_connection_sock.c#L91
    pub fn insert(&mut self, four_tuple: net_common::FourTuple, sender: tokio::sync::mpsc::Sender<(Vec<u8>,net_common::AddrPort)>) -> bool {
        if four_tuple.src.port == 0 {
            log::warn!("Cannot bind to port 0");
            return false; // Cannot bind to port 0
        }
        let local_addresses = self.port_map.entry(four_tuple.src.port)
        .or_insert_with(std::collections::HashMap::new);
        if local_addresses.contains_key(&net_common::UNSPECIFIED) { // 0.0.0.0にバインドしたものがある場合そちらは全てのアドレスに対して受信するので、ポートが重複している場合は許可しない
            log::warn!("Port {} is already in use for 0.0.0.0", four_tuple.src.port);
            return false; // Port is already in use for UNSPECIFIED
        }
        let remote_addresses = local_addresses.entry(four_tuple.src.address).or_insert_with(std::collections::HashMap::new);
        if remote_addresses.contains_key(&net_common::AddrPort::new(net_common::UNSPECIFIED, 0)) { // 既にワイルドカードでの受信がされる(サーバーなど)場合は許可しない
            log::warn!("Port {} is already in use for local address {}", four_tuple.src.port, four_tuple.src.address);
            return false; // Port is already in use for this local address
        }
        match remote_addresses.entry(four_tuple.dst) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(sender);
                true // Successfully inserted
            },
            std::collections::hash_map::Entry::Occupied(_) => {
                log::warn!("Port {} is already in use for destination {}", four_tuple.dst.port, four_tuple.dst.address);
                false // Port is already in use for this destination
            }
        }
    }

    pub fn get(&self, four_tuple: &net_common::FourTuple) -> Option<&tokio::sync::mpsc::Sender<(Vec<u8>,net_common::AddrPort)>> {
        self.port_map.get(&four_tuple.src.port)
            .and_then(|addr_map| addr_map.get(&four_tuple.src.address))
            .and_then(|dst_map| dst_map.get(&four_tuple.dst))
    }

    pub fn remove(&mut self, four_tuple: &net_common::FourTuple) -> Option<tokio::sync::mpsc::Sender<(Vec<u8>,net_common::AddrPort)>> {
        if let Some(local_addresses) = self.port_map.get_mut(&four_tuple.src.port) {
            if let Some(remote_addresses) = local_addresses.get_mut(&four_tuple.src.address) {
                if let Some(sender) = remote_addresses.remove(&four_tuple.dst) {
                    if remote_addresses.is_empty() {
                        local_addresses.remove(&four_tuple.src.address);
                    }
                    if local_addresses.is_empty() {
                        self.port_map.remove(&four_tuple.src.port);
                    }
                    return Some(sender);
                }
            }
        }
        None // No matching four-tuple found
    }
}

struct UDPState {
    port_mapper: tokio::sync::RwLock<PortMapper>,
    ipv4 :ipv4::Router,
    local_port_range : std::ops::RangeInclusive<u16>,
}

pub struct UDPSocket {
    four_tuple: net_common::FourTuple,
    hub : UDPHub,
    receiver: tokio::sync::mpsc::Receiver<(Vec<u8>,net_common::AddrPort)>,
}

impl UDPSocket {
    fn new(four_tuple: net_common::FourTuple, hub: UDPHub, receiver :tokio::sync::mpsc::Receiver<(Vec<u8>,net_common::AddrPort)>) -> Self {
        Self {
            four_tuple,
            hub,
            receiver,
        }
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        self.hub.send(self.four_tuple.clone(), data).await
    }

    pub async fn send_to(&self, addr: net_common::AddrPort, data: &[u8]) -> Result<(), Error> {
        let four_tuple = net_common::FourTuple::new(self.four_tuple.src, addr);
        self.hub.send(four_tuple, data).await
    }

    pub async fn receive_from(&mut self) -> Result<(Vec<u8>,net_common::AddrPort), Error> {
        match self.receiver.recv().await {
            Some((data, addr)) => Ok((data, addr)),
            None => Err(Error::Protocol("Receiver closed".to_string())),
        }
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        if self.four_tuple.dst.address.is_unspecified() {
            log::warn!("receive() called on a socket with unspecified destination address. This is likely a server socket that should use receive_from() instead.");
        }
       self.receive_from().await.map(|(data, _addr)| data)
    }

    pub fn local_addr(&self) -> net_common::AddrPort {
        self.four_tuple.src
    }
    pub fn remote_addr(&self) -> net_common::AddrPort {
        self.four_tuple.dst
    }
}

impl Drop for UDPSocket {
    fn drop(&mut self) {
        let hub = self.hub.clone();
        let four_tuple = self.four_tuple.clone();
        tokio::spawn(async move {
            let mut port_mapper = hub.state.port_mapper.write().await;
            port_mapper.remove(&four_tuple).or_else(|| {
                log::warn!("Failed to remove UDP socket for four-tuple: {}", four_tuple);
                None
            });
        });
    }
}

#[derive(Debug)]
pub enum Error {
    DatagramError(datagram::Error),
    IPv4Error(ipv4::Error),
    Protocol(String)
}

impl From<datagram::Error> for Error {
    fn from(e: datagram::Error) -> Self {
        Error::DatagramError(e)
    }
}

impl From<ipv4::Error> for Error {
    fn from(e: ipv4::Error) -> Self {
        Error::IPv4Error(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DatagramError(e) => write!(f, "DatagramError: {}", e),
            Error::IPv4Error(e) => write!(f, "IPv4Error: {}", e),
            Error::Protocol(s) => write!(f, "Protocol error: {}", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::DatagramError(e) => Some(e),
            Error::IPv4Error(e) => Some(e),
            Error::Protocol(_) => None,
        }
    }
}

#[derive(Clone)]
pub struct UDPHub {
    state: std::sync::Arc<UDPState>,
}


fn udp_checksum(udp_datagram: &[u8], src_addr: net_common::Ipv4Address, dst_addr: net_common::Ipv4Address) -> u16 {
    let pseudo_header = ipv4::packet::IPv4PseudoHeader {
        srcAddr: src_addr.0,
        dstAddr: dst_addr.0,
        zero: 0,
        protocol: ipv4::packet::ProtocolNumber::UDP,
        length: udp_datagram.len() as u16,
        ..Default::default()
    };
    let mut buffer :[u8; 12] = [0; 12];
    let pseudo = pseudo_header.encode_to_fixed(&mut buffer)
        .expect("Failed to encode pseudo header");
    let mut checksum = ipv4::packet::CheckSum{..Default::default()};
    checksum = ipv4::packet::checkSumUpdate(checksum, std::borrow::Cow::Borrowed(&pseudo));
    checksum = ipv4::packet::checkSumUpdate(checksum, std::borrow::Cow::Borrowed(udp_datagram));
    ipv4::packet::checkSumFinish(checksum)
}


impl UDPHub {
    pub fn new(ipv4 :ipv4::Router) -> Self {
        let udp = Self {
            state: std::sync::Arc::new(UDPState {
                port_mapper: tokio::sync::RwLock::new(PortMapper::new()),
                ipv4: ipv4.clone(),
                local_port_range: 1024..=65535, // Default port range for dynamic ports
            }),
        };
        ipv4.register_protocol(ipv4::packet::ProtocolNumber::UDP, Box::new(udp.clone()));
        udp
    }

    async fn send(&self,tuple :net_common::FourTuple,data :&[u8]) -> Result<(), Error> {
        if data.len() > 0xffff - 8 {
            log::warn!("UDP datagram is too large");
            return Err(Error::Protocol(format!("UDP datagram is too large: {} bytes", data.len())));
        }
        if tuple.src.port == 0 || tuple.dst.port == 0 {
            log::warn!("UDP datagram has unspecified port");
            return Err(Error::Protocol("UDP datagram has unspecified port".to_string()));
        }
        if tuple.dst.address.is_unspecified() {
            log::warn!("UDP datagram has unspecified destination address");
            return Err(Error::Protocol("UDP datagram has unspecified destination address".to_string()));
        }
        let src_ip_addr =  if tuple.src.address.is_unspecified() { // serverがsend_toで呼び出す場合のシナリオ
            let route = match self.state.ipv4.get_route(tuple.dst.address).await {
                Some(route) => route,
                None => {
                    log::warn!("No route to address {}", tuple.dst.address);
                    return Err(Error::Protocol(format!("No route to address {}", tuple.dst.address)));
                }
            }; 
            route.device.ipv4_address().address
        } else {
            tuple.src.address
        };
        let datagram = datagram::UDPDatagram{
            header: datagram::UDPHeader {
                src_port: tuple.src.port,
                dst_port: tuple.dst.port,
                length: (8 + data.len()) as u16,
                checksum: 0,
                ..Default::default()
            },
            data: std::borrow::Cow::Borrowed(data),
            ..Default::default()
        };
        // チェックサムを計算するためにデータをエンコード
        let mut data = datagram.encode_to_vec()?;
        let checksum = udp_checksum(&data, src_ip_addr, tuple.dst.address);
        data[6] = (checksum >> 8) as u8; // checksumの上位バイト
        data[7] = (checksum & 0xff) as u8; // checksumの下位バイト
        self.state.ipv4.send(ipv4::packet::ProtocolNumber::UDP,tuple.dst.address, &data).await?;
        Ok(())
    }

    async fn auto_bind(&self,dst_addr: net_common::AddrPort,src_ip :net_common::Ipv4Address) -> Result<UDPSocket,Error> {
        let mut port_mapper = self.state.port_mapper.write().await;
        let (sender, receiver) = tokio::sync::mpsc::channel(32);
        for port in self.state.local_port_range.clone() {
            let four_tuple = net_common::FourTuple::new(net_common::AddrPort::new(src_ip, port), dst_addr);
            if port_mapper.insert(four_tuple.clone(), sender.clone()) {
                return Ok(UDPSocket::new(four_tuple, self.clone(), receiver));
            }
        }
        Err(Error::Protocol("No available ports".to_string()))
    }

    pub async fn bind(&self, self_addr: net_common::AddrPort) -> Result<UDPSocket, Error> {
        if self_addr.port == 0 {
            log::warn!("Cannot bind to port 0");
            return Err(Error::Protocol("Cannot bind to port 0".to_string()));
        }
        // port_mapperではsrcが自分側dstが相手側の4タプルを管理する
        let four_tuple = net_common::FourTuple::new(self_addr,net_common::AddrPort::new(net_common::UNSPECIFIED, 0));
        let (sender, receiver) = tokio::sync::mpsc::channel(32);
        {
            let mut port_mapper = self.state.port_mapper.write().await;
            port_mapper.insert(four_tuple.clone(), sender);
        }
        Ok(UDPSocket::new(four_tuple, self.clone(), receiver))
    }

    pub async fn connect(&self, addr: net_common::AddrPort, src_port :Option<u16>) -> Result<UDPSocket, Error> {
        if addr.address.is_unspecified() {
            log::warn!("Cannot connect to unspecified address");
            return Err(Error::Protocol("Cannot connect to unspecified address".to_string()));
        }
        if addr.port == 0 {
            log::warn!("Cannot connect to port 0");
            return Err(Error::Protocol("Cannot connect to port 0".to_string()));
        }
        let route = match self.state.ipv4.get_route(addr.address).await {
            Some(route) => route,
            None => {
                log::warn!("No route to address {}", addr.address);
                return Err(Error::Protocol(format!("No route to address {}", addr.address)));
            }
        };
        // src_portが指定されている場合はそのポートの使用を試みる
        if let Some(port) = src_port {
            if port == 0 {
                log::warn!("Cannot connect with port 0");
                return Err(Error::Protocol("Cannot connect with port 0".to_string()));
            }
            let four_tuple = net_common::FourTuple::new(net_common::AddrPort::new(route.device.ipv4_address().address, port), addr);
            let (sender, receiver) = tokio::sync::mpsc::channel(32);
            {
                let mut port_mapper = self.state.port_mapper.write().await;
                if !port_mapper.insert(four_tuple.clone(), sender) {
                    log::warn!("Port {} is already in use", port);
                    return Err(Error::Protocol(format!("Port {} is already in use", port)));
                }
            }
            return Ok(UDPSocket::new(four_tuple, self.clone(), receiver));
        }
        self.auto_bind(addr,route.device.ipv4_address().address).await
    }

}

impl ipv4::IPv4Receiver for UDPHub {
    fn receive(&self, pkt: ipv4::packet::IPv4Packet<'static>) -> Result<(), Box<dyn std::error::Error>> {
        let mut pkt = pkt;
        let (udp_dgram,_) = datagram::UDPDatagram::decode_slice(&pkt.data)?;
        if udp_dgram.header.checksum != 0 {
            pkt.data.to_mut()[6] = 0; // チェックサムを0に設定してチェックサムの計算を行う
            pkt.data.to_mut()[7] = 0; 
            let checksum = udp_checksum(&pkt.data.as_ref()[..udp_dgram.header.length as usize], net_common::Ipv4Address(pkt.hdr.src_addr), net_common::Ipv4Address(pkt.hdr.dst_addr));
            if udp_dgram.header.checksum != 0 && udp_dgram.header.checksum != checksum {
                log::warn!("UDP checksum mismatch: expected {}, got {}", udp_dgram.header.checksum, checksum);
                return Ok(());
            }
            pkt.data.to_mut()[6] = (checksum >> 8) as u8; // チェックサムの上位バイト 
            pkt.data.to_mut()[7] = (checksum & 0xff) as u8; // チェックサムの下位バイト
        }
        let src_addr = net_common::AddrPort::new(net_common::Ipv4Address(pkt.hdr.src_addr), udp_dgram.header.src_port);
        let dst_addr = net_common::AddrPort::new(net_common::Ipv4Address(pkt.hdr.dst_addr), udp_dgram.header.dst_port);
        // 検索用4タプルはsrcがlocal,dstがremoteのものなのでここでは逆にする
        let four_tuple = net_common::FourTuple::new(dst_addr, src_addr);
        let bind_explicit_addr = { // サーバー受信時の場合(相手アドレスがわからないが自分のアドレスは明示)
            let mut cloned = four_tuple.clone();
            cloned.dst.address = net_common::UNSPECIFIED;
            cloned.dst.port = 0; // UNSPECIFIED port
            cloned
        };       
        let bind_wildcard = { // サーバー受信時の場合(相手アドレスがわからなくてかつ自分のアドレスもワイルドカード指定)
            let mut cloned = four_tuple.clone();
            cloned.dst.address = net_common::UNSPECIFIED;
            cloned.dst.port = 0; // UNSPECIFIED port
            cloned.src.address = net_common::UNSPECIFIED; // ワイルドカード指定
            cloned
        };
        let search_candidates = [four_tuple, bind_explicit_addr, bind_wildcard];
        let udp =self.clone();
        tokio::spawn(async move {
            let  port_mapper = udp.state.port_mapper.read().await;
            for candidate in search_candidates.iter() {
                if let Some(sender) = port_mapper.get(candidate) {
                    if let Err(e) = sender.send((udp_dgram.data.into_owned(), net_common::AddrPort::new(net_common::Ipv4Address(pkt.hdr.src_addr), udp_dgram.header.src_port))).await {
                        log::warn!("Failed to send UDP datagram to user: {}", e);
                    }
                    return;
                }
            }
            log::warn!("No matching UDP socket found for datagram {}",four_tuple);
            udp.state.ipv4.send_port_unreachable(pkt);
        });
        Ok(())
    }
}
