mod packet;

#[derive(Clone)]
pub struct ICMPService {
    ipv4: ipv4::Router,
}

impl ICMPService {
    pub fn new(ipv4: ipv4::Router) -> Self {
        ICMPService {
            ipv4,
        }
    }

    async fn send(&self,dst_addr :net_common::Ipv4Address, mut packet: packet::ICMPv4Packet<'_>) -> Result<(), Error> {
        packet.header.checksum = 0;
        let mut buffer = [0u8; 100];
        let checksum_target = packet.encode_to_fixed(&mut buffer)?;
        packet.header.checksum = ipv4::packet::checkSum(std::borrow::Cow::Borrowed(&checksum_target));
        let final_encoded = packet.encode_to_fixed(&mut buffer)?;
        self.ipv4.send(
            ipv4::packet::ProtocolNumber::ICMP,
            dst_addr,
            final_encoded,
        ).await?;
        Ok(())
    }

    pub async fn send_echo_request(&self, dst_addr: net_common::Ipv4Address,id :u16,seq :u16, data: &[u8]) -> Result<(), Error> {
        let mut packet = packet::ICMPv4Packet::default();
        packet.header.type_ = packet::ICMPv4Type::echo.into();
        let mut echo_request = packet::ICMPEcho::default();
        echo_request.id = id;
        echo_request.seq = seq;
        echo_request.data = std::borrow::Cow::Borrowed(data);
        packet.set_echo(echo_request)?;
        self.send(dst_addr, packet).await
    }

    pub async fn send_destination_unreachable(&self, dst_addr: net_common::Ipv4Address,code :net_common::ICMPv4DstUnreachableCode,next_hop_mtu :u16, received_data :&[u8]) -> Result<(), Error> {
        let mut packet = packet::ICMPv4Packet::default();
        packet.header.type_ = packet::ICMPv4Type::dst_unreachable.into();
        packet.header.code = code.into();
        let mut unreachable = packet::ICMPDestinationUnreachable::default();
        unreachable.next_hop_mtu = next_hop_mtu;
        unreachable.data = std::borrow::Cow::Borrowed(&received_data);
        self.send(dst_addr, packet).await
    }
}

#[derive(Debug)]
pub enum Error {
    Packet(packet::Error),
    Protocol(String),
    IPv4(ipv4::Error),
}

impl From<packet::Error> for Error {
    fn from(err: packet::Error) -> Self {
        Error::Packet(err)
    }
}

impl From<ipv4::Error> for Error {
    fn from(err: ipv4::Error) -> Self {
        Error::IPv4(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Packet(e) => write!(f, "Packet error: {}", e),
            Error::Protocol(e) => write!(f, "Protocol error: {}", e),
            Error::IPv4(e) => write!(f, "IPv4 error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

fn check_checksum(icmp :&packet::ICMPv4Packet<'_>) -> Result<(), Error> {
    let checksum = icmp.header.checksum;
    let mut icmp = icmp.clone();
    icmp.header.checksum = 0;
    let mut buffer = [0u8; 64];
    icmp.encode_to_fixed(&mut buffer)?;
    let computed_checksum = ipv4::packet::checkSum(std::borrow::Cow::Borrowed(&buffer));
    if checksum != computed_checksum {
        return Err(Error::Protocol("Checksum mismatch".to_string()));
    }
    Ok(())
}

impl ipv4::IPv4Receiver for ICMPService {

    fn receive(&self, packet: ipv4::packet::IPv4Packet<'static>) -> Result<(), Box<dyn std::error::Error>> {
        let icmp_packet = packet::ICMPv4Packet::decode_exact(&packet.data)?;
        check_checksum(&icmp_packet)?;
        if let Some(echo) = icmp_packet.echo() {
            log::debug!("Received ICMP echo request: {:?}", echo);
            let mut response = icmp_packet.clone();
            response.header.type_ = packet::ICMPv4Type::echo_reply.into();
            response.set_echo_reply(echo.clone())?;
            let icmp = self.clone();
            tokio::spawn(async move {
                if let Err(e) = icmp.send(net_common::Ipv4Address(packet.hdr.src_addr), response).await {
                    log::error!("ICMP send error: {}", e);
                }
            });           
        } else if let Some(reply) = icmp_packet.echo_reply() {
            log::info!("Received ICMP echo reply: {:?}", reply);
        } else if let Some(dst_unreachable) = icmp_packet.destination_unreachable() {
            log::info!("Received ICMP destination unreachable: {:?}", dst_unreachable);
        } else {
            log::warn!("Received unknown ICMP packet: {:?}", icmp_packet);
        }
        Ok(())
    }
}
