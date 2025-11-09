use std::sync::{Arc, Mutex};


pub mod packet;

struct StunState {
    udp :tokio::sync::Mutex<udp::UDPSocket>,
    transaction_id :[u8;12],
}

pub struct StunClient {
    state :Arc<StunState>,
}

#[derive(Debug)]
pub enum Error {
    UDPError(udp::Error),
    PacketError(packet::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UDPError(e) => write!(f, "UDP error: {}", e),
            Error::PacketError(e) => write!(f, "Packet error: {}", e),
        }
    }
}

impl From<udp::Error> for Error {
    fn from(e: udp::Error) -> Self {
        Error::UDPError(e)
    }
}

impl From<packet::Error> for Error {
    fn from(e: packet::Error) -> Self {
        Error::PacketError(e)
    }
}

pub fn demap_xor_address(transaction_id :[u8;12], xor_mapped :&packet::MappedAddress) -> packet::MappedAddress{
    let port = packet::xor_port(xor_mapped.port);
    let address = xor_mapped.address.iter().enumerate().map(|(i,&b)| {
        if i < 4 {
            b ^ ((packet::MAGIC_COOKIE >> (8 * (3 - i))) as u8)
        } else {
            b ^ transaction_id[i -4]
        }
    }).collect::<Vec<u8>>().try_into().unwrap();
    packet::MappedAddress {padding: 0,family: xor_mapped.family, port, address }
}


impl StunClient {
    pub fn new(udp: udp::UDPSocket,transaction_id :[u8;12]) -> Self {
        StunClient {
            state: Arc::new(StunState { udp: tokio::sync::Mutex::new(udp), transaction_id }),
        }
    }

    pub async fn send(&self,to :net_common::AddrPort) -> Result<(), Error> {
        let mut hdr = packet::StunHeader::default();
        hdr.length = 0;
        hdr.msg_type = packet::MessageType::BindingRequest;
        hdr.magic_cookie = packet::MAGIC_COOKIE;
        hdr.transaction_id = self.state.transaction_id;
        let mut buf :[u8; 20] = [0; 20];
        hdr.encode_to_fixed(&mut buf)?;
        let state = self.state.udp.lock().await;
        state.send_to(to,&buf).await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<(net_common::AddrPort, packet::StunHeader, Vec<packet::Attribute>), Error> {
        let mut udp = self.state.udp.lock().await;
        let (pkt, from) = udp.receive_from().await?;
        let pkt = packet::StunPacket::decode_exact(&pkt)?;
        Ok((from, pkt.header, pkt.attributes))
    }

    
}
