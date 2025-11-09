use core::net;

use ipv4::ICMPSender;

mod packet;

#[derive(Clone)]
pub struct ICMPService {
    ipv4: ipv4::Router,
}

impl ICMPService {
    pub fn register(ipv4: ipv4::Router) -> Self {
        ipv4.register_protocol(ipv4::packet::ProtocolNumber::ICMP, Box::new(
            ICMPService{
                ipv4: ipv4.clone(),
            }
        ));
        ipv4.register_icmp_sender(Box::new(
            ICMPService{
                ipv4: ipv4.clone(),
            }
        ));
        ICMPService {
            ipv4,
        }
    }

    async fn send(&self,dst_addr :net_common::Ipv4Address, mut packet: packet::ICMPv4Packet<'_>) -> Result<(), Error> {
        packet.header.checksum = 0;
        let mut buffer = [0u8; 2048];
        let checksum_target = packet.encode_to_fixed(&mut buffer)?;
        packet.header.checksum = ipv4::packet::checkSum(std::borrow::Cow::Borrowed(&checksum_target));
        let final_encoded = packet.encode_to_fixed(&mut buffer)?;
        let len = final_encoded.len();
        self.ipv4.send(
            ipv4::packet::ProtocolNumber::ICMP,
            dst_addr,
        &mut buffer[..len],
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
        packet.set_destination_unreachable(unreachable)?;
        self.send(dst_addr, packet).await
    }

    pub async fn send_time_exceeded(&self, dst_addr: net_common::Ipv4Address,code :net_common::ICMPv4TimeExceededCode, received_data :&[u8]) -> Result<(), Error> {
        let mut packet = packet::ICMPv4Packet::default();
        packet.header.type_ = packet::ICMPv4Type::time_exceeded.into();
        packet.header.code = code.into();
        let mut time_exceeded = packet::ICMPTimeExceeded::default();
        time_exceeded.data = std::borrow::Cow::Borrowed(&received_data);
        packet.set_time_exceeded(time_exceeded)?;
        self.send(dst_addr, packet).await
    }

    
    fn can_send_error(
        &self,
        original_packet: &ipv4::packet::IPv4Packet<'_>,
    ) -> bool {
        if original_packet.hdr.proto == ipv4::packet::ProtocolNumber::ICMP {
            // try decode ICMP header
            let icmp_header = match packet::ICMPHeader::decode_slice(&original_packet.data) {
                Ok((header, _)) => header,
                Err(_) => {
                    log::warn!("Failed to decode ICMP header from original packet: {:?}", original_packet);
                    return false;
                }
            };
            // https://www.rfc-editor.org/rfc/rfc1122#page-38
            /*
                     ICMP messages are grouped into two classes.

             *
              ICMP error messages:

               Destination Unreachable   (see Section 3.2.2.1)
               Redirect                  (see Section 3.2.2.2)
               Source Quench             (see Section 3.2.2.3)
               Time Exceeded             (see Section 3.2.2.4)
               Parameter Problem         (see Section 3.2.2.5)

            An ICMP error message MUST NOT be sent as the result of receiving:

         *    an ICMP error message, or

         *    a datagram destined to an IP broadcast or IP multicast
              address, or

         *    a datagram sent as a link-layer broadcast, or

         *    a non-initial fragment, or

         *    a datagram whose source address does not define a single
              host -- e.g., a zero address, a loopback address, a
              broadcast address, a multicast address, or a Class E
              address.

             */
            let is_error = match icmp_header.type_.into() {
                packet::ICMPv4Type::dst_unreachable => true, 
                packet::ICMPv4Type::redirect => true,
                packet::ICMPv4Type::src_quench => true,
                packet::ICMPv4Type::time_exceeded => true,
                packet::ICMPv4Type::parameter_problem => true,
                _ => false,
            };
            if is_error {
                log::warn!("cannot send ICMP error message in response to ICMP error message: {:?}", icmp_header);
                return false;
            }
        }
        let src_addr = net_common::Ipv4Address(original_packet.hdr.src_addr);
        if src_addr.is_broadcast() || src_addr.is_multicast()|| src_addr.is_unspecified() || src_addr.is_loopback() {
            log::warn!("cannot send ICMP error message to broadcast, multicast, unspecified or loopback address: {}", src_addr);
            return false;
        }
        true
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
    let mut buffer = [0u8; 2048];
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
        let src_addr = net_common::Ipv4Address(packet.hdr.src_addr);
        if let Some(echo) = icmp_packet.echo() {
            log::info!("Received ICMP echo request from {}: {:?}",src_addr, echo);
            let mut response = icmp_packet.clone();
            response.header.type_ = packet::ICMPv4Type::echo_reply.into();
            response.set_echo_reply(echo.clone())?;
            let icmp = self.clone();
            tokio::spawn(async move {
                if let Err(e) = icmp.send(src_addr, response).await {
                    log::error!("ICMP send error: {}", e);
                }
            });           
        } else if let Some(reply) = icmp_packet.echo_reply() {
            log::info!("Received ICMP echo reply from {}: {:?}", src_addr, reply);
        } else if let Some(dst_unreachable) = icmp_packet.destination_unreachable() {
            log::info!("Received ICMP destination unreachable from {}: {} {:?}", src_addr,net_common::ICMPv4DstUnreachableCode::from(icmp_packet.header.code), dst_unreachable);
        } else if let Some(time_exceeded) = icmp_packet.time_exceeded() {
            log::info!("Received ICMP time exceeded from {}: {} {:?}", src_addr,net_common::ICMPv4TimeExceededCode::from(icmp_packet.header.code), time_exceeded);
        } else {
            log::warn!("Received unknown ICMP packet from {}: {:?}", src_addr, icmp_packet);
        }
        Ok(())
    }

}

impl ipv4::ICMPSender for ICMPService {
    fn send_destination_unreachable(
            &self,
            next_hop_mtu: u16,
            code : net_common::ICMPv4DstUnreachableCode,
            original_packet: ipv4::packet::IPv4Packet<'_>,
        ) {
        if !self.can_send_error(&original_packet) {
            return;
        }
        let mut buffer = [0u8; 2048];
        let len = original_packet.encode_to_fixed(&mut buffer).unwrap().len();
        let icmp =self.clone();
        tokio::spawn(async move {
            let src_addr = net_common::Ipv4Address(original_packet.hdr.src_addr);
            match icmp.send_destination_unreachable(src_addr, code,next_hop_mtu,&buffer[..std::cmp::min(len, 576)]).await {
                Ok(_) => log::info!("Sent ICMP destination unreachable to {}", src_addr),
                Err(e) => log::error!("Failed to send ICMP destination unreachable: {}", e),
            }
        });
    }

    fn send_time_exceeded(
            &self,
            code :net_common::ICMPv4TimeExceededCode,
            original_packet: ipv4::packet::IPv4Packet<'_>,
        ) {
        if !self.can_send_error(&original_packet) {
            return;
        }
        let mut buffer = [0u8; 2048];
        let len = original_packet.encode_to_fixed(&mut buffer).unwrap().len();
        let icmp =self.clone();
        tokio::spawn(async move {
            let src_addr = net_common::Ipv4Address(original_packet.hdr.src_addr);
            match icmp.send_time_exceeded(src_addr, code,&buffer[..std::cmp::min(len, 576)]).await {
                Ok(_) => log::info!("Sent ICMP time exceeded to {}", src_addr),
                Err(e) => log::error!("Failed to send ICMP time exceeded: {}", e),
            }
        });
    }
}
