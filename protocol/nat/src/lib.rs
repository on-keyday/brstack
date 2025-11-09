use std::{collections::HashMap, sync::{Arc, Mutex}};

use ipv4::packet::ProtocolNumber;
use net_common;

struct LocalGlobalMapping {
    global_to_local: HashMap<net_common::AddrPort, net_common::AddrPort>,
    local_to_global: HashMap<net_common::AddrPort, net_common::AddrPort>,
    last_activity: HashMap<(net_common::AddrPort, net_common::AddrPort), std::time::Instant>,
}

impl LocalGlobalMapping {
    pub fn new() -> Self {
        Self {
            global_to_local: HashMap::new(),
            local_to_global: HashMap::new(),
            last_activity: HashMap::new(),
        }
    }

    pub fn add_mapping(&mut self, local: net_common::AddrPort, global: net_common::AddrPort, now: std::time::Instant) {
        self.local_to_global.insert(local, global);
        self.global_to_local.insert(global, local);
        self.last_activity.insert((local, global), now);
    }

    pub fn get_global(&mut self, local: &net_common::AddrPort, now: std::time::Instant) -> Option<net_common::AddrPort> {
       match  self.local_to_global.get(local).cloned() {
            Some(global) => {
                self.last_activity.entry(( *local, global)).and_modify(|e| *e = now);
                Some(global)
            },
            None => None,
       }
    }

    pub fn get_local(&mut self, global: &net_common::AddrPort, now: std::time::Instant) -> Option<net_common::AddrPort> {
        match self.global_to_local.get(global).cloned() {
            Some(local) => {
                self.last_activity.entry((local, *global)).and_modify(|e| *e = now);
                Some(local)
            },
            None => None,
        }
    }

}

pub struct PortManager {
    port_range_start :u16,
    port_range_end :u16,
    current_port :u16,
    bitmap :Vec<u8>,
}
impl PortManager {
    pub fn new(port_range_start: u16, port_range_end: u16) -> Self {
        let size = (port_range_end - port_range_start + 1) as usize;
        let bitmap_size = (size + 7) / 8;
        Self {
            port_range_start,
            port_range_end,
            current_port: port_range_start,
            bitmap: vec![0; bitmap_size],
        }
    }

    pub fn release_port(&mut self, port: u16) {
        if port < self.port_range_start || port > self.port_range_end {
            return;
        }
        let index = (port - self.port_range_start) as usize;
        let byte_index = index / 8;
        let bit_index = index % 8;
        self.bitmap[byte_index] &= !(1 << bit_index);
    }

    pub fn allocate_port(&mut self) -> Option<u16> {
        let total_ports = (self.port_range_end - self.port_range_start + 1) as usize;
        for _ in 0..total_ports {
            let port = self.current_port;
            let index = (port - self.port_range_start) as usize;
            let byte_index = index / 8;
            let bit_index = index % 8;
            if (self.bitmap[byte_index] & (1 << bit_index)) == 0 {
                // ポートが使用されていない場合、割り当てる
                self.bitmap[byte_index] |= 1 << bit_index;
                // 次のポートに進める
                self.current_port += 1;
                if self.current_port > self.port_range_end {
                    self.current_port = self.port_range_start;
                }
                return Some(port);
            }
            // 次のポートに進める
            self.current_port += 1;
            if self.current_port > self.port_range_end {
                self.current_port = self.port_range_start;
            }
        }
        // 全てのポートが使用中の場合
        None
    }
}

struct NATState {
    wan_device :ethernet::NetworkInterface,

    port_manager :Mutex<PortManager>,
    tcp :Mutex<LocalGlobalMapping>,
    udp :Mutex<LocalGlobalMapping>,
}


#[derive(Debug)]
pub enum NATError {
    CommonDecodeError(net_common::Error),
    UDPError(udp::datagram::Error),
    TCPError(tcp::segment::Error),
    IPv4Error(ipv4::packet::Error),
    NoAvailablePorts,
}

impl From<net_common::Error> for NATError {
    fn from(e: net_common::Error) -> Self {
        NATError::CommonDecodeError(e)
    }
}

impl From<udp::datagram::Error> for NATError {
    fn from(e: udp::datagram::Error) -> Self {
        NATError::UDPError(e)
    }
}

impl From<tcp::segment::Error> for NATError {
    fn from(e: tcp::segment::Error) -> Self {
        NATError::TCPError(e)
    }
}

impl From<ipv4::packet::Error> for NATError {
    fn from(e: ipv4::packet::Error) -> Self {
        NATError::IPv4Error(e)
    }
}

impl std::fmt::Display for NATError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NATError::NoAvailablePorts => write!(f, "No available ports for NAT"),
            NATError::CommonDecodeError(e) => write!(f, "CommonDecodeError: {}", e),
            NATError::UDPError(e) => write!(f, "UDPError: {}", e),
            NATError::TCPError(e) => write!(f, "TCPError: {}", e),
            NATError::IPv4Error(e) => write!(f, "IPv4Error: {}", e),
        }
    }
}

impl std::error::Error for NATError {}

pub struct NAT {
    state: Arc<NATState>,
}

impl NAT {
    pub fn new(wan_device: ethernet::NetworkInterface, port_range_start: u16, port_range_end: u16) -> Self {
        Self {
            state: Arc::new(NATState {
                wan_device,
                tcp: Mutex::new(LocalGlobalMapping::new()),
                udp: Mutex::new(LocalGlobalMapping::new()),
                port_manager: Mutex::new(PortManager::new(port_range_start, port_range_end)),
            }),
        }
    }

    pub fn get_global(&self, internal: &net_common::AddrPort, protocol: ProtocolNumber) -> Option<net_common::AddrPort> {
        match protocol {
            ProtocolNumber::UDP => {
                self.state.udp.lock().unwrap().get_global(internal, std::time::Instant::now())
            }
            ProtocolNumber::TCP => {
                self.state.tcp.lock().unwrap().get_global(internal, std::time::Instant::now())
            }
            _ => None,
        }
    }

    pub fn get_internal(&self, external: &net_common::AddrPort, protocol: ProtocolNumber) -> Option<net_common::AddrPort> {
        match protocol {
            ProtocolNumber::UDP => {
                self.state.udp.lock().unwrap().get_local(external, std::time::Instant::now())
            }
            ProtocolNumber::TCP => {
                self.state.tcp.lock().unwrap().get_local(external, std::time::Instant::now())
            }
            _ => None,
        }
    }

    pub fn add_mapping(&self, internal: net_common::AddrPort, protocol: ProtocolNumber) -> Option<net_common::AddrPort> {
        let mut port_manager = self.state.port_manager.lock().unwrap();
        let external_port = port_manager.allocate_port()?;
        let external = net_common::AddrPort {
            address: self.state.wan_device.ipv4_address().address,
            port: external_port,
        };

        match protocol {
            ProtocolNumber::UDP => {
                self.state.udp.lock().unwrap().add_mapping(internal, external, std::time::Instant::now());
                Some(external)
            }
            ProtocolNumber::TCP => {
                self.state.tcp.lock().unwrap().add_mapping(internal, external, std::time::Instant::now());
                Some(external)
            }
            _ => None,
        }
    }

    pub fn get_four_tuple(hdr :&ipv4::packet::IPv4Header<'_>,payload :&[u8]) -> Result<Option<(ipv4::packet::ProtocolNumber, net_common::FourTuple)>, NATError> {
        let src_addr = net_common::Ipv4Address(hdr.src_addr);
        let dst_addr = net_common::Ipv4Address(hdr.dst_addr);
        match hdr.proto {
            ipv4::packet::ProtocolNumber::TCP | ipv4::packet::ProtocolNumber::UDP => {
                let (ports, _) = net_common::TransportPorts::decode_slice(payload)?;
                let src_port = ports.src_port;
                let dst_port = ports.dst_port;
                Ok(Some((
                    hdr.proto,
                    net_common::FourTuple{
                        src: net_common::AddrPort{
                            address: src_addr,
                            port: src_port,
                        },
                        dst: net_common::AddrPort{
                            address: dst_addr,
                            port: dst_port,
                        },
                    }
                )))
            },
            _=> {
                Ok(None) 
            }
        }
    }

    pub fn modify_packet(hdr :&mut ipv4::packet::IPv4Header<'_>,payload :&mut [u8], four_tuple :&net_common::FourTuple) -> Result<(), NATError> {
        hdr.src_addr = four_tuple.src.address.0;
        hdr.dst_addr = four_tuple.dst.address.0;
        let mut pseudo_buffer = [0u8; 12];
        let pseudo = ipv4::packet::IPv4PseudoHeader{
            srcAddr: hdr.src_addr,
            dstAddr: hdr.dst_addr,
            zero: 0,
            protocol: hdr.proto,
            length: payload.len() as u16,
            ..Default::default()
        };
        match hdr.proto {
            ipv4::packet::ProtocolNumber::TCP => {
                let (mut tcp_hdr, _) = tcp::segment::TCPHeaderFixed::decode_slice(payload)?;
                tcp_hdr.src_port = four_tuple.src.port;
                tcp_hdr.dst_port = four_tuple.dst.port;
                tcp_hdr.checksum = 0; // temporary 0
                tcp_hdr.encode_to_fixed(payload)?;
                pseudo.encode_to_fixed(&mut pseudo_buffer[..])?;
                let sum = ipv4::packet::checkSumUpdate(ipv4::packet::CheckSum::default(), std::borrow::Cow::Borrowed(&pseudo_buffer));
                let sum = ipv4::packet::checkSumUpdate(sum, std::borrow::Cow::Borrowed(&payload));
                let sum = ipv4::packet::checkSumFinish(sum);
                tcp_hdr.checksum = sum;
                tcp_hdr.encode_to_fixed(payload)?;
                Ok(())
            }
            ipv4::packet::ProtocolNumber::UDP => {
                let (mut udp_hdr, _) = udp::datagram::UDPHeader::decode_slice(payload)?;
                udp_hdr.src_port = four_tuple.src.port;
                udp_hdr.dst_port = four_tuple.dst.port;
                udp_hdr.checksum = 0; // temporary 0
                udp_hdr.encode_to_fixed(payload)?;
                pseudo.encode_to_fixed(&mut pseudo_buffer[..])?;
                let sum = ipv4::packet::checkSumUpdate(ipv4::packet::CheckSum::default(), std::borrow::Cow::Borrowed(&pseudo_buffer));
                let sum = ipv4::packet::checkSumUpdate(sum, std::borrow::Cow::Borrowed(&payload));
                let sum = ipv4::packet::checkSumFinish(sum);
                udp_hdr.checksum = sum;
                udp_hdr.encode_to_fixed(payload)?;
                Ok(())
            },
            _=> {
                Ok(()) 
            }
        }
    }

    // SNAT
    pub fn translate_outbound(&self,dest_device :&ethernet::NetworkInterface, hdr :&mut ipv4::packet::IPv4Header<'_>,payload :&mut ipv4::Data)  -> Result<(), NATError> {
        if let Some((protocol,four_tuple)) = NAT::get_four_tuple(hdr,payload.as_slice())? {
             if let Some(external_four_tuple) = self.get_global(&four_tuple.src,protocol).and_then(|external_addr_port| {
                Some(net_common::FourTuple{
                    src: external_addr_port,
                    dst: four_tuple.dst,
                })
            }) {
                NAT::modify_packet(hdr,payload.to_mut(),&external_four_tuple)?;
                log::debug!("SNAT: {} => {}", four_tuple, external_four_tuple);
            } else {
                if dest_device.name() == self.state.wan_device.name() {
                    if let Some(external_addr_port) = self.add_mapping(four_tuple.src, protocol) {
                        let external_four_tuple = net_common::FourTuple{
                            src: external_addr_port,
                            dst: four_tuple.dst,
                        };
                        NAT::modify_packet(hdr,payload.to_mut(),&external_four_tuple)?;
                        log::debug!("SNAT: {} => {}", four_tuple, external_four_tuple);
                    } else {
                        return Err(NATError::NoAvailablePorts);
                    }
                }
            }
        }
        Ok(())
    }

    // DNAT
    pub fn translate_inbound(&self,_ :&ethernet::NetworkInterface, hdr :&mut ipv4::packet::IPv4Header<'_>,payload :&mut ipv4::Data) -> Result<(), NATError> {
        if let Some((protocol,four_tuple)) = NAT::get_four_tuple(hdr,payload.as_slice())? {
            if let Some(internal_four_tuple) = self.get_internal(&four_tuple.dst,protocol).and_then(|internal_addr_port| {
                Some(net_common::FourTuple{
                    src: four_tuple.src,
                    dst: internal_addr_port,
                })
            }) {
                NAT::modify_packet(hdr,payload.to_mut(),&internal_four_tuple)?;
                log::debug!("DNAT: {} => {}", four_tuple, internal_four_tuple);
            }
        }
        Ok(())
    }
}

impl ipv4::IPv4Nat for NAT {
    fn translate_inbound(&self,in_dev :&ethernet::NetworkInterface, hdr: &mut ipv4::packet::IPv4Header<'_>, payload: &mut ipv4::Data) -> Result<(), Box<dyn std::error::Error>> {
        self.translate_inbound(in_dev,hdr,payload)?;
        Ok(())
    }

    fn translate_outbound(&self, out_dev :&ethernet::NetworkInterface, hdr: &mut ipv4::packet::IPv4Header<'_>, payload: &mut ipv4::Data) -> Result<(), Box<dyn std::error::Error>> {
        self.translate_outbound(out_dev,hdr,payload)?;
        Ok(())
    }
}
