mod packet;

#[derive(Debug, Clone)]
struct ArpEntry {
    pub dst_ip :net_common::Ipv4Address,
    pub dst_mac :net_common::MacAddress,
    pub device :ethernet::NetworkInterface,
    pub state :net_common::NeighborCacheState,
    pub timestamp :Option<std::time::Instant>,
}

struct AddressResolutionTableState {
    entries :tokio::sync::RwLock<std::collections::HashMap<net_common::Ipv4Address, ArpEntry>>,
    stale_timeout :std::time::Duration,
}

pub struct AddressResolutionTable {
    state :std::sync::Arc<AddressResolutionTableState>,
}

pub enum Error {
    Packet(packet::Error),
    Ethernet(ethernet::Error),
}

impl From<packet::Error> for Error {
    fn from(err: packet::Error) -> Self {
        Error::Packet(err)
    }
}

impl From<ethernet::Error> for Error {
    fn from(err: ethernet::Error) -> Self {
        Error::Ethernet(err)
    }
}

impl AddressResolutionTable {
    pub fn new(stale_timeout :std::time::Duration) -> Self {
        Self {
            state :std::sync::Arc::new(
                AddressResolutionTableState {
                    entries :tokio::sync::RwLock::new(std::collections::HashMap::new()),
                    stale_timeout,
                }
            )
        }
    }

    pub async fn update_arp_entry(&self,cache_state: net_common::NeighborCacheState,  dst_ip :net_common::Ipv4Address, dst_mac :net_common::MacAddress, device :ethernet::NetworkInterface) {
        let mut entries = self.state.entries.write().await;
        entries.insert(dst_ip.clone(), ArpEntry {
            dst_ip,
            dst_mac,
            device,
            state: cache_state,
            timestamp: None,
        });
    }

    async fn get_arp_entry(&self, dst_ip :&net_common::Ipv4Address) -> Option<ArpEntry> {
        let entries = self.state.entries.read().await;
        entries.get(&dst_ip).cloned()
    }

    pub async fn receive(&self, frame :&ethernet::frame::EthernetFrame<'_>,device:&ethernet::NetworkInterface) -> Result<(),Error> {
        let data = frame.data().unwrap();
        let (arp_packet,_) = packet::ArpPacket::decode_slice(&data)?;
        if arp_packet.hardware_type != packet::HARDWARE_TYPE_ETHERNET ||
            arp_packet.protocol_type != ethernet::frame::EtherType::IPv4.into() ||
            arp_packet.hardware_len != 6 ||
            arp_packet.protocol_len != 4 {
            return Err(Error::Packet(packet::Error::AssertError("Unacceptable ARP packet")));
        }
        let convert_to_ip = |x :&[u8]| {
            let mut fixed = [0; 4];
            fixed.copy_from_slice(x);
            net_common::Ipv4Address(fixed)
        };
        let convert_to_mac = |x :&[u8]| {
            let mut fixed = [0; 6];
            fixed.copy_from_slice(x);
            net_common::MacAddress(fixed)
        };
        let src_ip =convert_to_ip(&arp_packet.source_protocol_address);
        let src_mac = convert_to_mac(&arp_packet.source_hardware_address);
        let dst_ip = convert_to_ip(&arp_packet.target_protocol_address);
        let mut updated = false;
        if let Some(entry) = self.get_arp_entry(&src_ip).await {
            if entry.dst_mac != src_mac { // MACアドレスが異なる場合は更新
                log::info!("Update ARP entry: {} -> {}", src_ip, src_mac);
                self.update_arp_entry(net_common::NeighborCacheState::REACHABLE, src_ip, src_mac, device.clone()).await;
                updated = true;
            }
        }
        if dst_ip == device.ipv4_address().address {
            if !updated {
                log::info!("Update ARP entry: {} -> {}", src_ip, src_mac);
                self.update_arp_entry(net_common::NeighborCacheState::REACHABLE, src_ip, src_mac, device.clone()).await;
            }
            if arp_packet.operation == packet::Operation::Request {
                log::info!("Send ARP reply: {} -> {}", src_ip, src_mac);
                let mut arp_reply = arp_packet.clone();
                arp_reply.operation = packet::Operation::Reply;
                arp_reply.target_protocol_address = arp_packet.source_protocol_address;
                arp_reply.target_hardware_address = arp_packet.source_hardware_address;
                arp_reply.source_hardware_address = std::borrow::Cow::Borrowed(&device.mac_address().0);
                arp_reply.source_protocol_address = std::borrow::Cow::Borrowed(&device.ipv4_address().address.0);
                let mut buf = [0u8; 2048];
                let buf = arp_reply.encode_to_fixed(&mut buf)?;
                device.send(ethernet::frame::EtherType::ARP, &src_mac, &buf).await?;
            }
        }
        Ok(())
    }
}
