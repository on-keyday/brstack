mod packet;

struct ArpEntry {
    pub dst_ip :net_common::Ipv4Address,
    pub dst_mac :net_common::MacAddress,
    pub device :ethernet::NetworkInterface,
    pub state :net_common::NeighborCacheState,
    pub timestamp :Option<std::time::Instant>,
}

struct AddressResolutionTableState {
    entries :std::collections::HashMap<net_common::Ipv4Address, ArpEntry>,
    stale_timeout :std::time::Duration,
}

pub struct AddressResolutionTable {
    state :std::sync::Arc<std::sync::Mutex<AddressResolutionTableState>>,
}

