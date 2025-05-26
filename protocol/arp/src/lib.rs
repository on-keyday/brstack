
mod packet;

#[derive(Debug, Clone)]
struct ArpEntry {
    pub dst_ip :net_common::Ipv4Address,
    pub dst_mac :net_common::MacAddress,
    pub device :ethernet::NetworkInterface,
    pub state :net_common::NeighborCacheState,
    pub timestamp :std::time::Instant,
}

struct ArpEntryWithQueue {
    pub entry :ArpEntry,
    pub queue: Option<tokio::sync::broadcast::Sender<Option<net_common::MacAddress>>>,
}

impl ArpEntry {
    fn update_state(&mut self, state: net_common::NeighborCacheState) {
        self.state = state;
        self.timestamp = std::time::Instant::now();
        log::info!("ARP entry {} at {} is now {:?}", self.dst_ip, self.device.name(), self.state);
    }
}

struct AddressResolutionTableState {
    entries :tokio::sync::RwLock<std::collections::HashMap<u32, std::collections::HashMap<net_common::Ipv4Address, ArpEntryWithQueue>>>,
    reachable_duration :std::time::Duration,
    retransmit_timer :std::time::Duration,
    delay_duration :std::time::Duration,
    retry_count :u32,
}

#[derive(Clone)]
pub struct AddressResolutionTable {
    state :std::sync::Arc<AddressResolutionTableState>,
}

#[derive(Debug)]
pub enum Error {
    Packet(packet::Error),
    Ethernet(ethernet::Error),
    Protocol(String),
    RecvError(tokio::sync::broadcast::error::RecvError),
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

impl From<tokio::sync::broadcast::error::RecvError> for Error {
    fn from(err: tokio::sync::broadcast::error::RecvError) -> Self {
        Error::RecvError(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Packet(err) => write!(f, "Packet error: {}", err),
            Error::Ethernet(err) => write!(f, "Ethernet error: {}", err),
            Error::Protocol(err) => write!(f, "Protocol error: {}", err),
            Error::RecvError(err) => write!(f, "Recv error: {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Packet(err) => Some(err),
            Error::Ethernet(err) => Some(err),
            Error::Protocol(_) => None,
            Error::RecvError(err) => Some(err),
        }
    }
}

impl Default for AddressResolutionTable {
    fn default() -> Self {
        Self::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(1), 
            3,
            std::time::Duration::from_secs(5),
        )
    }
}

impl AddressResolutionTable {
    pub fn new(reachable_duration :std::time::Duration, retransmit_timer: std::time::Duration,retry_count :u32,delay_duration :std::time::Duration) -> Self {
        Self {
            state :std::sync::Arc::new(
                AddressResolutionTableState {
                    entries :tokio::sync::RwLock::new(std::collections::HashMap::new()),
                    reachable_duration,
                    retransmit_timer,
                    retry_count,
                    delay_duration,
                }
            )
        }
    }

    fn start_stale_timer(&self,device :&ethernet::NetworkInterface, dst_ip :&net_common::Ipv4Address,now :std::time::Instant) {
        let arp = self.clone();
        let device = device.clone();
        let dst_ip = dst_ip.clone();
        log::info!("Start STALE timer for {} -> {}", device.name(), dst_ip);
        tokio::spawn(async move {
            tokio::time::sleep(arp.state.reachable_duration).await;
            let mut entries = arp.state.entries.write().await;
            if let Some(entry) = entries.get_mut(&device.index()).and_then(|entry| entry.get_mut(&dst_ip)) {
                if entry.entry.state == net_common::NeighborCacheState::REACHABLE  && entry.entry.timestamp == now {
                    entry.entry.update_state(net_common::NeighborCacheState::STALE);
                }
            }
        });
    }

    pub async fn update_arp_entry(&self,cache_state: net_common::NeighborCacheState,  dst_ip :net_common::Ipv4Address, dst_mac :net_common::MacAddress, device :ethernet::NetworkInterface) {
        let mut entries = self.state.entries.write().await;
        let entry = entries
            .entry(device.index())
            .or_insert_with(std::collections::HashMap::new).entry(dst_ip)
            .and_modify(|entry|{
            entry.entry.dst_mac = dst_mac;
            entry.entry.update_state(cache_state);
            if let Some(sender) = entry.queue.take() {
                sender.send(Some(dst_mac)).ok();
                if cache_state == net_common::NeighborCacheState::STALE { // 送信しようとしているのでDELAYに遷移
                    entry.entry.update_state(net_common::NeighborCacheState::DELAY);
                }
            }
        }).or_insert_with(|| {
            ArpEntryWithQueue {
                entry: ArpEntry {
                    dst_ip,
                    dst_mac,
                    device: device.clone(),
                    state: cache_state,
                    timestamp: std::time::Instant::now(),
                },
                queue: None,
            }
        });
        if entry.entry.state == net_common::NeighborCacheState::REACHABLE {
            self.start_stale_timer(&device, &dst_ip, entry.entry.timestamp);
        } else if entry.entry.state == net_common::NeighborCacheState::DELAY {
            self.start_delay_timer(&device, &dst_ip, entry.entry.timestamp);
        }
    }

    async fn get_arp_entry(&self,device :&ethernet::NetworkInterface, dst_ip :&net_common::Ipv4Address) -> Option<ArpEntry> {
        let entries = self.state.entries.read().await;
        entries.get(&device.index())
            .and_then(|entry| entry.get(dst_ip))
            .map(|entry| {
                let now = std::time::Instant::now();
                if now.duration_since(entry.entry.timestamp) > self.state.reachable_duration {
                    None
                } else {
                    Some(entry.entry.clone())
                }
            })
            .flatten()
    }

    // 共通化したARP送信関数
    async fn send_arp_common(
        &self,
        device: &ethernet::NetworkInterface,
        operation: packet::Operation,
        target_hw: &[u8],
        target_proto: &[u8],
        ether_dst: &net_common::MacAddress,
    ) -> Result<(), Error> {
        let mut arp = packet::ArpPacket::default();
        arp.hardware_type = packet::HARDWARE_TYPE_ETHERNET;
        arp.protocol_type = ethernet::frame::EtherType::IPv4.into();
        arp.hardware_len = 6;
        arp.protocol_len = 4;
        arp.operation = operation;
        arp.source_hardware_address =
            std::borrow::Cow::Borrowed(&device.mac_address().0);
        arp.source_protocol_address =
            std::borrow::Cow::Borrowed(&device.ipv4_address().address.0);
        arp.target_hardware_address = std::borrow::Cow::Borrowed(target_hw);
        arp.target_protocol_address = std::borrow::Cow::Borrowed(target_proto);
        let mut buf = [0u8; 2048];
        let buf = arp.encode_to_fixed(&mut buf)?;
        device
            .send(ethernet::frame::EtherType::ARP, ether_dst, &buf)
            .await?;
        Ok(())
    }

    // 送信先が不明なときはHWアドレス全ゼロ、Ethernet宛先はリクエスト先をブロードキャスト
    async fn send_arp_request(
        &self,
        device: &ethernet::NetworkInterface,
        dst_ip: &net_common::Ipv4Address,
        dst_mac: &net_common::MacAddress,
    ) -> Result<(), Error> {
        self.send_arp_common(
            device,
            packet::Operation::Request,
            &[0; 6],
            &dst_ip.0,
            dst_mac,
        )
        .await
    }

    // 送信先HW/DSTは相手のMAC
    async fn send_arp_reply(
        &self,
        device: &ethernet::NetworkInterface,
        dst_ip: &net_common::Ipv4Address,
        dst_mac: &net_common::MacAddress,
    ) -> Result<(), Error> {
        self.send_arp_common(
            device,
            packet::Operation::Reply,
            &dst_mac.0,
            &dst_ip.0,
            dst_mac,
        )
        .await
    }

    fn start_delay_timer(&self,device :&ethernet::NetworkInterface, dst_ip :&net_common::Ipv4Address,start :std::time::Instant) {
        let arp = self.clone();
        let device = device.clone();
        let dst_ip = dst_ip.clone();
        log::info!("Start DELAY timer for {} -> {}", device.name(), dst_ip);
        tokio::spawn(async move {
            tokio::time::sleep(arp.state.delay_duration).await;
            log::debug!("DELAY timer expired for {} -> {}", device.name(), dst_ip);
            let mut entries = arp.state.entries.write().await;
            if let Some(entry) = entries.get_mut(&device.index()).and_then(|entry| entry.get_mut(&dst_ip)) {
                if entry.entry.state == net_common::NeighborCacheState::DELAY && entry.entry.timestamp == start {
                    entry.entry.update_state(net_common::NeighborCacheState::PROBE);    
                    let start = entry.entry.timestamp;
                    let (sender,mut receiver) = tokio::sync::broadcast::channel(1);
                    entry.queue = Some(sender);
                    let dst_mac = entry.entry.dst_mac;
                    drop(entries); // ロックを解放してから受信待ち
                    for i in 0..arp.state.retry_count {
                        log::info!("Send ARP PROBE request attempt {}: {} -> {}", i, device.name(), dst_ip);
                        if let Err(e) = arp.send_arp_request(&device, &dst_ip, &dst_mac).await {
                            log::error!("Failed to send ARP PROBE request: {}", e);
                            break;
                        }
                        tokio::select! {
                            result = receiver.recv() => {
                                match result {
                                    Ok(_) => {},
                                    Err(e) => {
                                        log::error!("Failed to receive ARP response: {}", e);
                                        break;
                                    }
                                };
                                return; // 受信したら終了
                            }
                            _ = tokio::time::sleep(arp.state.retransmit_timer) => {
                                log::info!("ARP request timeout: {} -> {}", device.name(), dst_ip);
                            }
                        }
                    }              
                    // すべてのリトライが失敗した場合再度write lockを取得して確認
                    let mut entries = arp.state.entries.write().await;
                    if let Some(entry) = entries.get_mut(&device.index()).and_then(|entry| entry.get_mut(&dst_ip)) {
                        if entry.entry.state == net_common::NeighborCacheState::PROBE && entry.entry.timestamp == start {
                            entry.entry.update_state(net_common::NeighborCacheState::FAILED);
                            if let Some(sender) = entry.queue.take() {
                                sender.send(None).ok();
                            }
                        }
                    }
                } else {
                    log::debug!("Entry state changed for {} -> {}: {:?}", device.name(), dst_ip, entry.entry.state);
                }
            } else {
                log::debug!("Entry not found for {} -> {}", device.name(), dst_ip);
            }
        });    
    }

    pub async fn get_dst_mac(&self, device :&ethernet::NetworkInterface, dst_ip :&net_common::Ipv4Address) -> Result<net_common::MacAddress,Error> {
        let failure = || {
            Err(Error::Protocol(format!("ARP entry for {} is failed", dst_ip)))
        };
        if let Some(entry) = self.get_arp_entry(device, dst_ip).await {
            if entry.state == net_common::NeighborCacheState::REACHABLE { // すでにMACアドレスがわかっている場合
                return Ok(entry.dst_mac);
            }else if entry.state ==net_common::NeighborCacheState::FAILED {
                return failure();
            }
            // 他の状態はwrite lockを取得してから確認する
        }
        let mut entries = self.state.entries.write().await;
        let entry = entries
            .entry(device.index())
            .or_insert_with(std::collections::HashMap::new);
        // ロック中に別のスレッドがエントリを追加する可能性があるので、lock後に再度確認
        if let Some(entry) = entry.get_mut(dst_ip) {
            match entry.entry.state {
                net_common::NeighborCacheState::REACHABLE | net_common::NeighborCacheState::DELAY => {
                    return Ok(entry.entry.dst_mac);
                }
                net_common::NeighborCacheState::FAILED => {
                    return failure();
                }
                net_common::NeighborCacheState::INCOMPLETE | net_common::NeighborCacheState::PROBE => {
                    // 他のタスクがすでにARPリクエストを送信している場合、受信待ち
                    if let Some(sender) = &entry.queue {
                        let mut receiver =sender.subscribe();
                        drop(entries); // ロックを解放してから受信待ち
                        let result = receiver.recv().await?;
                        if let Some(mac) = result {
                            return Ok(mac);
                        } else {
                            return failure();
                        }
                    }
                    return Err(Error::Protocol(format!("Unexpected ARP entry state: {}", entry.entry.state)));
                }
                net_common::NeighborCacheState::STALE => { // STALEの場合はDELAYに遷移とタイマーの起動
                    entry.entry.update_state(net_common::NeighborCacheState::DELAY);
                    self.start_delay_timer(device, dst_ip, entry.entry.timestamp);
                    return Ok(entry.entry.dst_mac);
                }
            }
        }
        // この時点で現タスクがwrite lockを取得しているのでエントリの追加及びその後のARPリクエストはこのタスクが行う
        let now = std::time::Instant::now();
        let (sender,mut receiver) = tokio::sync::broadcast::channel(1);
        entry.insert(dst_ip.clone(), ArpEntryWithQueue {
            entry: ArpEntry {
                dst_ip: dst_ip.clone(),
                dst_mac: net_common::MacAddress([0; 6]),
                device: device.clone(),
                state: net_common::NeighborCacheState::INCOMPLETE,
                timestamp: now,
            },
            queue: Some(sender),
        });
        drop(entries); // ロックを解放してから受信待ち
        for i in 0..self.state.retry_count {
            log::info!("Send ARP INCOMPLETE request attempt {}: {} -> {}", i, device.name(), dst_ip);
            self.send_arp_request(device, dst_ip,&net_common::MacAddress([0xff;6])).await?;
            tokio::select! {
                result = receiver.recv() => {
                    let mac = result?;
                    match mac {
                        Some(mac) => return Ok(mac),
                        None => return failure(),
                    }
                }
                _ = tokio::time::sleep(self.state.retransmit_timer) => {
                    log::info!("ARP request timeout: {} -> {}", device.name(), dst_ip);
                }
            }
        }
        // すべてのリトライが失敗した場合再度write lockを取得して確認
        let mut entries = self.state.entries.write().await;
        if let Some(entry) = entries.get_mut(&device.index()).and_then(|entry| entry.get_mut(dst_ip)) {
            match entry.entry.state { 
                net_common::NeighborCacheState::INCOMPLETE => { 
                    // この時点でINCOMPLETEの場合は自タスクのものであることは確実なので更新する
                    entry.entry.update_state(net_common::NeighborCacheState::FAILED);
                    if let Some(sender) = entry.queue.take() {
                        sender.send(None).ok();
                    }
                }
                net_common::NeighborCacheState::REACHABLE | // lock取得直前にREACHABLEに遷移した場合(Reply packetを受信した場合)
                net_common::NeighborCacheState::DELAY => { // lock取得直前にSTALE->DELAYと遷移した場合(Request packetを受信してさらに他タスクが送信を試みた場合)
                    return Ok(entry.entry.dst_mac);
                }
                net_common::NeighborCacheState::STALE => { //lock取得直前にSTALEに遷移した場合(Request packetを受信した場合)
                    entry.entry.update_state(net_common::NeighborCacheState::DELAY);
                    self.start_delay_timer(device, dst_ip, entry.entry.timestamp);
                    return Ok(entry.entry.dst_mac);
                }
                // FAILED/PROBEのとき(つまりINCOMPLETEのリトライが終わったあとwrite lockを取得するまでの間にSTALE->DELAY->PROBEと遷移した場合(ほぼありえないので無視))
                _ => {} 
            }
        }
        failure()
    }

    pub async fn receive(&self, frame :ethernet::frame::EthernetFrame<'_>,device:&ethernet::NetworkInterface) -> Result<(),Error> {
        let data = frame.data().unwrap();
        let (arp_packet,_) = packet::ArpPacket::decode_slice(&data)?;
        if arp_packet.hardware_type != packet::HARDWARE_TYPE_ETHERNET ||
            arp_packet.protocol_type != ethernet::frame::EtherType::IPv4.into() ||
            arp_packet.hardware_len != 6 ||
            arp_packet.protocol_len != 4 {
            return Err(Error::Protocol(format!("Unacceptable ARP packet: {:?}", arp_packet)));
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
        if src_ip == dst_ip { // Gratuitous ARPはDockerが送ってくるが今回は無視
            return Ok(());
        }
        let is_broadcast = frame.dst_mac == [0xff; 6];
        let mut updated = false;
        // LinuxのARP cacheはbroadcastアドレスで受信あるいはRequestを受信した場合はSTALEに遷移するのでそれに従う。
        let state = if is_broadcast || arp_packet.operation == packet::Operation::Request {
            net_common::NeighborCacheState::STALE
        } else {
            net_common::NeighborCacheState::REACHABLE
        };
        if let Some(entry) = self.get_arp_entry(device,&src_ip).await {
            if entry.state != net_common::NeighborCacheState::REACHABLE {
                log::info!("Update ARP entry: {} -> {}", src_ip, src_mac);
                self.update_arp_entry(state, src_ip, src_mac, device.clone()).await;
            }
            updated = true;
        }
        if dst_ip == device.ipv4_address().address {
            if !updated {
                log::info!("New ARP entry: {} -> {}", src_ip, src_mac);
                self.update_arp_entry(state, src_ip, src_mac, device.clone()).await;
            }
            if arp_packet.operation == packet::Operation::Request {
                log::info!("Send ARP reply: {} -> {}", src_ip, src_mac);
                self.send_arp_reply(device, &src_ip,&src_mac).await?;
            }
        }
        Ok(())
    }
}
