use std::sync::{Arc, Mutex};

use net_common::AddrPort;


pub mod packet;

pub struct NTPState{
    udp :tokio::sync::Mutex<udp::UDPSocket>,
}

pub fn to_ntp_timestamp(system_time: std::time::SystemTime) -> packet::Timestamp<'static> {
    const NTP_UNIX_EPOCH_DIFF: u32 = 2_208_988_800; // Seconds between 1900 and 1970
    let duration_since_unix_epoch = system_time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration_since_unix_epoch.as_secs() as u32 + NTP_UNIX_EPOCH_DIFF;
    let fractional = duration_since_unix_epoch.subsec_nanos() / 1_000_000_000;
    packet::Timestamp {
        seconds,
        fraction: fractional,
        ..Default::default()
    }
}

pub fn to_u64_timestamp(ts: &packet::Timestamp) -> u64 {
    ((ts.seconds as u64) << 32) | (ts.fraction as u64)
}

pub struct NTPHandler {
    state: Arc<NTPState>,
}

pub enum Error{
    EncodeError(packet::Error),
    UDPError(udp::Error),
    ReceiveTimeout,
    InvalidResponse(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EncodeError(e) => write!(f, "NTP Encode Error: {}", e),
            Error::UDPError(e) => write!(f, "UDP Error: {}", e),
            Error::ReceiveTimeout => write!(f, "NTP Receive Timeout"),
            Error::InvalidResponse(s) => write!(f, "NTP Invalid Response: {}", s),
        }
    }
}

impl From<packet::Error> for Error {
    fn from(err: packet::Error) -> Self {
        Error::EncodeError(err)
    }
}

impl From<udp::Error> for Error {
    fn from(err: udp::Error) -> Self {
        Error::UDPError(err)
    }
}

impl NTPHandler {
    pub fn new(udp :udp::UDPSocket) -> Self {
        NTPHandler {
            state: Arc::new(NTPState {
                udp: tokio::sync::Mutex::new(udp),
            }),
        }
    }

    pub async fn time(&mut self,addr :AddrPort) -> Result<(), Error> {
        let mut pkt = packet::NtpPacket::default();
        pkt.set_version(4);
        pkt.set_mode(packet::Mode::Client);
        pkt.precision = 0x20;
        let transmit_time = to_ntp_timestamp(std::time::SystemTime::now());
        // TODO: should be random, but for testing we use fixed value
        pkt.transmit_timestamp.seconds = 0x12345678;
        pkt.transmit_timestamp.fraction = 0x9ABCDEF0;
        
        let mut buffer = [0u8; 48];
        let encoded = pkt.encode_to_fixed(&mut buffer)?;
        let mut conn = self.state.udp.lock().await;
        conn.send_to(addr,encoded).await?;
        let data = tokio::select! {
            res = conn.receive_from() => {
                let (data, _src) = res?;
                data
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                // Timeout
                return Err(Error::ReceiveTimeout);
            }
        };
        drop(conn);
        let recv_time = std::time::SystemTime::now();
        let (mut resp_pkt,remain) = packet::NtpPacket::decode_slice(&data)?;
        if resp_pkt.mode() != packet::Mode::Server {
            return Err(Error::InvalidResponse("mode"));
        }
        if resp_pkt.origin_timestamp != pkt.transmit_timestamp{
            return Err(Error::InvalidResponse("transmit timestamp mismatch"));
        }
        if resp_pkt.receive_timestamp.seconds > resp_pkt.transmit_timestamp.seconds ||
           (resp_pkt.receive_timestamp.seconds == resp_pkt.transmit_timestamp.seconds &&
            resp_pkt.receive_timestamp.fraction > resp_pkt.transmit_timestamp.fraction) {
            return Err(Error::InvalidResponse("server says it sent response before receiving request, impossible"));
        }

        let t1 = to_u64_timestamp(&transmit_time);
        let t2 = to_u64_timestamp(&resp_pkt.receive_timestamp);
        let t3 = to_u64_timestamp(&resp_pkt.transmit_timestamp);
        let t4 = to_u64_timestamp(&to_ntp_timestamp(recv_time));

        let mut rtt = (t4 as i64 - t1 as i64) - (t3 as i64 - t2 as i64);
        if rtt < 0 {
            rtt = 0; // 誤差
        }
        let offset = ((t2 as i64 - t1 as i64) + (t3 as i64 - t4 as i64)) / 2;
        log::info!("NTP Response from {}: round-trip delay = {}.{:09} seconds, local clock offset = {}.{:09} seconds",
            addr,
            rtt >> 32, rtt - (rtt >> 32 << 32),
            offset >> 32, offset  - (offset >> 32 << 32)
        );
        
        Ok(())
    }
}