use std::sync::Arc;
pub mod frame;


pub struct NetworkInterfaceState {
    name: String,
    mac_address: net_common::MacAddress,
    ipv4_address: net_common::Ipv4Prefix,
    socket :tokio::io::unix::AsyncFd<socket2::Socket>,
    write_mutex: tokio::sync::Mutex<()>,
    read_mutex: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
pub struct NetworkInterface {
    state :Arc<NetworkInterfaceState>,
}

#[derive(Debug)]
pub enum Error{
    Frame(frame::Error),
    Socket(tokio::io::Error),
}

impl From<frame::Error> for Error {
    fn from(err: frame::Error) -> Self {
        Error::Frame(err)
    }
}
impl From<tokio::io::Error> for Error {
    fn from(err: tokio::io::Error) -> Self {
        Error::Socket(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Frame(err) => write!(f, "Frame error: {}", err),
            Error::Socket(err) => write!(f, "Socket error: {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Frame(err) => Some(err), 
            Error::Socket(err) => Some(err),
        }
    }
}

impl NetworkInterface {
    pub fn new(name :String,mac_address: net_common::MacAddress,ipv4_address: net_common::Ipv4Prefix) ->  Result<Self, Error> {
        let socket=   socket2::Socket::new(socket2::Domain::PACKET,socket2::Type::RAW,Some(socket2::Protocol::from(libc::ETH_P_ALL)))?;
        socket.set_nonblocking(true)?;
        // ネットワークインターフェース名(eth0)からネットワークインターフェースのインデックスを取得
        let if_index =unsafe { libc::if_nametoindex(c"eth0".as_ptr() as *const i8)};
        if if_index == 0 {
            return Err(Error::Socket(tokio::io::Error::from_raw_os_error(libc::ENODEV)));
        }
        let mut storage : libc::sockaddr_storage  = unsafe { std::mem::zeroed() };
        // C言語の (struct sockaddr_ll*)&storage 相当の処理
        let sockaddr = unsafe { &mut *((&mut storage) as *const libc::sockaddr_storage as *mut libc::sockaddr_ll) };
        // sockaddr_ll構造体の初期化
        sockaddr.sll_family = libc::AF_PACKET as u16;
        sockaddr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sockaddr.sll_ifindex = if_index as i32;
        let sockaddr = unsafe { socket2::SockAddr::new(storage, std::mem::size_of::<libc::sockaddr_ll>() as u32) };
        // ソケットにバインド
        socket.bind(&sockaddr)?;
        // ソケットを非同期にする   
        let socket = tokio::io::unix::AsyncFd::new(socket)?;
    

        Ok(NetworkInterface {
            state: Arc::new(NetworkInterfaceState {
                name,
                mac_address,
                ipv4_address,
                socket,
                write_mutex: tokio::sync::Mutex::new(()),
                read_mutex: tokio::sync::Mutex::new(()),
            }),
        })
    }

    pub fn mac_address(&self) -> &net_common::MacAddress {
        &self.state.mac_address
    }
    pub fn ipv4_address(&self) -> &net_common::Ipv4Prefix {
        &self.state.ipv4_address
    }
    
    
    pub fn name(&self) -> &str {
        &self.state.name
    }

    pub async fn send(&self, ether_type :frame::EtherType,dst :&net_common::MacAddress,data :&[u8]) -> Result<(), Error> {
        let mut frame = frame::EthernetFrame::default();
        frame.ether_type = ether_type;
        frame.src_mac = self.state.mac_address.0;
        frame.dst_mac = dst.0;
        frame.set_data(std::borrow::Cow::Borrowed(data))?;
        let mut buf = [0u8; 2048];
        let buf = frame.encode_to_fixed(&mut buf)?;
        let state = self.state.clone();
        let _write_guard = state.write_mutex.lock().await;
        state.socket.async_io(tokio::io::Interest::WRITABLE, |socket| {
            socket.send(&buf)
        }).await?;
        drop(_write_guard);
        Ok(())
    }

    pub async fn recv(&self) -> Result<frame::EthernetFrame<'_>, Error> {
        let _read_guard = self.state.read_mutex.lock().await;
        let buffer: (usize, [std::mem::MaybeUninit<u8>; 2048]) =  self.state.socket.async_io(tokio::io::Interest::READABLE,|socket| {
            let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
            let buf_size = socket.recv_with_flags(&mut buf, libc::MSG_TRUNC)?;
            Ok((buf_size,buf))
        }).await?;
        drop(_read_guard);
        if buffer.0 > 2048 {
            return Err(Error::Socket(tokio::io::Error::from_raw_os_error(libc::EMSGSIZE)));
        }
        let buffer= unsafe {
            std::mem::transmute::<&[std::mem::MaybeUninit<u8>], &[u8]>(&buffer.1[..buffer.0])
        };
        Ok(frame::EthernetFrame::decode_exact(&buffer)?)
    }

}