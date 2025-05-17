use std::{os::fd::AsRawFd, str::FromStr, sync::Arc};
pub mod frame;

#[derive(Debug)]
pub struct NetworkInterfaceState {
    name: String,
    index: u32,
    mac_address: net_common::MacAddress,
    ipv4_address: net_common::Ipv4Prefix,
    socket :tokio::io::unix::AsyncFd<socket2::Socket>,
    write_mutex: tokio::sync::Mutex<()>,
    read_mutex: tokio::sync::Mutex<()>,
}

#[derive(Debug,Clone)]
pub struct NetworkInterface {
    state :Arc<NetworkInterfaceState>,
}

#[derive(Debug)]
pub enum Error{
    Frame(frame::Error),
    Socket(tokio::io::Error),
    NulError(std::ffi::NulError),
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
impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Self {
        Error::NulError(err)
    }
}


impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Frame(err) => write!(f, "Frame error: {}", err),
            Error::Socket(err) => write!(f, "Socket error: {}", err),
            Error::NulError(err) => write!(f, "Nul error: {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Frame(err) => Some(err), 
            Error::Socket(err) => Some(err),
            Error::NulError(err) => Some(err),
        }
    }
}

impl NetworkInterface {
    pub fn new(name :String,ipv4_address: net_common::Ipv4Prefix) ->  Result<Self, Error> {
        let socket=   socket2::Socket::new(socket2::Domain::PACKET,socket2::Type::RAW,Some(socket2::Protocol::from(libc::ETH_P_ALL)))?;
        socket.set_nonblocking(true)?;
        let c_name =  std::ffi::CString::from_str(&name)?;
        // ネットワークインターフェース名からネットワークインターフェースのインデックスを取得
        let if_index =unsafe { libc::if_nametoindex(c_name.as_ptr() as *const i8)};
        if if_index == 0 {
            return Err(Error::Socket(tokio::io::Error::from_raw_os_error(libc::ENODEV)));
        }
        // ネットワークインターフェースからMACアドレスを取得
        let mac_address = unsafe {
            let mut name_buf = [0i8;libc::IFNAMSIZ];
            name.as_bytes().iter().enumerate().for_each(|(i, &b)| {
                name_buf[i] = b as i8;
            });
            let mut req = libc::ifreq {
                ifr_name:name_buf,
                ifr_ifru: libc::__c_anonymous_ifr_ifru {
                    ifru_hwaddr: libc::sockaddr {
                        sa_family: libc::AF_PACKET as u16,
                        sa_data: [0; 14],
                    },
                }
            };
            let ret =  libc::ioctl(socket.as_raw_fd(),libc::SIOCGIFHWADDR,&mut req as *mut libc::ifreq);
            if ret < 0 {
                return Err(Error::Socket(tokio::io::Error::last_os_error()));
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(std::mem::transmute(&req.ifr_ifru.ifru_hwaddr.sa_data[0..6]));
            net_common::MacAddress(mac)
        };
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

        log::debug!("NetworkInterface: {} mac: {} ipv4: {}", name, mac_address, ipv4_address);
        
        Ok(NetworkInterface {
            state: Arc::new(NetworkInterfaceState {
                name,
                index: if_index,
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

    pub fn index(&self) -> u32 {
        self.state.index
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

    pub async fn recv(&self) -> Result<frame::EthernetFrame<'static>, Error> {
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


pub fn get_interfaces() -> Result<Vec<NetworkInterface>, Error> {
    let mut interfaces = Vec::new();
    // ifaddrs::get_if_addrs()は、全てのインターフェースの情報を取得する
    let if_addrs = if_addrs::get_if_addrs()?;
    for if_addr in if_addrs {
      if let if_addrs::IfAddr::V4(addr) = if_addr.addr {
        let prefix = net_common::Ipv4Prefix::new(
            addr.ip.octets()[0],
            addr.ip.octets()[1],
            addr.ip.octets()[2],
            addr.ip.octets()[3],
            addr.prefixlen,
        );
        let iface = NetworkInterface::new(if_addr.name, prefix)?;
        interfaces.push(iface);
      }
    }
    Ok(interfaces)
}
