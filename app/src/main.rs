use std::mem::MaybeUninit;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Raw Socketの作成 
  let socket=   socket2::Socket::new(socket2::Domain::PACKET,socket2::Type::RAW,Some(socket2::Protocol::from(libc::ETH_P_ALL)))?;
  socket.set_nonblocking(true)?;
  // ネットワークインターフェース名(eth0)からネットワークインターフェースのインデックスを取得
  let if_index =unsafe { libc::if_nametoindex(c"eth0".as_ptr() as *const i8)};
  if if_index == 0 {
      return Err(Box::from("Failed to get interface index for eth0"));
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
  // ソケットから受信する
  let buffer: (usize, [MaybeUninit<u8>; 2048]) =  socket.async_io(tokio::io::Interest::READABLE,|socket| {
    let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
    let buf_size = socket.recv_with_flags(&mut buf, libc::MSG_TRUNC)?;
    Ok((buf_size,buf))
  }).await?;
  let buf= unsafe {
   std::mem::transmute::<&[MaybeUninit<u8>], &[u8]>(&buffer.1[..buffer.0])
  };
  println!("Received {} bytes", buf.len());
  for byte in buf.iter() {
    print!("{:02x} ", byte);
  }
  println!();
  Ok(())
}
