

fn get_if_addr(if_name: &str) -> Result<net_common::Ipv4Prefix, std::io::Error> {
    let if_addrs = if_addrs::get_if_addrs()?;
    for if_addr in if_addrs {
        if if_addr.name == if_name {
            if let if_addrs::IfAddr::V4(addr) = if_addr.addr {
                return Ok(net_common::Ipv4Prefix::new(
                    addr.ip.octets()[0],
                    addr.ip.octets()[1],
                    addr.ip.octets()[2],
                    addr.ip.octets()[3],
                    addr.prefixlen,
                ));
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Interface not found",
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  env_logger::init();
  let addr = get_if_addr("eth0")?;
  // Raw Socketの作成 
  let iface= ethernet::NetworkInterface::new(String::from("eth0"), addr)?;
  let sender=iface.clone();
  tokio::spawn(async move {
    loop {
      sender.send(ethernet::frame::EtherType::BRSTACK,
        // 相手のMACアドレスがわからないのでブロードキャストアドレスを指定
        &net_common::MacAddress::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        // 規格上は最低46バイト必要だがDocker上ではそれより小さくても普通に通信できる
        b"Hello brstack"
      ).await.unwrap();
      tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
  });
  loop {
    // ソケットから受信する
    let frame =  iface.recv().await?;
    // 受信したフレームのデータを表示する
    log::info!("Received frame: {:?}", frame);
    let reencoded = frame.encode_to_vec()?;
    log::info!("Raw bytes: len {} {:x?}",reencoded.len(), reencoded);
  }
}
