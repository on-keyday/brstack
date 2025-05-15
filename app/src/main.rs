
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Raw Socketの作成 
  let iface= ethernet::NetworkInterface::new(String::from("eth0"),
                                  net_common::MacAddress::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
                                  net_common::Ipv4Prefix::new(192, 168, 1, 1, 24))?;
  
  let sender=iface.clone();
  tokio::spawn(async move {
    loop {
      sender.send(ethernet::frame::EtherType::BRSTACK,
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
    println!("Received {} bytes",14 + frame.data().unwrap().len());
    println!("Decoded Ethernet frame: {:x?}", frame);
    let reencoded = frame.encode_to_vec()?;
    println!("Raw bytes: len {} {:x?}",reencoded.len(), reencoded);
  }
}
