
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Raw Socketの作成 
  let iface= ethernet::NetworkInterface::new(String::from("eth0"),
                                  net_common::MacAddress::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
                                  net_common::Ipv4Prefix::new(192, 168, 1, 1, 24))?;
  loop {
    // ソケットから受信する
    let frame =  iface.recv().await?;
    println!("Received {} bytes",14 + frame.data().unwrap().len());
    println!("Decoded Ethernet frame: {:x?}", frame);
    let reencoded = frame.encode_to_vec()?;
    println!("Raw bytes: len {} {:x?}",reencoded.len(), reencoded);
  }
}
