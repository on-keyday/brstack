

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  env_logger::init();
  let interfaces = ethernet::get_interfaces()?;
  let arp = arp::AddressResolutionTable::new(std::time::Duration::from_secs(60));
  for iface in interfaces {
    let sender = iface.clone();
    tokio::spawn(async move {
      loop {
        sender.send(ethernet::frame::EtherType::BRSTACK,
          // 相手のMACアドレスがわからないのでブロードキャストアドレスを指定
          &net_common::MacAddress::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
          // 規格上は最低46バイト必要だがDocker上ではそれより小さくても普通に通信できる
          format!("Hello from {}({})!", sender.name(), sender.mac_address()).as_bytes()
        ).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
      }
    });
    let receiver = iface;
    let arp = arp.clone();
    tokio::spawn(async move {
      let receiver = receiver;
      loop {
        let receive_single :Result<(), Box<dyn std::error::Error>> = async {
          let frame = receiver.recv().await?;
          match frame.ether_type {
            ethernet::frame::EtherType::ARP => {
              let arp = arp.clone();
              let receiver = receiver.clone();
              tokio::spawn(async move {
                match arp.receive(frame, &receiver).await {
                  Err(e) => {
                    log::error!("ARP error: {} {}", receiver.name(), e);
                  }
                  _ => {}
                }
              });
            }
            ethernet::frame::EtherType::BRSTACK => {
              let data = frame.data().unwrap();
              let data = String::from_utf8(data.to_vec())?;
              log::debug!("Received data: {} {:?}", receiver.name(), data);
            }
            _ => {}
          }
          Ok(())
        }.await;
        match receive_single {
          Ok(_) => {},
          Err(e) => {
            log::error!("Error receiving frame: {:?}", e);
          }
        }
      }
    });
  }
  loop {
    // このループは、メインスレッドが終了しないようにするためのもの
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
  }
}
