

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  env_logger::init();
  let interfaces = ethernet::get_interfaces()?;
  let dst_ip = std::env::var("DST").unwrap().parse::<std::net::Ipv4Addr>()?;
  let dst_ip = net_common::Ipv4Address::new(
    dst_ip.octets()[0],
    dst_ip.octets()[1],
    dst_ip.octets()[2],
    dst_ip.octets()[3]
  );
  let arp_table = arp::AddressResolutionTable::default();
  for iface in interfaces {
    let sender = iface.clone();
    let arp = arp_table.clone();
    tokio::spawn(async move {
      let dst_mac = if sender.name()=="lo" {
        *sender.mac_address()
      } else { 
        match arp.get_dst_mac(&sender, &dst_ip).await {
          Ok(mac) => mac,
          Err(e) => {
            log::error!("ARP error: {} {}", sender.name(), e);
            return;
          }
        }
      };
      loop {
        sender.send(ethernet::frame::EtherType::BRSTACK,
          // 相手のMACアドレスがわかったので相手のアドレスを指定して通信する
          &dst_mac,
          // 規格上は最低46バイト必要だがDocker上ではそれより小さくても普通に通信できる
          format!("Hello from {}({})!", sender.name(), sender.mac_address()).as_bytes()
        ).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
      }
    });
    let receiver = iface;
    let arp = arp_table.clone();
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
