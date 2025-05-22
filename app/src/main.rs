

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
  let router = ipv4::Router::new(arp_table.clone());
  let icmp = icmp::ICMPService::new(router.clone());
  for iface in interfaces {
    let sender = iface.clone();
    let icmp = icmp.clone();
    tokio::spawn(async move {
      let id :u16 = (sender.ipv4_address().address.0[2] as u16) << 8 | sender.ipv4_address().address.0[3] as u16;  
      let mut seq = 0;
      loop {
        icmp.send_echo_request(dst_ip, id, seq, b"Hello brstack!").await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        seq += 1;
      }
    });
    let receiver = iface;
    let arp = arp_table.clone();
    let router = router.clone();
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
            ethernet::frame::EtherType::IPv4 => {
              let router = router.clone();
              let receiver = receiver.clone();
              tokio::spawn(async move {
                match router.receive(&receiver, &frame).await {
                  Err(e) => {
                    log::error!("IPv4 error: {} {}", receiver.name(), e);
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
