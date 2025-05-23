
fn parse_routing_table(routing: &str, interfaces: Vec<ethernet::NetworkInterface>) -> Vec<(net_common::Ipv4Prefix, net_common::Ipv4Address, ethernet::NetworkInterface)> {
    routing
        .split(" ")
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| {
            if chunk.len() != 2 {
                panic!("Invalid arguments");
            }
            let splited = chunk[0].split("/").collect::<Vec<_>>();
            if splited.len() != 2 {
                panic!("Invalid arguments");
            }
            let bits = splited[1].parse::<u8>().unwrap();
            if bits > 32 {
                panic!("Invalid arguments");
            }
            let prefix_addr = splited[0].parse::<std::net::Ipv4Addr>().unwrap().octets();
            (
                net_common::Ipv4Prefix::new(
                    prefix_addr[0],
                    prefix_addr[1],
                    prefix_addr[2],
                    prefix_addr[3],
                    bits,
                ),
                net_common::Ipv4Address(chunk[1].parse::<std::net::Ipv4Addr>().unwrap().octets()),
            )
        })
        .map(|(prefix,next_hop)|{
           let target = if next_hop == net_common::Ipv4Address::new(0,0,0,0) {
              prefix.address
            } else {
              next_hop
            };
            let mut longest: Option<ethernet::NetworkInterface>  = None;
            for iface in &interfaces {
              if iface.ipv4_address().contains(&target) {
                match longest {
                  Some(ref mut l) if l.ipv4_address().prefix_length < iface.ipv4_address().prefix_length => {
                    *l = iface.clone();
                  }
                  None => {
                    longest = Some(iface.clone());
                  }
                  _ => {}
                }
              }
            }
            if longest.is_none() {
              panic!("No interface found for prefix {}", prefix);
            }
            (prefix, next_hop, longest.unwrap())
        }) 
        .collect::<Vec<_>>()
}

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
  let routing = std::env::var("ROUTING").expect("ROUTING should be set");
  let routing = parse_routing_table(&routing, interfaces.clone());
  let arp_table = arp::AddressResolutionTable::default();
  let router = ipv4::Router::new(arp_table.clone());
  for (prefix, next_hop, longest) in routing {
    router.add_route(prefix, next_hop, longest).await;
  }
  let icmp = icmp::ICMPService::new(router.clone());
  for iface in interfaces {
    if iface.ipv4_address().contains(&dst_ip) {
      let sender = iface.clone();
      let icmp = icmp.clone();
      tokio::spawn(async move {
        let id :u16 = (sender.ipv4_address().address.0[2] as u16) << 8 | sender.ipv4_address().address.0[3] as u16;  
        let mut seq = 0;
        loop {
          match icmp.send_echo_request(dst_ip, id, seq, b"Hello brstack!").await {
            Ok(_) => {
              log::info!("Sent echo request: {} id: {} seq: {}", sender.name(), id, seq);
            }
            Err(e) => {
              log::error!("Error sending echo request: {} {}", sender.name(), e);
            }
          }
          tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
          seq += 1;
        }
      });
    }
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
