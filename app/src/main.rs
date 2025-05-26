
fn parse_routing_table(routing: &str, interfaces: Vec<ethernet::NetworkInterface>) -> Vec<(net_common::Ipv4Prefix, net_common::Ipv4Address, ethernet::NetworkInterface)> {
    routing
        .split(" ").filter(|s| !s.is_empty())
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
  // DSTがある場合は、環境変数から取得する(でなければNone)
  let dst_ip = std::env::var("DST").ok().map(|v| {
    let v = v.parse::<std::net::Ipv4Addr>().unwrap();
    net_common::Ipv4Address::new(
      v.octets()[0],
      v.octets()[1],
      v.octets()[2],
      v.octets()[3]
    )
  });
  let routing = std::env::var("ROUTING").expect("ROUTING should be set");
  let role = std::env::var("ROLE").expect("ROLE should be set");
  let routing = parse_routing_table(&routing, interfaces.clone());
  let arp_table = arp::AddressResolutionTable::default();
  let router = ipv4::Router::new(arp_table.clone());
  for (prefix, next_hop, longest) in routing {
    router.add_route(prefix, next_hop, longest).await;
  }
  let icmp = icmp::ICMPService::new(router.clone());
  let udp = udp::UDPHub::new(router.clone());


  for iface in interfaces {
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
  if let Some(dst_ip) = dst_ip {
    let udp = udp.clone();
    tokio::spawn(async move {
      let mut socket = udp.connect(
        net_common::AddrPort { address: dst_ip, port: 12345 },None
      ).await.unwrap();
      let mut seq = 0;
      loop {
        let data = format!("Hello from client {}! Seq: {}", socket.local_addr(), seq);
        match socket.send(data.as_bytes()).await {
          Ok(_) => {
            log::info!("Sent data: {}", data);
          }
          Err(e) => {
            log::error!("Error sending data: {}", e);
          }
        }
        tokio::select!{
          Ok(response) = socket.receive() => {
            log::info!("Received response: {}", String::from_utf8_lossy(&response));
          }
          _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
            log::error!("Error: No response received within timeout");
          }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        seq += 1;
      }
    });
  } else if role == "server" {
    let udp = udp.clone();
    tokio::spawn(async move {
        let mut socket =  udp.bind(net_common::AddrPort { address: net_common::UNSPECIFIED, port: 12345 }).await.unwrap();
        loop {
          let (data,peer) =match socket.receive_from().await {
            Ok(data) => data,
            Err(e) => {
              log::error!("Error receiving data: {}", e);
              continue;
            }
          };
          log::info!("Received data from {}: {}", peer, String::from_utf8_lossy(&data));
          let response = format!("Hello from server! {} Received: {}", socket.local_addr(), String::from_utf8_lossy(&data));
          match socket.send_to(peer,response.as_bytes()).await {
            Ok(_) => {
              log::info!("Sent response to {}: {}", peer, response);
            }
            Err(e) => {
              log::error!("Error sending response: {}", e);
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
