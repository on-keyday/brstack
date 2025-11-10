
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
            let bits = splited[1].parse::<u8>().expect("Bits should be a number");
            if bits > 32 {
                panic!("Invalid arguments");
            }
            let prefix_addr = splited[0].parse::<std::net::Ipv4Addr>().expect("IP address should be here").octets();
            (
                net_common::Ipv4Prefix::new(
                    prefix_addr[0],
                    prefix_addr[1],
                    prefix_addr[2],
                    prefix_addr[3],
                    bits,
                ),
                net_common::Ipv4Address(chunk[1].parse::<std::net::Ipv4Addr>().expect("IP address should be here").octets()),
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
  tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .thread_name("brstack-thread")
    .build()
    .unwrap()
    .block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
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
  for (prefix, next_hop,device) in routing {
    if role == "nat_router" {
      if prefix.prefix_length == 0 { // デフォルトルートをnatの外側として扱う
        let nat =  nat::NAT::new(device.clone(),20000,65534);
        router.register_nat(Box::new(nat)).await;
      }
    }
    router.add_route(prefix, next_hop, device).await;
  }
  icmp::ICMPService::register(router.clone());
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
  if role == "client" {
    let dst_ip = dst_ip.expect("DST should be set for client");
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

  } else if role == "stun_client" {
    let dst_ip = dst_ip.expect("DST should be set for stun_client");
    let udp = udp.clone();
    tokio::spawn(async move {
      let stun_transaction_id: [u8; 12] = [123, 45, 67, 89, 10, 11, 12, 13, 14, 15, 16, 17];
      let mut stun_client = stun::StunClient::new(
        udp.connect(
          net_common::AddrPort { address: dst_ip, port: 19302 },None
        ).await.unwrap(),
        stun_transaction_id,
      );
      loop {
        match stun_client.send(
          net_common::AddrPort { address: dst_ip, port: 19302 }
        ).await {
          Ok(_) => {
            log::info!("Sent STUN Binding Request to {}", dst_ip);
          }
          Err(e) => {
            log::error!("Error sending STUN Binding Request: {}", e);
            return;
          }
        }
        tokio::select! {
          _ = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => {
            log::error!("Error: No STUN response received within timeout");
            continue;
          },
          x = stun_client.receive() => match x {
            Ok((from, hdr, attrs)) => {
              log::info!("Received STUN response from {}:{} {:?} {:?}", from,hdr.msg_type, hdr, attrs);
              for attr in attrs.iter() {
                if let Some(xor_mapped) = attr.xor_mapped_address() {
                  let demapped = stun::demap_xor_address(stun_transaction_id, xor_mapped);
                  log::info!("XOR-MAPPED-ADDRESS: {}:{}", net_common::Ipv4Address::new(
                    demapped.address[0],
                    demapped.address[1],
                    demapped.address[2],
                    demapped.address[3],
                  ), demapped.port);
                } else if let Some(mapped) = attr.mapped_address() {
                  log::info!("MAPPED-ADDRESS: {}:{}", net_common::Ipv4Address::new(
                    mapped.address[0],
                    mapped.address[1],
                    mapped.address[2],
                    mapped.address[3],
                  ), mapped.port);    
                }
              }
            }
            Err(e) => {
              log::error!("Error receiving STUN response: {}", e);
            },
          }
        };
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
      }
    });
  } else if role == "ntp_client" {
    let dst_ip = dst_ip.expect("DST should be set for ntp_client");
    let udp_socket = udp.connect(
      net_common::AddrPort { address: dst_ip, port: 123 },None
    ).await.unwrap();
    let mut ntp_handler = ntp::NTPHandler::new(udp_socket);
    tokio::spawn( async move {
      loop {
        match ntp_handler.time(
          net_common::AddrPort { address: dst_ip, port: 123 }
        ).await {
          Ok(_) => {
            log::info!("NTP request successful to {}", dst_ip);
          }
          Err(e) => {
            log::error!("Error in NTP request to {}: {}", dst_ip, e);
          }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
      }
    });
  }
  loop {
    // このループは、メインスレッドが終了しないようにするためのもの
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
  }
}
