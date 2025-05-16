

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  env_logger::init();
  let interfaces = ethernet::get_interfaces()?;
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
        log::info!("Sent frame: {} {}", sender.name(), sender.mac_address());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
      }
    });
    let receiver = iface;
    tokio::spawn(async move {
      loop {
        let receive_single :Result<(), Box<dyn std::error::Error>> = async {
          let frame = receiver.recv().await?;
          if receiver.name()!="lo" && frame.src_mac == receiver.mac_address().0 {
            // 自分のMACアドレスからのフレームは無視(ループバックインターフェースのフレームは例外)
            return Ok(());
          }
          log::info!("Received frame: {} {:?}",receiver.name(), frame);
          let reencoded = frame.encode_to_vec()?;
          log::info!("Raw bytes: {} len {} {:x?}",receiver.name(), reencoded.len(), reencoded);
          if frame.ether_type == ethernet::frame::EtherType::BRSTACK {
            let data = frame.data().unwrap();
            let data = String::from_utf8(data.to_vec())?;
            log::info!("Received data: {} {:?}", receiver.name(), data);
          }
          Ok(())
        }.await;
        match receive_single {
          Ok(_) => {},
          Err(e) => {
            log::error!("Error receiving frame: {:?}", e);
            break;
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
