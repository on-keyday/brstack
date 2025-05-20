
pub struct RoutingEntry {
    pub prefix :net_common::Ipv4Prefix,
    pub next_hop: net_common::Ipv4Address,
    pub device : ethernet::NetworkInterface,
}

struct RoutingTrieNode {
    pub children: [Option<Box<RoutingTrieNode>>; 2],
    pub entry: Option<std::sync::Arc<RoutingEntry>>,
}
impl RoutingTrieNode {
    pub fn new() -> Self {
        RoutingTrieNode {
            children: [None, None],
            entry: None,
        }
    }
}

pub struct RoutingTable {
    root: tokio::sync::RwLock<RoutingTrieNode>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable {
            root: tokio::sync::RwLock::new(RoutingTrieNode::new()),
        }
    }

    pub async fn insert(&mut self, prefix: net_common::Ipv4Prefix, next_hop: net_common::Ipv4Address, device: ethernet::NetworkInterface) {
        let mut node = self.root.write().await;
        let mut node = &mut *node;
        for i in (0..prefix.prefix_length).rev() {
            let bit = (prefix.address.0[(i / 8) as usize] >> (7 - (i % 8))) & 1;
            if node.children[bit as usize].is_none() {
                node.children[bit as usize] = Some(Box::new(RoutingTrieNode::new()));
            }
            node = node.children[bit as usize].as_mut().unwrap();
        }
        node.entry = Some(std::sync::Arc::new(RoutingEntry {
            prefix,
            next_hop,
            device,
        }));
    }

    pub async fn lookup(&self, address: &net_common::Ipv4Address) -> Option<std::sync::Arc<RoutingEntry>> {
        let node = self.root.read().await;
        let mut node = &*node;
        let mut best_entry: Option<std::sync::Arc<RoutingEntry>> = None;

        for i in (0..32).rev() {
            if let Some(entry) = &node.entry {
                best_entry = Some(entry.clone());
            }
            let bit = (address.0[(i / 8) as usize] >> (7 - (i % 8))) & 1;
            if node.children[bit as usize].is_none() {
                break;
            }
            node = node.children[bit as usize].as_ref().unwrap();
        }

        best_entry
    }
}
