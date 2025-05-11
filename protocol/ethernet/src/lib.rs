
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: net_common::MacAddress,
    pub ipv4_address: net_common::Ipv4Prefix,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
