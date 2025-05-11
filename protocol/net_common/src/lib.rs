
pub struct MacAddress(pub [u8; 6]);

pub struct Ipv4Address(pub [u8; 4]);

pub struct Ipv4Prefix {
    pub address: Ipv4Address,
    pub mask: Ipv4Address,
    pub prefix_length: u8,
}