
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }
}

pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }
}

pub struct Ipv4Prefix {
    pub address: Ipv4Address,
    pub mask: Ipv4Address,
    pub prefix_length: u8,
}

impl Ipv4Prefix {
    pub fn new(a: u8, b: u8, c: u8, d: u8, prefix_length: u8) -> Self {
        let mut mask = [0; 4];
        for i in 0..prefix_length {
            mask[i as usize / 8] |= 1 << (7 - (i % 8));
        }
        Self {
            address: Ipv4Address([a, b, c, d]),
            mask: Ipv4Address(mask),
            prefix_length,
        }
    }
}