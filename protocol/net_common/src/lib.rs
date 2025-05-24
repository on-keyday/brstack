
#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub struct Ipv4Address(pub [u8; 4]);

pub const UNSPECIFIED : Ipv4Address = Ipv4Address([0, 0, 0, 0]);

impl Ipv4Address {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }
}

impl Ipv4Address {
    pub fn is_broadcast(&self) -> bool {
        self.0 == [255, 255, 255, 255]
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0xF0 == 0xE0
    }

    pub fn is_unspecified(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

impl std::hash::Hash for Ipv4Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

impl std::fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}",
            self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[derive(Debug, Clone,Copy)]
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

    pub fn contains(&self, address: &Ipv4Address) -> bool {
        let masked_self_address = Ipv4Address([
            self.address.0[0] & self.mask.0[0],
            self.address.0[1] & self.mask.0[1],
            self.address.0[2] & self.mask.0[2],
            self.address.0[3] & self.mask.0[3],
        ]);
        let masked_address = Ipv4Address([
            address.0[0] & self.mask.0[0],
            address.0[1] & self.mask.0[1],
            address.0[2] & self.mask.0[2],
            address.0[3] & self.mask.0[3],
        ]);
        masked_self_address == masked_address
    }

    pub fn is_network_address(&self,target :Ipv4Address) -> bool {
        // 下位ビットが0であるかを確認
        for i in 0..4 {
            if target.0[i] & !self.mask.0[i] != 0 {
                return false;
            }
        }
        true
    }

    pub fn is_broadcast_address(&self,target :Ipv4Address) -> bool {
        // 下位ビットが1であるかを確認
        for i in 0..4 {
            if target.0[i] & !self.mask.0[i] != !self.mask.0[i] {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}",
            self.address, self.prefix_length)
    }
}

mod enums;
pub use enums::NeighborCacheState;
pub use enums::ICMPv4DstUnreachableCode;
pub use enums::ICMPv4TimeExceededCode;