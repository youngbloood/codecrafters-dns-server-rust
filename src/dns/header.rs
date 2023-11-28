use byteorder::{BigEndian, ByteOrder};

pub struct Header([u8; 12]);

impl Header {
    pub fn new(raw: [u8; 12]) -> Self {
        return Header(raw);
    }

    pub fn id(&self) -> u16 {
        return BigEndian::read_u16(&self.0[..2]);
    }

    pub fn qr(&self) -> u8 {
        return self.0[3] & 1;
    }

    pub fn op_code(&self) -> u8 {
        return self.0[3] & (1 << 1 | 1 << 2 | 1 << 3 | 1 << 4);
    }

    pub fn aa(&self) -> u8 {
        return self.0[3] & 1 << 5;
    }

    pub fn tc(&self) -> u8 {
        return self.0[3] & 1 << 6;
    }

    pub fn rd(&self) -> u8 {
        return self.0[3] & 1 << 7;
    }

    pub fn ra(&self) -> u8 {
        return self.0[4] & 1;
    }

    pub fn z(&self) -> u8 {
        return self.0[4] & (1 << 1 | 1 << 2 | 1 << 3);
    }

    pub fn r_code(&self) -> u8 {
        return self.0[4] & (1 << 4 | 1 << 5 | 1 << 6 | 1 << 7);
    }

    pub fn qd_count(&self) -> u16 {
        return BigEndian::read_u16(&self.0[4..6]);
    }

    pub fn an_count(&self) -> u16 {
        return BigEndian::read_u16(&self.0[6..8]);
    }

    pub fn ns_count(&self) -> u16 {
        return BigEndian::read_u16(&self.0[8..10]);
    }

    pub fn ar_count(&self) -> u16 {
        return BigEndian::read_u16(&self.0[10..]);
    }

    pub fn zero(&self) -> [u8; 12] {
        return self.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_header_id() {
        let head = Header([1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(258, head.id());

        println!("1 = {}", 1 << 1);
    }
}
