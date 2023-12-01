trait BitOption {
    fn set_0(&mut self, pos: u8);
    fn set_1(&mut self, pos: u8);
}

impl BitOption for &mut u8 {
    fn set_0(&mut self, pos: u8) {
        if pos >= 8 {
            return;
        }
        let value = 1 << pos;
        // pos位是0，直接返回
        if value != **self & value {
            return;
        }
        // pos位是1，将其置为0
        **self = **self & (!value);
    }

    fn set_1(&mut self, pos: u8) {
        if pos >= 8 {
            return;
        }
        let value = 1 << pos;
        // pos位是1，直接返回
        if value == **self & value {
            return;
        }
        // pos位是0，将其置为1
        **self = **self & u8::MAX | value;
    }
}

pub struct Header([u8; 12]);

impl Header {
    pub fn new(raw: [u8; 12]) -> Self {
        return Header(raw);
    }

    fn set_bit(&mut self, index: usize, pos: u8, val: u8) -> &mut Self {
        if index > self.0.len() || pos >= 8 || val > 1 {
            return self;
        }
        let mut b = &mut self.0[index];
        if val == 1 {
            b.set_1(pos);
        } else {
            b.set_0(pos);
        }
        self.0[index] = *b;

        return self;
    }
    // Packet Identifier (ID): 16 bits;
    // A random ID assigned to query packets. Response packets must reply with the same ID.
    // Expected value: 1234.
    pub fn id(&self) -> u16 {
        let id = [self.0[0], self.0[1]];
        return u16::from_be_bytes(id);
    }

    pub fn with_id(&mut self, id: u16) -> &mut Self {
        let ids = id.to_be_bytes();
        (self.0[0], self.0[1]) = (ids[0], ids[1]);
        return self;
    }

    // Query/Response Indicator (QR): 1 bit
    // 1 for a reply packet, 0 for a question packet.
    // Expected value: 1.
    pub fn qr(&self) -> u8 {
        return self.0[2] & 0b0000_0001;
    }

    pub fn with_qr(&mut self, qr: u8) -> &mut Self {
        if qr > 1 {
            return self;
        }
        return self.set_bit(2, 0, qr);
    }

    // Operation Code (OPCODE): 4 bits
    // Specifies the kind of query in a message.
    // Expected value: 0.
    pub fn opcode(&self) -> u8 {
        return (self.0[2] & 0b0001_1110) >> 1;
    }

    pub fn with_opcode(&mut self, opcode: u8) -> &mut Self {
        if opcode << 1 > 0b0001_1110 {
            return self;
        }

        if opcode << 1 & 0b0000_0010 == 0b0000_0010 {
            self.set_bit(2, 1, 1);
        } else {
            self.set_bit(2, 1, 0);
        }
        if opcode << 1 & 0b0000_0100 == 0b0000_0100 {
            self.set_bit(2, 2, 1);
        } else {
            self.set_bit(2, 2, 0);
        }
        if opcode << 1 & 0b0000_1000 == 0b0000_1000 {
            self.set_bit(2, 3, 1);
        } else {
            self.set_bit(2, 3, 0);
        }
        if opcode << 1 & 0b0001_0000 == 0b0001_0000 {
            self.set_bit(2, 4, 1);
        } else {
            self.set_bit(2, 4, 0);
        }

        return self;
    }

    // Authoritative Answer (AA): 1 bit
    // 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    // Expected value: 0.
    pub fn aa(&self) -> u8 {
        return (self.0[2] & 0b0010_0000) >> 5;
    }

    pub fn with_aa(&mut self, aa: u8) -> &mut Self {
        if aa > 1 {
            return self;
        }
        return self.set_bit(2, 5, aa);
    }

    // Truncation (TC): 1 bit
    // 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    // Expected value: 0.
    pub fn tc(&self) -> u8 {
        return (self.0[2] & 0b0100_0000) >> 6;
    }

    pub fn with_tc(&mut self, tc: u8) -> &mut Self {
        if tc > 1 {
            return self;
        }
        return self.set_bit(2, 6, tc);
    }

    // Recursion Desired (RD): 1 bit
    // Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    // Expected value: 0.
    pub fn rd(&self) -> u8 {
        return (self.0[2] & 0b1000_0000) >> 7;
    }

    pub fn with_rd(&mut self, rd: u8) -> &mut Self {
        if rd > 1 {
            return self;
        }
        return self.set_bit(2, 7, rd);
    }

    // Recursion Available (RA): 1 bit
    // Server sets this to 1 to indicate that recursion is available.
    // Expected value: 0.
    pub fn ra(&self) -> u8 {
        return self.0[3] & 0b0000_0001;
    }

    pub fn with_ra(&mut self, ra: u8) -> &mut Self {
        if ra > 1 {
            return self;
        }
        return self.set_bit(3, 0, ra);
    }

    // Reserved (Z): 3 bits
    // Used by DNSSEC queries. At inception, it was reserved for future use.
    // Expected value: 0.
    pub fn z(&self) -> u8 {
        return (self.0[3] & 0b0000_1110) >> 1;
    }

    pub fn with_z(&mut self, z: u32) -> &mut Self {
        if z << 1 > 0b0000_1110 {
            return self;
        }

        if z << 1 & 0b0000_0010 == 0b0000_0010 {
            self.set_bit(3, 1, 1);
        } else {
            self.set_bit(3, 1, 0);
        }
        if z << 1 & 0b0000_0100 == 0b0000_0100 {
            self.set_bit(3, 2, 1);
        } else {
            self.set_bit(3, 2, 0);
        }
        if z << 1 & 0b0000_1000 == 0b0000_1000 {
            self.set_bit(3, 3, 1);
        } else {
            self.set_bit(3, 3, 0);
        }

        return self;
    }

    // Response Code (RCODE):4 bits
    // Response code indicating the status of the response.
    // Expected value: 0 (no error).
    pub fn rcode(&self) -> u8 {
        return (self.0[3] & 0b1111_0000) >> 4;
    }

    pub fn with_rcode(&mut self, rcode: u32) -> &mut Self {
        if rcode << 4 > 0b1111_0000 {
            return self;
        }

        if rcode << 4 & 0b0001_0000 == 0b0001_0000 {
            self.set_bit(3, 4, 1);
        } else {
            self.set_bit(3, 4, 0);
        }
        if rcode << 4 & 0b0010_0000 == 0b0010_0000 {
            self.set_bit(3, 5, 1);
        } else {
            self.set_bit(3, 5, 0);
        }
        if rcode << 4 & 0b0100_0000 == 0b0100_0000 {
            self.set_bit(3, 6, 1);
        } else {
            self.set_bit(3, 6, 0);
        }
        if rcode << 4 & 0b1000_0000 == 0b1000_0000 {
            self.set_bit(3, 7, 1);
        } else {
            self.set_bit(3, 7, 0);
        }

        return self;
    }

    // Question Count (QDCOUNT): 16 bits
    // Number of questions in the Question section.
    // Expected value: 0.
    pub fn qdcount(&self) -> u16 {
        let qd: [u8; 2] = [self.0[4], self.0[5]];
        return u16::from_be_bytes(qd);
    }

    pub fn with_qdcount(&mut self, qdcount: u16) -> &mut Self {
        let bts = qdcount.to_be_bytes();
        (self.0[4], self.0[5]) = (bts[0], bts[1]);
        return self;
    }

    // Answer Record Count (ANCOUNT): 16 bits
    // Number of records in the Answer section.
    // Expected value: 0.
    pub fn ancount(&self) -> u16 {
        let an = [self.0[6], self.0[7]];
        return u16::from_be_bytes(an);
    }

    pub fn with_ancount(&mut self, ancount: u16) -> &mut Self {
        let bts = ancount.to_be_bytes();
        (self.0[6], self.0[7]) = (bts[0], bts[1]);
        return self;
    }

    // Authority Record Count (NSCOUNT): 16 bits
    // Number of records in the Authority section.
    // Expected value: 0.
    pub fn nscount(&self) -> u16 {
        let ns = [self.0[8], self.0[9]];
        return u16::from_be_bytes(ns);
    }

    pub fn with_nscount(&mut self, nscount: u16) -> &mut Self {
        let bts = nscount.to_be_bytes();
        (self.0[8], self.0[9]) = (bts[0], bts[1]);
        return self;
    }

    // Additional Record Count (ARCOUNT): 16 bits
    // Number of records in the Additional section.
    // Expected value: 0.
    pub fn arcount(&self) -> u16 {
        let ar = [self.0[10], self.0[11]];
        return u16::from_be_bytes(ar);
    }

    pub fn with_arcount(&mut self, arcount: u16) -> &mut Self {
        let bts = arcount.to_be_bytes();
        (self.0[10], self.0[11]) = (bts[0], bts[1]);
        return self;
    }

    pub fn get_0(&self) -> [u8; 12] {
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
    }

    #[test]
    pub fn test_header_with_id() {
        let mut head = Header([0; 12]);
        head.with_id(12);
        assert_eq!(12, head.id());
    }

    #[test]
    pub fn test_header_qr() {
        let mut head = Header([0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.qr());
        let head = Header([0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(0, head.qr());
    }

    #[test]
    pub fn test_header_with_qr() {
        let mut head = Header([0; 12]);
        head.with_qr(12);
        assert_eq!(0, head.qr());
        head.with_qr(1);
        assert_eq!(1, head.qr());
        head.with_qr(0);
        assert_eq!(0, head.qr());
    }

    #[test]
    pub fn test_header_opcode() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(15, head.opcode());
        head = Header([0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(15, head.opcode());
        head = Header([0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.opcode());
    }

    #[test]
    pub fn test_header_with_opcode() {
        let mut head = Header([0; 12]);
        head.with_opcode(12);
        assert_eq!(12, head.opcode());
        head.with_opcode(99);
        assert_eq!(12, head.opcode());
        head.with_opcode(15);
        assert_eq!(15, head.opcode());
    }

    #[test]
    pub fn test_header_aa() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.aa());
        let mut head = Header([0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(0, head.aa());
    }

    #[test]
    pub fn test_header_with_aa() {
        let mut head = Header([0; 12]);
        head.with_aa(1);
        assert_eq!(1, head.aa());
        head.with_aa(2);
        assert_eq!(1, head.aa());
        head.with_aa(0);
        assert_eq!(0, head.aa());
    }

    #[test]
    pub fn test_header_tc() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.tc());
        let mut head = Header([0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.tc());
        let mut head = Header([0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(0, head.tc());
    }

    #[test]
    pub fn test_header_with_tc() {
        let mut head = Header([0; 12]);
        head.with_tc(1);
        assert_eq!(1, head.tc());
        head.with_tc(2);
        assert_eq!(1, head.tc());
        head.with_tc(0);
        assert_eq!(0, head.tc());
    }

    #[test]
    pub fn test_header_rd() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.rd());
        let mut head = Header([0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.rd());
        let mut head = Header([0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(0, head.rd());
    }

    #[test]
    pub fn test_header_with_rd() {
        let mut head = Header([0; 12]);
        head.with_rd(1);
        assert_eq!(1, head.rd());
        head.with_rd(2);
        assert_eq!(1, head.rd());
        head.with_rd(0);
        assert_eq!(0, head.rd());
    }

    #[test]
    pub fn test_header_ra() {
        let mut head = Header([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.ra());
        let mut head = Header([0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.ra());
        let mut head = Header([0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(0, head.ra());
    }

    #[test]
    pub fn test_header_with_ra() {
        let mut head = Header([0; 12]);
        head.with_ra(1);
        assert_eq!(1, head.ra());
        head.with_ra(2);
        assert_eq!(1, head.ra());
        head.with_ra(0);
        assert_eq!(0, head.ra());
    }

    #[test]
    pub fn test_header_z() {
        let mut head = Header([0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(7, head.z());
    }

    #[test]
    pub fn test_header_with_z() {
        let mut head = Header([0; 12]);
        head.with_z(1);
        assert_eq!(1, head.z());
        head.with_z(7);
        assert_eq!(7, head.z());
        head.with_z(8);
        assert_eq!(7, head.z());
    }

    #[test]
    pub fn test_header_rcode() {
        let mut head = Header([0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(15, head.rcode());
    }

    #[test]
    pub fn test_header_with_rcode() {
        let mut head = Header([0; 12]);
        head.with_rcode(1);
        assert_eq!(1, head.rcode());
        head.with_rcode(7);
        assert_eq!(7, head.rcode());
        head.with_rcode(15);
        assert_eq!(15, head.rcode());
        head.with_rcode(16);
        assert_eq!(15, head.rcode());
    }

    #[test]
    pub fn test_header_qdcount() {
        let mut head = Header([0, 0, 0, 14, 2, 4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(516, head.qdcount());
    }

    #[test]
    pub fn test_header_with_qdcount() {
        let mut head = Header([0; 12]);
        head.with_qdcount(16);
        assert_eq!(16, head.qdcount());
        head.with_qdcount(516);
        assert_eq!(2, head.0[4]);
        assert_eq!(4, head.0[5]);
    }

    #[test]
    pub fn test_header_ancount() {
        let mut head = Header([0, 0, 0, 14, 0, 0, 2, 4, 0, 0, 0, 0]);
        assert_eq!(516, head.ancount());
    }

    #[test]
    pub fn test_header_with_ancount() {
        let mut head = Header([0; 12]);
        head.with_ancount(16);
        assert_eq!(16, head.ancount());
        head.with_ancount(516);
        assert_eq!(2, head.0[6]);
        assert_eq!(4, head.0[7]);
    }

    #[test]
    pub fn test_header_nscount() {
        let mut head = Header([0, 0, 0, 14, 0, 0, 0, 0, 2, 4, 0, 0]);
        assert_eq!(516, head.nscount());
    }

    #[test]
    pub fn test_header_with_nscount() {
        let mut head = Header([0; 12]);
        head.with_nscount(16);
        assert_eq!(16, head.nscount());
        head.with_nscount(516);
        assert_eq!(2, head.0[8]);
        assert_eq!(4, head.0[9]);
    }

    #[test]
    pub fn test_header_arcount() {
        let mut head = Header([0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 2, 4]);
        assert_eq!(516, head.arcount());
    }

    #[test]
    pub fn test_header_with_arcount() {
        let mut head = Header([0; 12]);
        head.with_arcount(16);
        assert_eq!(16, head.arcount());
        head.with_arcount(516);
        assert_eq!(2, head.0[10]);
        assert_eq!(4, head.0[11]);
    }
}
