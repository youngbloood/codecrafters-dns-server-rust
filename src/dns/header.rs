use nom::bits;

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

    pub fn id_with(&mut self, id: u16) -> &mut Self {
        let ids = id.to_be_bytes();
        (self.0[0], self.0[1]) = (ids[0], ids[1]);
        return self;
    }

    // Query/Response Indicator (QR): 1 bit
    // 1 for a reply packet, 0 for a question packet.
    // Expected value: 1.
    pub fn qr(&self) -> u8 {
        return self.0[3] & 0b0000_0001;
    }

    pub fn qr_with(&mut self, qr: u8) -> &mut Self {
        if qr > 1 {
            return self;
        }
        return self.set_bit(3, 0, qr);
    }

    // Operation Code (OPCODE): 4 bits
    // Specifies the kind of query in a message.
    // Expected value: 0.
    pub fn op_code(&self) -> u8 {
        return self.0[3] & 0b0001_1110 >> 1;
    }

    pub fn op_code_with(&mut self, op_code: u8) -> &mut Self {
        if op_code << 1 > 0b0001_1110 {
            return self;
        }

        if op_code << 1 & 0b0000_0010 == 0b0000_0010 {
            self.set_bit(3, 1, 1);
        } else {
            self.set_bit(3, 1, 0);
        }
        if op_code << 1 & 0b0000_0100 == 0b0000_0100 {
            self.set_bit(3, 2, 1);
        } else {
            self.set_bit(3, 2, 0);
        }
        if op_code << 1 & 0b0000_1000 == 0b0000_1000 {
            self.set_bit(3, 3, 1);
        } else {
            self.set_bit(3, 3, 0);
        }
        if op_code << 1 & 0b0001_0000 == 0b0001_0000 {
            self.set_bit(3, 4, 1);
        } else {
            self.set_bit(3, 4, 0);
        }

        return self;
    }

    // Authoritative Answer (AA): 1 bit
    // 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    // Expected value: 0.
    pub fn aa(&self) -> u8 {
        return self.0[3] & 1 << 5;
    }

    pub fn aa_with(&mut self, aa: u8) -> &mut Self {
        if aa > 1 {
            return self;
        }
        return self.set_bit(3, 5, aa);
    }

    // Truncation (TC): 1 bit
    // 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    // Expected value: 0.
    pub fn tc(&self) -> u8 {
        return self.0[3] & 1 << 6;
    }

    pub fn tc_with(&mut self, tc: u8) -> &mut Self {
        if tc > 1 {
            return self;
        }
        return self.set_bit(3, 6, tc);
    }

    // Recursion Desired (RD): 1 bit
    // Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    // Expected value: 0.
    pub fn rd(&self) -> u8 {
        return self.0[3] & 0b1000_0000;
    }

    pub fn rd_with(&mut self, rd: u8) -> &mut Self {
        if rd > 1 {
            return self;
        }
        return self.set_bit(3, 7, rd);
    }

    // Recursion Available (RA): 1 bit
    // Server sets this to 1 to indicate that recursion is available.
    // Expected value: 0.
    pub fn ra(&self) -> u8 {
        return self.0[4] & 0b0000_0001;
    }

    pub fn ra_with(&mut self, ra: u8) -> &mut Self {
        if ra > 1 {
            return self;
        }
        return self.set_bit(3, 1, ra);
    }

    // Reserved (Z): 3 bits
    // Used by DNSSEC queries. At inception, it was reserved for future use.
    // Expected value: 0.
    pub fn z(&self) -> u8 {
        return self.0[4] & 0b0000_1110;
    }

    pub fn z_with(&mut self, z: u32) -> &mut Self {
        if z << 1 > 0b0000_1110 {
            return self;
        }

        if z << 1 & 0b0000_0010 == 0b0000_0010 {
            self.set_bit(4, 1, 1);
        } else {
            self.set_bit(4, 1, 0);
        }
        if z << 1 & 0b0000_0100 == 0b0000_0100 {
            self.set_bit(4, 2, 1);
        } else {
            self.set_bit(4, 2, 0);
        }
        if z << 1 & 0b0000_1000 == 0b0000_1000 {
            self.set_bit(4, 3, 1);
        } else {
            self.set_bit(4, 3, 0);
        }

        return self;
    }

    // Response Code (RCODE):4 bits
    // Response code indicating the status of the response.
    // Expected value: 0 (no error).
    pub fn r_code(&self) -> u8 {
        return self.0[4] & 0b1111_0000;
    }

    pub fn r_code_with(&mut self, rcode: u32) -> &mut Self {
        if rcode << 4 > 0b1111_0000 {
            return self;
        }

        if rcode << 4 & 0b0001_0000 == 0b0001_0000 {
            self.set_bit(4, 4, 1);
        } else {
            self.set_bit(4, 4, 0);
        }
        if rcode << 4 & 0b0010_0000 == 0b0010_0000 {
            self.set_bit(4, 5, 1);
        } else {
            self.set_bit(4, 5, 0);
        }
        if rcode << 4 & 0b0100_0000 == 0b0100_0000 {
            self.set_bit(4, 6, 1);
        } else {
            self.set_bit(4, 6, 0);
        }
        if rcode << 4 & 0b1000_0000 == 0b1000_0000 {
            self.set_bit(4, 7, 1);
        } else {
            self.set_bit(4, 7, 0);
        }

        return self;
    }

    // Question Count (QDCOUNT): 16 bits
    // Number of questions in the Question section.
    // Expected value: 0.
    pub fn qd_count(&self) -> u16 {
        let qd = [self.0[4], self.0[5]];
        return u16::from_be_bytes(qd);
    }

    pub fn qd_count_with(&mut self, qdcount: u16) -> &mut Self {
        let bts = qdcount.to_be_bytes();
        (self.0[4], self.0[5]) = (bts[0], bts[1]);
        return self;
    }

    // Answer Record Count (ANCOUNT): 16 bits
    // Number of records in the Answer section.
    // Expected value: 0.
    pub fn an_count(&self) -> u16 {
        let an = [self.0[6], self.0[7]];
        return u16::from_be_bytes(an);
    }

    pub fn an_count_with(&mut self, ancount: u16) -> &mut Self {
        let bts = ancount.to_be_bytes();
        (self.0[6], self.0[7]) = (bts[0], bts[1]);
        return self;
    }

    // Authority Record Count (NSCOUNT): 16 bits
    // Number of records in the Authority section.
    // Expected value: 0.
    pub fn ns_count(&self) -> u16 {
        let ns = [self.0[8], self.0[9]];
        return u16::from_be_bytes(ns);
    }

    pub fn ns_count_with(&mut self, nscount: u16) -> &mut Self {
        let bts = nscount.to_be_bytes();
        (self.0[8], self.0[9]) = (bts[0], bts[1]);
        return self;
    }

    // Additional Record Count (ARCOUNT): 16 bits
    // Number of records in the Additional section.
    // Expected value: 0.
    pub fn ar_count(&self) -> u16 {
        let ar = [self.0[10], self.0[11]];
        return u16::from_be_bytes(ar);
    }

    pub fn ar_count_with(&mut self, arcount: u16) -> &mut Self {
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

        println!("1 = {}", 1 << 1);
    }
}
