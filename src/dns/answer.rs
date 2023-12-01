use std::net::Ipv4Addr;

// RR
pub struct ResourceRecord {
    names: Vec<String>,
    typ: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl ResourceRecord {
    pub fn new() -> Self {
        Self {
            names: vec![],
            typ: 0,
            class: 0,
            ttl: 0,
            rdlength: 0,
            rdata: vec![],
        }
    }

    pub fn with_name(&mut self, name: &str) -> &mut Self {
        self.names.push(name.to_string());
        return self;
    }

    pub fn with_type(&mut self, typ: u16) -> &mut Self {
        self.typ = typ;
        return self;
    }

    pub fn with_class(&mut self, class: u16) -> &mut Self {
        self.class = class;
        return self;
    }

    pub fn with_ttl(&mut self, ttl: u32) -> &mut Self {
        self.ttl = ttl;
        return self;
    }

    pub fn with_rdata(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.rdata = ip.octets().to_vec();
        return self;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        // encode names
        for name in &self.names {
            result.push(name.len() as u8);
            for v in name.as_bytes() {
                result.push(*v);
            }
        }
        result.push(b'\x00');

        // encode type
        result.extend_from_slice(&self.typ.to_be_bytes());
        // encode class
        result.extend_from_slice(&self.class.to_be_bytes());
        // encode class
        result.extend_from_slice(&self.ttl.to_be_bytes());
        // encode length
        result.extend_from_slice(&self.rdlength.to_be_bytes());
        // encode data
        result.extend_from_slice(&self.rdata);

        result
    }
}

pub struct Answers(Vec<ResourceRecord>);

impl Answers {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn extend(&mut self, rr: ResourceRecord) {
        self.0.push(rr);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        for rr in &self.0 {
            // encode names
            result.extend_from_slice(&rr.encode());
        }

        return result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    pub fn test_rr_with_name() {
        let mut rr = ResourceRecord::new();
        rr.with_name("google.com");
        assert_eq!(1, rr.names.len());
        assert_eq!(&"google.com", &rr.names.get(0).unwrap().as_str());

        rr.with_name("amazon.com");
        assert_eq!(2, rr.names.len());
        assert_eq!(&"amazon.com", &rr.names.get(1).unwrap().as_str());
    }

    #[test]
    pub fn test_rr_with_typ() {
        let mut rr = ResourceRecord::new();
        rr.with_type(1);
        assert_eq!(1, rr.typ);

        rr.with_type(2);
        assert_eq!(2, rr.typ);
    }

    #[test]
    pub fn test_rr_with_class() {
        let mut rr = ResourceRecord::new();
        rr.with_class(1);
        assert_eq!(1, rr.class);

        rr.with_class(2);
        assert_eq!(2, rr.class);
    }

    #[test]
    pub fn test_rr_with_ttl() {
        let mut rr = ResourceRecord::new();
        rr.with_ttl(1);
        assert_eq!(1, rr.ttl);

        rr.with_ttl(2);
        assert_eq!(2, rr.ttl);
    }

    #[test]
    pub fn test_rr_with_rdata() {
        let mut rr = ResourceRecord::new();
        rr.with_rdata(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(vec![10_u8, 0, 0, 1], rr.rdata);

        rr.with_rdata(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(vec![10_u8, 0, 0, 2], rr.rdata);
    }
}
