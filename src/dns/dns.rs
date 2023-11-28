use super::Header;
pub struct DNS {
    raw: Vec<u8>,
    head: Header,
}

impl DNS {
    pub fn from(raw: &[u8]) -> Self {
        Self {
            raw: raw.to_vec(),
            head: Header::new(raw[..12].try_into().expect("slice covert to array error")),
        }
    }

    pub fn head(&self) -> &Header {
        return &self.head;
    }
}
