use anyhow::Error;
use nom::AsChar;

#[derive(Debug)]
pub struct Question {
    length: usize,
    names: Vec<String>,
    typ: u16,
    class: u16,
}

impl Question {
    pub fn new(raw: &mut [u8]) -> Result<Self, Error> {
        let pkg_err = Err(Error::msg("the question package not incomplete"));
        if raw.len() == 0 {
            return pkg_err;
        }

        let mut ques = Question {
            names: vec![],
            typ: 0,
            class: 0,
            length: 0,
        };

        let mut domain_length = 0;
        // parse domain name
        let mut iter = raw.as_ref().into_iter();
        let mut start = 0_usize;
        loop {
            let u = iter.next().unwrap();
            start += 1;
            domain_length += 1;
            if u.as_char().eq(&'\x00') {
                break;
            }

            let mut length = *u as usize;
            domain_length += length;

            if start + length >= raw.len() {
                return pkg_err;
            }
            ques.names
                .extend(String::from_utf8(raw[start..start + length].to_vec()));
            while length > 0 {
                iter.next();
                start += 1;
                length -= 1;
            }
        }

        if domain_length + 4 > raw.len() {
            return pkg_err;
        }
        // parse typ
        ques.typ = u16::from_be_bytes(raw[domain_length..domain_length + 2].try_into()?);
        // parse class
        ques.class = u16::from_be_bytes(raw[domain_length + 2..domain_length + 4].try_into()?);
        // length
        ques.length = domain_length + 4;

        return Ok(ques);
    }

    pub fn names(&self) -> &Vec<String> {
        return &self.names;
    }

    pub fn length(&self) -> usize {
        return self.length;
    }

    pub fn typ(&self) -> u16 {
        return self.typ;
    }

    pub fn class(&self) -> u16 {
        return self.class;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        // encode domain names
        for name in &self.names {
            result.push(name.len() as u8);
            for v in name.as_bytes() {
                result.push(*v);
            }
        }
        result.push(b'\x00');

        // encode typ
        for v in self.typ.to_be_bytes() {
            result.push(v);
        }
        // encode class
        for v in self.class.to_be_bytes() {
            result.push(v);
        }

        return result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_question_new() {
        // correct
        let mut ques = Question::new(&mut vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // type & class
            0x11, 0x22, 0x33, 0x44,
        ]);
        assert_eq!(true, ques.as_ref().is_ok());
        assert_eq!(2, ques.as_ref().unwrap().names().len());
        assert_eq!(16, ques.as_ref().unwrap().length());
        assert_eq!("google", ques.as_ref().unwrap().names().get(0).unwrap());
        assert_eq!("com", ques.as_ref().unwrap().names().get(1).unwrap());

        // incorrect
        let mut raw = vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // type & class
            0x11, 0x22, 0x33,
        ];
        while raw.len() != 0 {
            ques = Question::new(&mut raw);
            assert_eq!(true, ques.is_err());
            raw.pop();
        }
    }

    #[test]
    pub fn test_question_encode() {
        // correct
        let ques = Question {
            length: 16,
            names: vec!["google".to_string(), "com".to_string()],
            typ: 4386,
            class: 13124,
        };

        let raw1: Vec<u8> = vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // type & class
            0x11, 0x22, 0x33, 0x44,
        ];

        let raw2: Vec<u8> = vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // type & class
            0x11, 0x22, 0x33, 0x43,
        ];

        assert_eq!(raw1, ques.encode());
        assert_ne!(raw2, ques.encode());
    }
}
