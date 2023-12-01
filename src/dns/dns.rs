use super::{answer::Answers, header::Header, question::Question};

pub struct DNS {
    raw: Vec<u8>,
    head: Header,
    ques: Question,
    answers: Answers,
}

impl DNS {
    pub fn from(raw: &[u8]) -> Self {
        Self {
            raw: raw.to_vec(),
            head: Header::new(raw[..12].try_into().expect("slice covert to array error")),
            ques: todo!(),
            answers: todo!(),
        }
    }

    pub fn head(&self) -> &Header {
        return &self.head;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        result.extend_from_slice(&self.head.get_0());
        result.extend_from_slice(&self.ques.encode());
        result.extend_from_slice(&self.answers.encode());

        return result;
    }
}
