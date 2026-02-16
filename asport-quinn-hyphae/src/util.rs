use std::collections::VecDeque;

use quinn_proto::{VarInt, coding::Codec as _};

#[derive(Debug)]
pub struct InvalidHandshakeMessage;

#[derive(Default)]
pub struct HandshakeMessageFramer {
    message_in_progress: Option<(usize, Vec<u8>)>,
    messages_ready: VecDeque<Vec<u8>>,
}

impl HandshakeMessageFramer {
    pub const MESSAGE_LEN_MAX: usize = u16::MAX as usize;
    pub const MESSAGE_READY_MAX: usize = 8;

    pub fn injest_bytes(&mut self, mut buffer: &[u8]) -> Result<bool, InvalidHandshakeMessage> {
        while !buffer.is_empty() {
            match &mut self.message_in_progress {
                None => {
                    let next_message_len: u64 = VarInt::decode(&mut buffer)
                        .map_err(|_| InvalidHandshakeMessage)?.into();
                    if next_message_len > Self::MESSAGE_LEN_MAX as u64 || self.messages_ready.len() > Self::MESSAGE_READY_MAX {
                        return Err(InvalidHandshakeMessage);
                    }
                    if next_message_len == 0 {
                        self.messages_ready.push_back(Vec::new());
                    } else {
                        let next_message_len = next_message_len as usize;
                        self.message_in_progress = Some((next_message_len, Vec::with_capacity(next_message_len)));
                    }
                },

                Some((bytes_remaining, message)) => {
                    let take_amt = (*bytes_remaining).min(buffer.len());
                    let (take, rem) = buffer.split_at(take_amt);
                    message.extend_from_slice(take);
                    *bytes_remaining -= take_amt;
                    if *bytes_remaining == 0 {
                        self.messages_ready.push_back(self.message_in_progress.take().unwrap().1)
                    }
                    buffer = rem;
                },
            }
        }

        Ok(self.ready())
    }

    pub fn ready(&self) -> bool {
        !self.messages_ready.is_empty()
    }

    pub fn next(&mut self) -> Option<Vec<u8>> {
        self.messages_ready.pop_front()
    }

    pub fn write_frame(buffer: &mut Vec<u8>, message: &[u8]) -> Result<(), InvalidHandshakeMessage> {
        if message.len() > Self::MESSAGE_LEN_MAX {
            return Err(InvalidHandshakeMessage);
        }
        let len_var = VarInt::try_from(message.len())
            .map_err(|_| InvalidHandshakeMessage)?;
        len_var.encode(buffer);
        buffer.extend_from_slice(message);
        Ok(())
    }
}

