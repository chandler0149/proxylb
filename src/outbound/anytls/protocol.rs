use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;

#[derive(Debug)]
pub struct Frame {
    pub cmd: u8,
    pub stream_id: u32,
    pub data: Bytes,
}

impl Frame {
    pub fn new(cmd: u8, stream_id: u32, data: Bytes) -> Self {
        Self {
            cmd,
            stream_id,
            data,
        }
    }
}

pub fn parse_frame(buf: &mut BytesMut) -> Option<Frame> {
    if buf.len() < 7 {
        return None;
    }
    let data_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    if buf.len() < 7 + data_len {
        return None;
    }

    let cmd = buf[0];
    let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    // Consume header
    buf.advance(7);
    // Extract data via zero-copy freeze
    let data = buf.split_to(data_len).freeze();

    Some(Frame {
        cmd,
        stream_id,
        data,
    })
}

pub fn encode_frame_header(cmd: u8, stream_id: u32, data_len: u16, buf: &mut BytesMut) {
    buf.reserve(7 + data_len as usize);
    buf.put_u8(cmd);
    buf.put_u32(stream_id);
    buf.put_u16(data_len);
}
