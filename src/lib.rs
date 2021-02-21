use rustable::gatt::{AttValue, LocalChar, ValOrFn};
use rustable::{Error as BLEError, MAX_APP_MTU};
use sha2::{Digest, Sha256};

use std::convert::TryInto;
use std::rc::Rc;

const MIN_NOTIFY_LEN: usize = 64;
const MAX_OPT_CHAR_LEN: usize = 495;

pub struct Clip {
    mime: String,
    hash: [u8; 32],
    data: Vec<u8>,
}
impl std::fmt::Debug for Clip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clip")
            .field("mime", &self.mime)
            .field("hash", &self.hash)
            .field("data.len()", &self.len())
            .finish()
    }
}

impl Clip {
    pub fn new(data: Vec<u8>, mime: String) -> Self {
        let hash = Sha256::digest(&data).into();
        Self { hash, data, mime }
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
    pub fn mime(&self) -> &str {
        &self.mime
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
}
impl Default for Clip {
    fn default() -> Self {
        Self::new(Vec::new(), "text/plain;charset=utf-8".to_owned())
    }
}
impl PartialEq<Clip> for Clip {
    fn eq(&self, other: &Clip) -> bool {
        if self.mime != other.mime {
            return false;
        }
        if self.data.len() != other.data.len() {
            return false;
        }
        self.hash == other.hash
    }
}

fn optimal_mtu_downgrade(mtu: usize) -> usize {
    if mtu >= 495 {
        495
    } else if mtu >= 244 {
        244
    } else if mtu >= 169 {
        169
    } else if mtu >= 123 {
        123
    } else {
        mtu
    }
}

pub struct OutSyncer {
    clip: Rc<Clip>,
    cur_pos: u32,
    written: u32,
    verbose: u8,
    notify_len: usize,
    bad_streak: bool,
}

impl OutSyncer {
    pub fn new(clip: Rc<Clip>, verbose: u8) -> Self {
        OutSyncer {
            clip,
            cur_pos: std::u32::MAX,
            written: 0,
            verbose,
            notify_len: MIN_NOTIFY_LEN,
            bad_streak: false,
        }
    }
    pub fn get_buf(&self) -> &[u8] {
        &self.clip.data()
    }
    pub fn get_clip(&self) -> &Clip {
        &self.clip
    }
    fn increment_notify_len(&mut self) -> usize {
        self.notify_len += 1;
        self.notify_len
    }
    pub fn notify_len(&self) -> usize {
        self.notify_len
    }
    fn reduce_notify_len(&mut self) -> Option<(usize, usize)> {
        if self.clip.len() as u32 == self.cur_pos || self.cur_pos == std::u32::MAX {
            let old_len = self.notify_len;
            self.notify_len = (self.notify_len * 3 / 4).max(MIN_NOTIFY_LEN);
            Some((old_len, self.notify_len))
        } else {
            None
        }
    }
    pub fn indicate_local(&mut self, local_char: &mut LocalChar) -> Result<(), BLEError> {
        if self.clip.len() as u32 == self.cur_pos {
            return Ok(());
        }
        if self.cur_pos == std::u32::MAX {
            let v = self.generate_char(self.cur_pos, MAX_OPT_CHAR_LEN);
            let ret = local_char.notify(Some(&mut ValOrFn::Value(v)));
            return ret;
        }
        let nl = optimal_mtu_downgrade(self.notify_len);
        let pload_len = nl - 4;
        let max_out = pload_len * 6;
        let target = self.clip.len().min(self.cur_pos as usize + max_out);

        // we only want to send full messages
        //let mut num_msg_to_send = (target - self.written as usize) / pload_len;
        let diff = target - self.written as usize;
        let num_msg_to_send = if diff % pload_len == 0 || target != self.clip.len() {
            diff / pload_len
        } else {
            diff / pload_len + 1
        };
        for _ in 0..num_msg_to_send {
            let v = self.generate_char(self.written, nl);
            let len = v.len() - 4;
            debug_assert!(len > 0);
            if self.verbose >= 2 {
                eprintln!("Indicating at position {}.", self.written);
            }
            if let Err(e) = local_char.notify(Some(&mut ValOrFn::Value(v))) {
                return Err(e);
            }
            self.written += len as u32;
        }
        Ok(())
    }
    fn generate_char(&self, loc: u32, max_len: usize) -> AttValue {
        let mut v = AttValue::default();
        v.extend_from_slice(&loc.to_be_bytes());
        if loc == std::u32::MAX {
            v.extend_from_slice(&self.clip.hash());
            v.extend_from_slice(&(self.clip.len() as u32).to_be_bytes());
            v.extend_from_slice(self.clip.mime().as_bytes());
        } else {
            let end = self.clip.len().min(loc as usize + max_len - 4);
            v.extend_from_slice(&self.get_buf()[loc as usize..end]);
        }
        v
    }
    pub fn read_fn(&mut self) -> AttValue {
        /* In theory the MAX_CHAR_LEN should work but android will only accept charactertiscs of len
          MAX_CHAR_LEN - 1. Not sure if this is a bug or the standard.
        */
        self.reduce_notify_len();
        self.generate_char(self.cur_pos, MAX_OPT_CHAR_LEN)
    }
    /*
    pub fn read_loc(&self) -> AttValue {
        if self.cur_pos == std::u32::MAX {
            AttValue::from(&[255, 255, 255, 255][..])
        } else {
            AttValue::from(&self.cur_pos.to_be_bytes()[..])
        }
    }
    */
    pub fn read_mime(&self) -> AttValue {
        AttValue::from(self.clip.mime().as_bytes())
    }
    pub fn read_len(&self) -> AttValue {
        let bytes = (self.clip.len() as u32).to_be_bytes();
        AttValue::from(&bytes[..])
    }
    pub fn read_hash(&self) -> AttValue {
        AttValue::from(&self.clip.hash()[..])
    }
    /// If this function returns `true` it indicates there is still data to be written to the client.
    pub fn update_pos(&mut self, data: &[u8]) {
        let mut int_buf = [0; 4];
        int_buf.copy_from_slice(&data[..4]);
        let cur_pos = u32::from_be_bytes(int_buf);
        if self.cur_pos == std::u32::MAX && cur_pos as usize <= self.clip.len() {
            if data.len() != 36 {
                return;
            }
            if &data[4..36] != self.clip.hash() {
                return;
            }
            self.cur_pos = cur_pos;
            self.written = cur_pos;
            return;
        }
        if cur_pos as usize > self.clip.len() {
            self.cur_pos = std::u32::MAX;
        } else {
            // self.dirty = cur_pos as usize != self.buf.len();
            self.cur_pos = if cur_pos == std::u32::MAX
                || (data.len() == 36 && &data[4..36] != self.clip.hash())
            {
                // Client in waiting for new message or bad hash received
                std::u32::MAX
            } else {
                if cur_pos <= self.cur_pos {
                    // a duplicate ACK was received
                    self.written = cur_pos;
                    if !self.bad_streak {
                        // if the first of a series of notifications fails,
                        // only reduce_notify_len on the first failure.
                        self.reduce_notify_len();
                        self.bad_streak = true;
                    }
                } else if cur_pos > self.written {
                    // In the event of a long read cur_pos could jump self.written
                    // so we account for that.
                    self.written = cur_pos;
                } else {
                    self.bad_streak = false;
                    self.increment_notify_len();
                }
                cur_pos
            };
        }
    }
}

enum BufOrDone {
    Buf(Vec<u8>),
    Done,
}
impl BufOrDone {
    fn reserve(&mut self, size: u32) {
        match self {
            BufOrDone::Buf(b) => b.reserve(size as usize),
            BufOrDone::Done => *self = BufOrDone::Buf(Vec::with_capacity(size as usize)),
        }
    }
    fn reserve_and_clear(&mut self, size: u32) {
        self.reserve(size);
        if let BufOrDone::Buf(b) = self {
            b.clear();
        }
    }
    fn take(&mut self) -> Option<Vec<u8>> {
        let bod = std::mem::replace(self, BufOrDone::Done);
        match bod {
            BufOrDone::Buf(b) => Some(b),
            BufOrDone::Done => None,
        }
    }
}

pub struct InSyncer {
    local_clip: Rc<Clip>,
    hash: [u8; 32],
    msg_length: u32,
    data_buf: BufOrDone,
    mime: String,
}

impl Default for InSyncer {
    fn default() -> Self {
        Self {
            local_clip: Rc::new(Clip::default()),
            msg_length: std::u32::MAX,
            hash: [0; 32],
            data_buf: BufOrDone::Buf(Vec::new()),
            mime: String::new(),
        }
    }
}

impl InSyncer {
    pub fn new(local_clip: Rc<Clip>) -> Self {
        Self {
            local_clip,
            ..Default::default()
        }
    }
    fn recvd(&self) -> u32 {
        match &self.data_buf {
            BufOrDone::Buf(b) => b.len() as u32,
            BufOrDone::Done => self.msg_length,
        }
    }
    fn generate_char(&self, include_hash: bool) -> AttValue {
        let mut ret = AttValue::default();
        ret.extend_from_slice(&self.recvd().to_be_bytes()[..]);
        if include_hash {
            ret.extend_from_slice(&self.hash);
        }
        ret
    }
    pub fn update_with_local(&mut self, local_clip: Rc<Clip>) {
        self.local_clip = local_clip;
    }
    fn should_receive(&self) -> bool {
        self.msg_length as usize != self.local_clip.len()
            || self.hash != self.local_clip.hash
            || self.mime != self.local_clip.mime
    }
    pub fn process_write(&mut self, v: &[u8]) -> (Option<Rc<Clip>>, AttValue) {
        if v.len() < 4 {
            return (None, self.generate_char(true));
        }
        let mut int_buf = [0; 4];
        int_buf.copy_from_slice(&v[..4]);
        let off = u32::from_be_bytes(int_buf);
        if off == std::u32::MAX {
            if v.len() < 40 {
                return (None, self.generate_char(true));
            }
            // determine if were we are in receiving this
            let hash = &v[4..36];
            int_buf.copy_from_slice(&v[36..40]);
            let msg_length = u32::from_be_bytes(int_buf);
            let mime_bytes = &v[40..];
            if self.hash != hash
                || self.msg_length != msg_length
                || self.mime.as_bytes() != mime_bytes
            {
                self.mime.clear();
                let mime_str = match std::str::from_utf8(&v[40..]) {
                    Ok(s) => s,
                    Err(_) => {
                        self.msg_length = std::u32::MAX;
                        return (None, self.generate_char(true));
                    }
                };
                self.mime.push_str(mime_str);
                self.hash.copy_from_slice(hash);
                self.msg_length = msg_length;
                if self.should_receive() {
                    self.data_buf.reserve_and_clear(msg_length);
                } else {
                    self.data_buf = BufOrDone::Done;
                }
            }
            (None, self.generate_char(true))
        } else if off <= self.recvd() {
            let ret = match &mut self.data_buf {
                BufOrDone::Buf(data_buf) => {
                    let diff = data_buf.len() - off as usize;
                    let start = diff + 4;
                    let end = v
                        .len()
                        .min(start + (self.msg_length as usize - data_buf.len()));
                    if start < v.len() {
                        for byte in &v[start..end] {
                            data_buf.push(*byte);
                        }
                    }
                    if data_buf.len() == self.msg_length as usize {
                        let clip = Clip::new(self.data_buf.take().unwrap(), self.mime.clone());
                        if clip.hash() == self.hash {
                            let clip = Rc::new(clip);
                            self.local_clip = clip.clone();
                            Some(clip)
                        } else {
                            let mut buf = clip.data;
                            buf.clear();
                            self.data_buf = BufOrDone::Buf(buf);
                            self.msg_length = std::u32::MAX;
                            None
                        }
                    } else {
                        None
                    }
                }
                BufOrDone::Done => None,
            };
            (ret, self.generate_char(false))
        } else {
            (None, self.generate_char(true))
        }
    }
}
