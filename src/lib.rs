
use rustable::{Error as BLEError, MAX_APP_MTU};
use rustable::gatt::{LocalChar, AttValue, ValOrFn};
use sha2::{Digest, Sha256};

pub struct OutSyncer {
    buf: Vec<u8>,
    cur_pos: usize,
    written: usize,
    hash: [u8; 32],
    verbose: u8,
}

impl OutSyncer {
    pub fn new(buf: Vec<u8>, verbose: u8) -> Self {
        let hash: [u8; 32] = Sha256::digest(&buf).into();
        OutSyncer {
            hash,
            buf,
            cur_pos: std::usize::MAX,
            written: 0,
            verbose,
        }
    }
	pub fn get_buf(&self) -> &[u8] {
		&self.buf
	}
    pub fn indicate_local(
        &mut self,
        local_char: &mut LocalChar,
        max_out: usize,
    ) -> Result<(), BLEError> {
        if self.buf.len() == self.cur_pos {
            return Ok(());
        }
        let mut vf = ValOrFn::Value(AttValue::default());
        local_char.write_val_or_fn(&mut vf); // remove the vf function so we can write custom data
        if self.cur_pos == std::usize::MAX {
            // we need to write the initial data to tell the GATT client how long what we are copying is
            let mut v = AttValue::default();
            v.extend_from_slice(&std::u32::MAX.to_be_bytes());
            v.extend_from_slice(&(self.buf.len() as u32).to_be_bytes());
            v.extend_from_slice(&self.hash);
            local_char.write_val_or_fn(&mut ValOrFn::Value(v));
            if let Err(e) = local_char.notify() {
                local_char.write_val_or_fn(&mut vf);
                return Err(e);
            }
            self.written = 0;
            local_char.write_val_or_fn(&mut vf); // return read function
            return Ok(());
        }
        let target = self.buf.len().min(self.cur_pos + max_out);
        while self.written < target {
            let end = target.min(self.written + MAX_APP_MTU - 8);
            let mut v = AttValue::default();
            let l = end - self.written;
            v.extend_from_slice(&self.written.to_be_bytes()[4..8]);
            v.extend_from_slice(&l.to_be_bytes()[4..8]);
            v.extend_from_slice(&self.buf[self.written..end]);
            local_char.write_val_or_fn(&mut ValOrFn::Value(v));
            if self.verbose > 0 {
                eprintln!("Indicating at position {}.", self.written);
            }
            if let Err(e) = local_char.notify() {
                local_char.write_val_or_fn(&mut vf);
                return Err(e);
            }
            self.written = end;
        }
        local_char.write_val_or_fn(&mut vf);
        Ok(())
    }
    pub fn read_fn(&self) -> AttValue {
        if self.cur_pos == std::usize::MAX {
            let mut v = AttValue::default();
            v.extend_from_slice(&std::u32::MAX.to_be_bytes());
            v.extend_from_slice(&(self.buf.len() as u32).to_be_bytes());
            v.extend_from_slice(&self.hash);
            v
        } else {
            let end = self.buf.len().min(self.cur_pos + 256 - 8);
            let mut v = AttValue::default();
            // let l = end - self.cur_pos;
            let l = match end.checked_sub(self.cur_pos) {
                Some(v) => v,
                None => panic!("overflowed end - self.cur_pos: {} - {}", end, self.cur_pos),
            };
            v.extend_from_slice(&(self.cur_pos as u32).to_be_bytes());
            v.extend_from_slice(&(l as u32).to_be_bytes());
            v.extend_from_slice(&self.buf[self.cur_pos..end]);
            v
        }
    }
    /// If this function returns `true` it indicates there is still data to be written to the client.
    pub fn update_pos(&mut self, data: &[u8]) {
        let mut int_buf = [0; 4];
        int_buf.copy_from_slice(&data[..4]);
        let cur_pos = u32::from_be_bytes(int_buf);
        int_buf.copy_from_slice(&data[4..8]);
        let msg_length = u32::from_be_bytes(int_buf) as usize;
        let mut hash = [0; 32];
        hash.copy_from_slice(&data[8..40]);
        if msg_length != self.buf.len() || hash != self.hash || cur_pos as usize > self.buf.len() {
            // handle hash or msg_length mismatch
            self.cur_pos = std::usize::MAX;
        } else {
            // self.dirty = cur_pos as usize != self.buf.len();
            self.cur_pos = if cur_pos == std::u32::MAX {
                // we have no received
                std::usize::MAX
            } else {
                let cur_pos = cur_pos as usize;
                if cur_pos <= self.cur_pos {
                    // a duplicate ACK was received
                    self.written = cur_pos
                }
                cur_pos
            };
        }
    }
}



#[derive(Default)]
pub struct InSyncer {
    hash: [u8; 32],
    msg_length: usize,
    data_buf: Vec<u8>,
}
impl InSyncer {
    pub fn read_fn(&self) -> AttValue {
        let mut ret = AttValue::default();
        ret.extend_from_slice(&self.data_buf.len().to_be_bytes()[4..8]);
        ret.extend_from_slice(&self.msg_length.to_be_bytes()[4..8]);
        ret.extend_from_slice(&self.hash);
        return ret;
    }
    pub fn process_write(&mut self, v: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        let s: &Self = self;
        if v.len() < 8 {
            return Err(());
        }
        let mut int_buf = [0; 4];
        int_buf.copy_from_slice(&v[..4]);
        let p_num = u32::from_be_bytes(int_buf);
        int_buf.copy_from_slice(&v[4..8]);
        let p_len = u32::from_be_bytes(int_buf) as usize;
        if p_num == std::u32::MAX {
            if v.len() != 40 {
                let s: &Self = self;
                return Err(());
            }
            self.data_buf.clear();
            self.msg_length = p_len;
            self.hash.copy_from_slice(&v[8..])
        } else {
            if p_len + 8 != v.len() {
                return Err(());
            }
            if self.data_buf.len() + p_len > self.msg_length {
                return Err(());
            }
            self.data_buf.extend_from_slice(&v[8..]);
        }
        if self.data_buf.len() == self.msg_length {
            let res = Sha256::digest(&self.data_buf);
            if res.as_slice() == self.hash {
                Ok(Some(self.data_buf.clone()))
            } else {
                self.data_buf.clear();
                Err(())
            }
        } else {
            Ok(None)
        }
    }
}
