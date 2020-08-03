use rustable::gatt::{CharFlags, LocalCharBase, LocalCharactersitic, LocalServiceBase, Service};
use rustable::{AdType, Advertisement, Bluetooth, Error as BLEError, ValOrFn, MAX_APP_MTU, UUID};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::Write;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::thread::sleep;
use std::time::{Duration, Instant};

const COPY_UUID: &'static str = "4981333e-2d59-43b2-8dc3-8fedee1472c5";
const READ_UUID: &'static str = "07178017-1879-451b-9bb5-3ff13bb85b70";
const WRITE_UUID: &'static str = "07178017-1879-451b-9bb5-3ff13bb85b71";

fn update_clipboard(buf: &[u8]) -> Result<(), std::io::Error> {
    let proc = Command::new("wl-copy").stdin(Stdio::piped()).spawn()?;
    proc.stdin.unwrap().write(buf).map(|_| ())
}
fn get_clipboard() -> Result<Vec<u8>, std::io::Error> {
    let out = Command::new("wl-paste")
        .arg("-n")
        .arg("-t")
        .arg("text")
        .output()?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Non-zero return",
        ))
    }
}

fn main() {
    let name = Command::new("hostname")
        .output()
        .expect("Failed to get device hostname");
    let mut name = String::from_utf8(name.stdout).expect("Invalid hostname received.");
    name.pop();
    let mut blue = Bluetooth::new("ecp", "/org/bluez/hci0".to_string()).unwrap();
    let verbose = 1;
    blue.filter_dest = None;

    let serv_uuid = Rc::from(COPY_UUID.to_string());
    let mut copy_service = LocalServiceBase::new(&serv_uuid, true);

    let cur_clip = match get_clipboard() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to read clipboard: {:?}", e);
            Vec::new()
        }
    };
    let out_syncer = Rc::new(RefCell::new(OutSyncer::new(cur_clip, verbose)));

    /*
       The read and write services are from the prespective of the client. So
       for this program we read the write_char for updates from the client (typically a phone)
       and write to the read_char for updates to the client from this device.
    */
    let mut read_flags = CharFlags::default();
    // perimissions
    read_flags.secure_read = true;
    read_flags.read = true;
    read_flags.notify = true;
    read_flags.indicate = true;
    read_flags.write = true;
    read_flags.write_wo_response = true;
    // create read characteristic
    let read_uuid = Rc::from(READ_UUID.to_string());
    let mut read_char = LocalCharBase::new(&read_uuid, read_flags);
    // neable the write fd and setup the write callback
    read_char.enable_write_fd(true);
    let os_clone = out_syncer.clone();
    read_char.write_callback = Some(Box::new(move |data| {
        if data.len() != 40 {
            return Err((
                "org.bluez.DBus.Failed".to_string(),
                Some("Data was not 40 bytes long".to_string()),
            ));
        }
        os_clone.borrow_mut().update_pos(data);
        Ok((None, false))
    }));
    copy_service.add_char(read_char);
    //permissions
    let write_uuid = Rc::from(WRITE_UUID.to_string());
    let mut write_flags = CharFlags::default();
    write_flags.secure_write = true;
    write_flags.write = true;
    write_flags.write_wo_response = true;
    write_flags.read = true;
    write_flags.notify = true;
    write_flags.indicate = true;
    let mut write_char = LocalCharBase::new(&write_uuid, write_flags);
    // setup write call back
    write_char.enable_write_fd(true);
    let mut syncer = InSyncer::default();
    let last_written = Rc::new(RefCell::new(Vec::new()));
    let lw_clone = last_written.clone();
    // let (v, l) = syncer.read_fn();
    write_char.write_callback = Some(Box::new(move |bytes| {
        match syncer.process_write(bytes) {
            Ok(buf) => {
                if let Some(buf) = buf {
                    update_clipboard(&buf);
                    lw_clone.replace(buf);
                }
                false
            }
            Err(_) => true,
        };
        let (v, l) = syncer.read_fn();
        Ok((Some(ValOrFn::Value(v, l)), true))
    }));
    copy_service.add_char(write_char);
    /*
    let mut write_serv = copy_service.get_char(&write_uuid);
    write_serv.write_val_or_fn(&mut ValOrFn::Value(v, l));*/

    blue.add_service(copy_service).unwrap();
    blue.register_application().unwrap();

    let mut adv = Advertisement::new(AdType::Peripheral, name);
    adv.duration = 2;
    adv.timeout = std::u16::MAX;
    adv.service_uuids.push(serv_uuid.clone());
    blue.set_power(true)
        .expect("Failed to power on bluetooth controller!");
    blue.set_discoverable(true)
        .expect("Failed to make device discoverable!");
    let adv_idx = match blue.start_advertise(adv) {
        Ok(idx) => idx,
        Err((idx, _)) => {
            eprintln!("Warning: failed to start advertisement");
            idx
        }
    };
    let mut copy_serv = blue.get_service(&serv_uuid).unwrap();
    let mut read_char = copy_serv.get_char(&read_uuid).unwrap();
    let os_clone = out_syncer.clone();
    read_char.write_val_or_fn(&mut ValOrFn::Function(Box::new(move || {
        os_clone.borrow().read_fn()
    })));

    let mut target = Instant::now();
    loop {
        // check for writes to local clipboard from GATT client
        let now = Instant::now();
        blue.process_requests().unwrap();
        let mut serv = blue.get_service(&serv_uuid).unwrap();
        let mut write_char = serv.get_char(&write_uuid).unwrap();
        write_char.check_write_fd();

        // check for local updates to clipboard;
        let mut read_char = serv.get_char(&read_uuid).unwrap();
        read_char.check_write_fd();
        if let Err(e) = out_syncer
            .borrow_mut()
            .indicate_local(&mut read_char, MAX_APP_MTU * 32)
        {
            eprintln!("Error inidicating: {:?}", e);
        }
        if let None = target.checked_duration_since(now) {
            target = now + Duration::from_secs(2);
            let new_clip = match get_clipboard() {
                Ok(o) => o,
                Err(e) => {
                    if verbose > 0 {
                        eprintln!("Failed to read clipboard: {:?}", e);
                    }
                    continue;
                }
            };
            if out_syncer.borrow().buf != new_clip && *last_written.borrow() != new_clip {
                println!("Writing: {:?}", new_clip);
                out_syncer.replace(OutSyncer::new(new_clip, verbose));
            }
            match blue.restart_adv(adv_idx) {
                Ok(v) => {
                    if (v) {
                        if let Err(e) = blue.set_discoverable(true) {
                            eprintln!("Failed to set to discoverable: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    if verbose > 1 {
                        eprintln!("Failed to set to started advertisement: {:?}", e);
                    }
                }
            }
        }
        sleep((now + Duration::from_millis(200)).saturating_duration_since(Instant::now()));
    }
}

struct OutSyncer {
    buf: Vec<u8>,
    cur_pos: usize,
    written: usize,
    hash: [u8; 32],
    verbose: u8,
}

impl OutSyncer {
    fn new(buf: Vec<u8>, verbose: u8) -> Self {
        let hash: [u8; 32] = Sha256::digest(&buf).into();
        OutSyncer {
            hash,
            buf,
            cur_pos: std::usize::MAX,
            written: 0,
            verbose,
        }
    }
    fn indicate_local(
        &mut self,
        local_char: &mut LocalCharactersitic,
        max_out: usize,
    ) -> Result<(), BLEError> {
        if self.buf.len() == self.cur_pos {
            return Ok(());
        }
        let mut vf = ValOrFn::Value([0; 512], 0);
        local_char.write_val_or_fn(&mut vf); // remove the vf function so we can write custom data
        if self.cur_pos == std::usize::MAX {
            // we need to write the initial data to tell the GATT client how long what we are copying is
            let mut v = [0; 512];
            v[..4].copy_from_slice(&std::u32::MAX.to_be_bytes());
            v[4..8].copy_from_slice(&(self.buf.len() as u32).to_be_bytes());
            v[8..40].copy_from_slice(&self.hash);
            local_char.write_val_or_fn(&mut ValOrFn::Value(v, 40));
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
            let mut v = [0; 512];
            let l = end - self.written;
            v[0..4].copy_from_slice(&self.written.to_be_bytes()[4..8]);
            v[4..8].copy_from_slice(&l.to_be_bytes()[4..8]);
            v[8..l + 8].copy_from_slice(&self.buf[self.written..end]);
            local_char.write_val_or_fn(&mut ValOrFn::Value(v, l));
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
    fn read_fn(&self) -> ([u8; 512], usize) {
        if self.cur_pos == std::usize::MAX {
            let mut v = [0; 512];
            v[..4].copy_from_slice(&std::u32::MAX.to_be_bytes());
            v[4..8].copy_from_slice(&(self.buf.len() as u32).to_be_bytes());
            v[8..40].copy_from_slice(&self.hash);
            (v, 40)
        } else {
            let end = self.buf.len().min(self.cur_pos + 256 - 8);
            let mut v = [0; 512];
            // let l = end - self.cur_pos;
            let l = match end.checked_sub(self.cur_pos) {
                Some(v) => v,
                None => panic!("overflowed end - self.cur_pos: {} - {}", end, self.cur_pos),
            };
            v[0..4].copy_from_slice(&(self.cur_pos as u32).to_be_bytes());
            v[4..8].copy_from_slice(&(l as u32).to_be_bytes());
            v[8..l + 8].copy_from_slice(&self.buf[self.cur_pos..end]);
            (v, l + 8)
        }
    }
    /// If this function returns `true` it indicates there is still data to be written to the client.
    fn update_pos(&mut self, data: &[u8]) {
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
struct InSyncer {
    hash: [u8; 32],
    msg_length: usize,
    data_buf: Vec<u8>,
}
impl InSyncer {
    fn read_fn(&self) -> ([u8; 512], usize) {
        let mut ret = [0; 512];
        ret[0..4].copy_from_slice(&self.data_buf.len().to_be_bytes()[4..8]);
        ret[4..8].copy_from_slice(&self.msg_length.to_be_bytes()[4..8]);
        ret[8..40].copy_from_slice(&self.hash);
        return (ret, 40);
    }
    fn process_write(&mut self, v: &[u8]) -> Result<Option<Vec<u8>>, ()> {
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
