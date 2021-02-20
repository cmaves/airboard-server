use clap::{Arg, App};
use rustable::gatt::{CharFlags, LocalCharBase, LocalServiceBase, DescFlags, LocalDescBase, HasChildren,ValOrFn};
use rustable::{AdType, Advertisement, Bluetooth, Error as BLEError, MAX_APP_MTU, UUID, ToUUID};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::cell::RefCell;
use std::borrow::Borrow;
use std::io::{Read,Write};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::thread::sleep;
use std::time::{Duration, Instant};
use airboard_server::{InSyncer, OutSyncer, Clip};
// use wl_clipboard_rs::paste::Error as PasteError;

const COPY_UUID: &'static str = "4981333e-2d59-43b2-8dc3-8fedee1472c5";
const READ_UUID: &'static str = "07178017-1879-451b-9bb5-3ff13bb85b70";
const WRITE_UUID: &'static str = "07178017-1879-451b-9bb5-3ff13bb85b71";

const VER_UUID: &'static str = "b05778f1-5a88-46a3-b6c8-2d154d629910";
const LEN_UUID: &'static str = "b05778f1-5a88-46a3-b6c8-2d154d629911";
const MIME_UUID: &'static str = "b05778f1-5a88-46a3-b6c8-2d154d629912";
const HASH_UUID: &'static str = "b05778f1-5a88-46a3-b6c8-2d154d629913";
//const LOC_UUID: &'static str = "b05778f1-5a88-46a3-b6c8-2d154d629912";

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn update_clipboard(clip: &Clip) -> Result<(), std::io::Error> {
    let proc = Command::new("wl-copy")
        .arg("-t")
        .arg(clip.mime())
        .stdin(Stdio::piped()).spawn()?;
    proc.stdin.unwrap().write(clip.data()).map(|_| ())
}
fn resolve_mime_type(mut mimes: HashSet<String>) -> Option<String> {
    if let Some(s) = mimes.take("text/plain;charset=utf-8") {
        return Some(s);
    }
    let mut mimes: Vec<String> = mimes.into_iter().collect();
    mimes.sort_unstable();
    
    let mut start = binary_search(&mimes[..], "image/").unwrap_err();
    while start < mimes.len() && mimes[start].starts_with("image/") {
        let second = &mimes[start][6..];
        match second {
            "png" | "jpeg" => return Some(mimes.remove(start)),
            _ => ()
        }
        start += 1;
    }
    let mut start = binary_search(&mimes[..], "text/").unwrap_err();
    while start < mimes.len() && mimes[start].starts_with("text/") {
        let second = &mimes[start][5..];
        match second {
            "html" => return Some(mimes.remove(start)),
            _ => ()
        }
        start += 1;
    }
    return None 
}
fn binary_search<T, K>(list: &[T], k: &K) -> Result<usize, usize> 
    where
        T: Borrow<K>,
        K: Ord + ?Sized
{
    list.binary_search_by(|p| p.borrow().cmp(k))
}
fn get_clipboard() -> std::io::Result<Rc<Clip>> {

    loop {
        let mime_bytes = Command::new("wl-paste")
            .arg("-l")
            .output()?;
        // let mimes = get_mime_types(ClipboardType::Regular, Seat::Unspecified)?;
        let mimes: HashSet<String> = std::str::from_utf8(&mime_bytes.stdout)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            .lines().map(|s| s.to_owned()).collect();

        let mime = resolve_mime_type(mimes)
                        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let out = match Command::new("wl-paste")
            .arg("-n")
            .arg("-t")
            .arg(&mime)
            .output() 
        {
            Ok(out) => out.stdout,
            Err(_) => continue
        };
        return Ok(Rc::new(Clip::new(out, mime)));

        /*
        let (mut out, _) = match get_contents(ClipboardType::Regular, Seat::Unspecified, MimeType::Specific(&mime))        {
            Ok(o) => o,
            Err(PasteError::NoMimeType) => continue,
            Err(e) => return Err(e)
        };
        let mut ret = vec![];
        out.read_to_end(&mut ret).map_err(|e| PasteError::WaylandCommunication(e))?;
        */
    }
    /*
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
    */
}
static mut VERBOSE: u8 = 0;
fn set_verbose(level: u8) {
    unsafe {
        VERBOSE = level;
    }
}
fn verbose() -> u8 {
    unsafe {
        VERBOSE
    }
}

fn main() {
	let parser = parser();
	let args = parser.get_matches();
	let name = match args.value_of("hostname") {
		Some(n) => n.to_string(),
		None => {
			let res = Command::new("hostname").output().expect("Failed to get device hostname!");
			let mut n = String::from_utf8(res.stdout).expect("Invalid hostname received!");
			n.pop();
			n
		}
	};
    let mut blue = Bluetooth::new("io.maves.airboard".to_string(), "/org/bluez/hci0".to_string()).unwrap();
    let verbose = args.occurrences_of("verbose") as u8;
    set_verbose(verbose);
	blue.verbose = verbose;
	if args.is_present("no-filter") {
		blue.set_filter(None).unwrap();
	}
    let serv_uuid = COPY_UUID.to_uuid();
    let mut copy_service = LocalServiceBase::new(&serv_uuid, true);

    let cur_clip = match get_clipboard() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to read clipboard: {:?}", e);
            Rc::new(Clip::default())
        }
    };

    let in_syncer = Rc::new(RefCell::new(InSyncer::new(cur_clip.clone())));
    let out_syncer = Rc::new(RefCell::new(OutSyncer::new(cur_clip, verbose)));

    /*
       The read and write services are from the prespective of the client. So
       for this program we read the write_char for updates from the client (typically a phone)
       and write to the read_char for updates to the client from this device.
    */
    let mut read_flags = CharFlags::default();
    // perimissions
    read_flags.secure_read = true;
    read_flags.encrypt_read = true;
    read_flags.notify = true;
    read_flags.indicate = true;
    read_flags.encrypt_write = true;
    read_flags.write_wo_response = true;
    // create read characteristic
    let read_uuid = READ_UUID.to_uuid();
    let mut read_char = LocalCharBase::new(&read_uuid, read_flags);
    // neable the write fd and setup the write callback
    read_char.enable_write_fd(true);

    let os_clone = out_syncer.clone();
    read_char.write_callback = Some(Box::new(move |data| {
        if verbose >= 2 {
            eprintln!("read_char.write_callback(): Read characteristic written to with: {:?}", data);
        }
        if data.len() != 4 && data.len() != 36 {
            return Err((
                "org.bluez.DBus.Failed".to_string(),
                Some("Data was not 4 or 36 bytes long".to_string()),
            ));
        }
        os_clone.borrow_mut().update_pos(data);
        Ok((None, false))
    }));

    let os_clone = out_syncer.clone();
    read_char.write_val_or_fn(&mut ValOrFn::Function(Box::new(move || {
        if verbose > 2 {
            eprintln!("Read characteristic read.");
        }
        os_clone.borrow_mut().read_fn()
    })));

	// create protocol version descriptor
	let mut ver_flags = DescFlags::default();
	ver_flags.read = true;
	ver_flags.encrypt_read = true;
	ver_flags.secure_read = true;
	let ver_uuid = VER_UUID.to_uuid();
	let mut ver_desc = LocalDescBase::new(&ver_uuid, ver_flags);
	ver_desc.vf = ValOrFn::Value([1_u8, 0][..].into());

    /*
    let mut loc_desc = LocalDescBase::new(LOC_UUID, ver_flags);
    let os_clone = out_syncer.clone();
    loc_desc.vf = ValOrFn::Function(Box::new(move || {
        os_clone.borrow().read_loc()
    }));
    */

    let mut len_desc = LocalDescBase::new(LEN_UUID, ver_flags);
    let os_clone = out_syncer.clone();
    len_desc.vf = ValOrFn::Function(Box::new(move || {
        RefCell::borrow(&os_clone).read_len()
    }));

    let mut mime_desc = LocalDescBase::new(MIME_UUID, ver_flags);
    let os_clone = out_syncer.clone();
    mime_desc.vf = ValOrFn::Function(Box::new(move || {
        RefCell::borrow(&os_clone).read_mime()
    }));

    let mut mime_desc = LocalDescBase::new(MIME_UUID, ver_flags);
    let os_clone = out_syncer.clone();
    mime_desc.vf = ValOrFn::Function(Box::new(move || {
        RefCell::borrow(&os_clone).read_mime()
    }));

    let mut hash_desc = LocalDescBase::new(HASH_UUID, ver_flags);
    let os_clone = out_syncer.clone();
    hash_desc.vf = ValOrFn::Function(Box::new(move || {
        RefCell::borrow(&os_clone).read_hash()
    }));

	read_char.add_desc(ver_desc);
    //read_char.add_desc(loc_desc);
    read_char.add_desc(len_desc);
    read_char.add_desc(mime_desc);
    read_char.add_desc(hash_desc);


    copy_service.add_char(read_char);
    //permissions
    let write_uuid = WRITE_UUID.to_uuid();
    let mut write_flags = CharFlags::default();
    write_flags.secure_write = true;
    write_flags.encrypt_write = true;
    write_flags.write_wo_response = true;
    write_flags.encrypt_read = true;
    write_flags.notify = true;
    write_flags.indicate = true;
    let mut write_char = LocalCharBase::new(&write_uuid, write_flags);
    // setup write call back
    write_char.enable_write_fd(true);
    //let last_written = Rc::new(RefCell::new(Clip::default()));
    //let lw_clone = last_written.clone();
    // let (v, l) = syncer.read_fn();
    let os_clone = out_syncer.clone();
    let is_clone = in_syncer.clone();
    
    write_char.write_callback = Some(Box::new(move |bytes| {
        if verbose >= 2 {
            eprintln!("Received message: {:?}", bytes);
        }
        let (clip, val) = is_clone.borrow_mut().process_write(bytes);
        eprintln!("write_char.write_callback(): replying with: {:?}", val);
        if let Some(clip) = clip {
            update_clipboard(&clip).ok();
            //lw_clone.replace(clip);
            os_clone.replace(OutSyncer::new(clip, verbose));
        }
        Ok((Some(ValOrFn::Value(val)), true))
    }));

	let mut ver_desc = LocalDescBase::new(&ver_uuid, ver_flags);
	ver_desc.vf = ValOrFn::Value([0, 0][..].into());
	write_char.add_desc(ver_desc);
    copy_service.add_char(write_char);
    /*
    let mut write_serv = copy_service.get_char(&write_uuid);
    write_serv.write_val_or_fn(&mut ValOrFn::Value(v, l));*/

    blue.add_service(copy_service).unwrap();
    /*loop {
        blue.process_requests().unwrap();
    }*/
    blue.register_application().unwrap();

    let mut adv = Advertisement::new(AdType::Peripheral, name);
    adv.duration = 2;
    adv.timeout = std::u16::MAX;
    adv.service_uuids.push(serv_uuid.clone());
    blue.set_power(true)
        .expect("Failed to power on bluetooth controller!");
    blue.set_discoverable(true)
        .expect("Failed to make device discoverable!");
    let adv_idx = match blue.start_adv(adv) {
        Ok(idx) => idx,
        Err((idx, _)) => {
            eprintln!("Warning: failed to start advertisement");
            idx
        }
    };

    let mut target = Instant::now();
    loop {
        // check for writes to local clipboard from GATT client
        let now = Instant::now();
        blue.process_requests().unwrap();
        let mut serv = blue.get_service(&serv_uuid).unwrap();
        let mut write_char = serv.get_child(&write_uuid).unwrap();
        write_char.check_write_fd();

        // check for the read characteristic
        let mut read_char = serv.get_child(&read_uuid).unwrap();
        read_char.check_write_fd();
        let mut os_bor = out_syncer.borrow_mut();
        if let Err(e) = os_bor.indicate_local(&mut read_char) 
        {
            eprintln!("Error indicating: {:?}", e);
        }
        drop(os_bor);

        // check for local updates to clipboard;
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
            if RefCell::borrow(&out_syncer).get_clip() != &*new_clip {
                println!("Writing: {:?}", new_clip);
                in_syncer.borrow_mut().update_with_local(new_clip.clone());
                out_syncer.replace(OutSyncer::new(new_clip, verbose));
            }
            match blue.restart_adv(adv_idx) {
                Ok(v) => {
                    if v {
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

fn parser<'a, 'b>() -> App<'a, 'b> {
	App::new("Airboard Server")
		.version(VERSION)
		.author("Curtis Maves <curtis@maves.io>")
		.arg(
			Arg::with_name("verbose")
				.short("v")
				.long("verbose")
				.multiple(true)
		)
		.arg(
			Arg::with_name("no-filter")
				.short("n")
				.long("nofilter")
				.help("Allows all incoming Dbus messages.")
		)
		.arg(
			Arg::with_name("hostname")
				.short("h")
				.long("hostname")
				.value_name("NAME")
				.takes_value(true)
		)
}
