extern crate libc;
extern crate rand;

#[macro_use]
extern crate error_chain;

use rand::{Rng, SeedableRng, XorShiftRng};
use std::mem;
use std::slice;

mod area;
mod flash;
pub mod api;
mod pdump;

use flash::Flash;
use area::{AreaDesc, CAreaDesc, FlashId};

fn main() {
    let (mut flash, areadesc) = if false {
        // STM style flash.  Large sectors, with a large scratch area.
        let flash = Flash::new(vec![16 * 1024, 16 * 1024, 16 * 1024, 16 * 1024,
                               64 * 1024,
                               128 * 1024, 128 * 1024, 128 * 1024]);
        let mut areadesc = AreaDesc::new(&flash);
        areadesc.add_image(0x020000, 0x020000, FlashId::Image0);
        areadesc.add_image(0x040000, 0x020000, FlashId::Image1);
        areadesc.add_image(0x060000, 0x020000, FlashId::ImageScratch);
        (flash, areadesc)
    } else {
        // NXP style flash.  Small sectors, one small sector for scratch.
        let flash = Flash::new(vec![4096; 128]);

        let mut areadesc = AreaDesc::new(&flash);
        areadesc.add_image(0x020000, 0x020000, FlashId::Image0);
        areadesc.add_image(0x040000, 0x020000, FlashId::Image1);
        areadesc.add_image(0x060000, 0x001000, FlashId::ImageScratch);
        (flash, areadesc)
    };

    // println!("Areas: {:#?}", areadesc.get_c());

    // Install the boot trailer signature, so that the code will start an upgrade.
    let primary = install_image(&mut flash, 0x020000, 32779);

    // Install an upgrade image.
    let upgrade = install_image(&mut flash, 0x040000, 41922);

    // Mark the upgrade as ready to install.  (This looks like it might be a bug in the code,
    // however.)
    mark_upgrade(&mut flash, 0x060000 - 402);

    let (fl2, total_count) = try_upgrade(&flash, &areadesc, None);
    println!("First boot, count={}", total_count);
    assert!(verify_image(&fl2, 0x020000, &upgrade));

    let mut bad = 0;
    // Let's try an image halfway through.
    for i in 1 .. total_count {
        println!("Try interruption at {}", i);
        let (fl3, total_count) = try_upgrade(&flash, &areadesc, Some(i));
        println!("Second boot, count={}", total_count);
        if !verify_image(&fl3, 0x020000, &upgrade) {
            println!("FAIL");
            bad += 1;
        }
        if !verify_image(&fl3, 0x040000, &primary) {
            println!("Slot 1 FAIL");
            bad += 1;
        }
    }
    println!("{} out of {} failed {:.2}%",
             bad, total_count,
             bad as f32 * 100.0 / total_count as f32);

    println!("Try revert");
    let fl2 = try_revert(&flash, &areadesc);
    assert!(verify_image(&fl2, 0x020000, &primary));

    println!("Try norevert");
    let fl2 = try_norevert(&flash, &areadesc);
    assert!(verify_image(&fl2, 0x020000, &upgrade));

    /*
    // show_flash(&flash);

    println!("First boot for upgrade");
    // unsafe { flash_counter = 570 };
    boot_go(&mut flash, &areadesc);
    // println!("{} flash ops", unsafe { flash_counter });

    verify_image(&flash, 0x020000, &upgrade);

    println!("\n------------------\nSecond boot");
    boot_go(&mut flash, &areadesc);
    */
}

/// Test a boot, optionally stopping after 'n' flash options.  Returns a count of the number of
/// flash operations done total.
fn try_upgrade(flash: &Flash, areadesc: &AreaDesc, stop: Option<i32>) -> (Flash, i32) {
    // Clone the flash to have a new copy.
    let mut fl = flash.clone();

    unsafe { flash_counter = stop.unwrap_or(0) };
    let (first_interrupted, cnt1) = match boot_go(&mut fl, &areadesc) {
        -0x13579 => (true, stop.unwrap()),
        0 => (false, unsafe { -flash_counter }),
        x => panic!("Unknown return: {}", x),
    };
    unsafe { flash_counter = 0 };

    if first_interrupted {
        // fl.dump();
        match boot_go(&mut fl, &areadesc) {
            -0x13579 => panic!("Shouldn't stop again"),
            0 => (),
            x => panic!("Unknown return: {}", x),
        }
    }

    let cnt2 = cnt1 - unsafe { flash_counter };

    (fl, cnt2)
}

fn try_revert(flash: &Flash, areadesc: &AreaDesc) -> Flash {
    let mut fl = flash.clone();
    unsafe { flash_counter = 0 };

    assert_eq!(boot_go(&mut fl, &areadesc), 0);
    assert_eq!(boot_go(&mut fl, &areadesc), 0);
    fl
}

fn try_norevert(flash: &Flash, areadesc: &AreaDesc) -> Flash {
    let mut fl = flash.clone();
    unsafe { flash_counter = 0 };

    assert_eq!(boot_go(&mut fl, &areadesc), 0);
    // Write boot_ok
    fl.write(0x040000 - 1, &[1]).unwrap();
    assert_eq!(boot_go(&mut fl, &areadesc), 0);
    fl
}

/// Show the flash layout.
#[allow(dead_code)]
fn show_flash(flash: &Flash) {
    println!("---- Flash configuration ----");
    for sector in flash.sector_iter() {
        println!("    {:2}: 0x{:08x}, 0x{:08x}",
                 sector.num, sector.base, sector.size);
    }
    println!("");
}

/// Invoke the bootloader on this flash device.
fn boot_go(flash: &mut Flash, areadesc: &AreaDesc) -> i32 {
    unsafe { invoke_boot_go(flash as *mut _ as *mut libc::c_void,
                            &areadesc.get_c() as *const _) as i32 }
}

/// Install a "program" into the given image.  This fakes the image header, or at least all of the
/// fields used by the given code.  Returns a copy of the image that was written.
fn install_image(flash: &mut Flash, offset: usize, len: usize) -> Vec<u8> {
    let offset0 = offset;

    // Generate a boot header.  Note that the size doesn't include the header.
    let header = ImageHeader {
        magic: 0x96f3b83c,
        tlv_size: 0,
        _pad1: 0,
        hdr_size: 32,
        key_id: 0,
        _pad2: 0,
        img_size: len as u32,
        flags: 0,
        ver: ImageVersion {
            major: 1,
            minor: 0,
            revision: 1,
            build_num: 1,
        },
        _pad3: 0,
    };

    let b_header = header.as_raw();
    /*
    let b_header = unsafe { slice::from_raw_parts(&header as *const _ as *const u8,
                                                  mem::size_of::<ImageHeader>()) };
                                                  */
    assert_eq!(b_header.len(), 32);
    flash.write(offset, &b_header).unwrap();
    let offset = offset + b_header.len();

    // The core of the image itself is just pseudorandom data.
    let mut buf = vec![0; len];
    splat(&mut buf, offset);
    flash.write(offset, &buf).unwrap();
    let offset = offset + buf.len();

    // Copy out the image so that we can verify that the image was installed correctly later.
    let mut copy = vec![0u8; offset - offset0];
    flash.read(offset0, &mut copy).unwrap();

    copy
}

/// Verify that given image is present in the flash at the given offset.
fn verify_image(flash: &Flash, offset: usize, buf: &[u8]) -> bool {
    let mut copy = vec![0u8; buf.len()];
    flash.read(offset, &mut copy).unwrap();

    if buf != &copy[..] {
        for i in 0 .. buf.len() {
            if buf[i] != copy[i] {
                println!("First failure at {:#x}", offset + i);
                break;
            }
        }
        false
    } else {
        true
    }
}

/// The image header
#[repr(C)]
pub struct ImageHeader {
    magic: u32,
    tlv_size: u16,
    key_id: u8,
    _pad1: u8,
    hdr_size: u16,
    _pad2: u16,
    img_size: u32,
    flags: u32,
    ver: ImageVersion,
    _pad3: u32,
}

impl AsRaw for ImageHeader {}

#[repr(C)]
pub struct ImageVersion {
    major: u8,
    minor: u8,
    revision: u16,
    build_num: u32,
}

/// Write out the magic so that the loader tries doing an upgrade.
fn mark_upgrade(flash: &mut Flash, offset: usize) {
    let magic = vec![0x77, 0xc2, 0x95, 0xf3,
                     0x60, 0xd2, 0xef, 0x7f,
                     0x35, 0x52, 0x50, 0x0f,
                     0x2c, 0xb6, 0x79, 0x80];
    flash.write(offset, &magic).unwrap();
}

// Drop some pseudo-random gibberish onto the data.
fn splat(data: &mut [u8], seed: usize) {
    let seed_block = [0x135782ea, 0x92184728, data.len() as u32, seed as u32];
    let mut rng: XorShiftRng = SeedableRng::from_seed(seed_block);
    rng.fill_bytes(data);
}

/// Return a read-only view into the raw bytes of this object
trait AsRaw : Sized {
    fn as_raw<'a>(&'a self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self as *const _ as *const u8,
                                       mem::size_of::<Self>()) }
    }
}

extern "C" {
    // This generates a warning about `CAreaDesc` not being foreign safe.  There doesn't appear to
    // be any way to get rid of this warning.  See https://github.com/rust-lang/rust/issues/34798
    // for information and tracking.
    fn invoke_boot_go(flash: *mut libc::c_void, areadesc: *const CAreaDesc) -> libc::c_int;
    static mut flash_counter: libc::c_int;
}
