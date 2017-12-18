extern crate failure;
extern crate moria;
extern crate object;

use std::env;
use std::fs::File;
use std::io::Read;

fn work() -> Result<(), failure::Error> {
    let path = env::args_os().nth(1)
        .ok_or(failure::err_msg("Usage: find-debug <binary path>"))?;
    let mut f = File::open(&path)?;
    let mut buf = vec![];
    f.read_to_end(&mut buf)?;
    let obj = object::File::parse(&*buf)
        .or(Err(failure::err_msg("Couldn't parse binary")))?;
    let debug_path = moria::locate_debug_symbols(&obj, &path)?;
    println!("{}", debug_path.to_string_lossy());
    Ok(())
}

fn main() {
    work().unwrap();
}
