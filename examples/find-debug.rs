use anyhow::{anyhow, Result};
use std::env;
use std::fs::File;
use std::io::Read;

fn work() -> Result<()> {
    let path = env::args_os()
        .nth(1)
        .ok_or(anyhow!("Usage: find-debug <binary path>"))?;
    let mut f = File::open(&path)?;
    let mut buf = vec![];
    f.read_to_end(&mut buf)?;
    let obj = object::File::parse(&*buf).or(Err(anyhow!("Couldn't parse binary")))?;
    let debug_path = locate_dwarf::locate_debug_symbols(&obj, &path)?;
    println!("{}", debug_path.to_string_lossy());
    Ok(())
}

fn main() {
    work().unwrap();
}
