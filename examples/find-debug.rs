use anyhow::{anyhow, Result};
use std::env;
use std::fs::File;
use std::io::Read;

fn work() -> Result<()> {
    let path = env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow!("Usage: find-debug <binary path>"))?;
    let mut f = File::open(&path)?;
    let mut buf = vec![];
    f.read_to_end(&mut buf)?;
    let obj = object::File::parse(&*buf)?;
    let debug_path = locate_dwarf::locate_debug_symbols(&obj, &path)?;
    if let Some(debug_path) = debug_path {
        println!("{}", debug_path.display());
    } else {
        println!("Symbols not found for '{}'", path.to_string_lossy());
    }
    Ok(())
}

fn main() {
    work().unwrap();
}
