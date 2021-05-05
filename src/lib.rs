#![warn(clippy::all)]

use anyhow::{anyhow, Error};
use object::Object;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

pub type Uuid = [u8; 16];

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        #[allow(clippy::unnecessary_wraps)]
        fn path_from_bytes(bytes: &[u8]) -> Result<&OsStr, Error> {
            Ok(OsStr::from_bytes(bytes))
        }
    } else {
        use std::str;

        fn path_from_bytes(bytes: &[u8]) -> Result<&str, str::Utf8Error> {
            str::from_utf8(bytes)
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos;
        use crate::macos::locate_dsym_using_spotlight;
    } else {
        fn locate_dsym_using_spotlight(_uuid: Uuid) -> Result<PathBuf, Error> {
            Err(anyhow!("Could not locate dSYM"))
        }
    }
}

/// On macOS it can take some time for spotlight to index the dSYM file and on other OSes it is
/// impossible to use spotlight. When built by cargo, we can likely find the dSYM file in
/// target/<profile>/deps or target/<profile>/examples. Otherwise it can likely be found at
/// <filename>.dSYM. This function will try to find it there.
///
/// # Arguments
///
/// * Parsed version of the object file which needs its debuginfo.
/// * Path to the object file.
fn locate_dsym_fastpath(path: &Path, uuid: Uuid) -> Option<PathBuf> {
    // Canonicalize the path to make sure the fastpath also works when current working
    // dir is inside target/
    let path = path.canonicalize().ok()?;

    // First try <path>.dSYM
    let mut dsym = path.file_name()?.to_owned();
    dsym.push(".dSYM");
    let dsym_dir = path.with_file_name(&dsym);
    if let Some(f) = try_match_dsym(&dsym_dir, uuid) {
        return Some(f);
    }

    // Get the path to the target dir of the current build channel.
    let mut target_channel_dir = &*path;
    loop {
        let parent = target_channel_dir.parent()?;
        target_channel_dir = parent;

        if target_channel_dir.parent().and_then(Path::file_name)
            == Some(std::ffi::OsStr::new("target"))
        {
            break; // target_dir = ???/target/<channel>
        }
    }

    // Check every entry in <target_channel_dir>/deps and <target_channel_dir>/examples
    for dir in fs::read_dir(target_channel_dir.join("deps"))
        .unwrap()
        .chain(fs::read_dir(target_channel_dir.join("examples")).unwrap())
    {
        let dir = dir.unwrap().path();

        // If not a dSYM dir, try next entry.
        if dir.extension() != Some(std::ffi::OsStr::new("dSYM")) {
            continue;
        }

        if let Some(debug_file_name) = try_match_dsym(&dir, uuid) {
            return Some(debug_file_name);
        }
    }

    None
}

fn try_match_dsym(dsym_dir: &Path, uuid: Uuid) -> Option<PathBuf> {
    // Get path to inner object file.
    let mut dir_iter = fs::read_dir(dsym_dir.join("Contents/Resources/DWARF")).ok()?;

    let debug_file_name = dir_iter.next()?.ok()?.path();

    if dir_iter.next().is_some() {
        return None; // There should only be one file in the `DWARF` directory.
    }

    // Parse inner object file.
    let file = fs::read(&debug_file_name).ok()?;
    let dsym = object::File::parse(&file[..]).ok()?;

    // Make sure the dSYM file matches the object file to find debuginfo for.
    if dsym.mach_uuid() == Ok(Some(uuid)) {
        Some(debug_file_name)
    } else {
        None
    }
}

/// Attempt to locate the path to separate debug symbols for `object` at `path`.
///
/// If `object` does not contain information that can be used to locate debug symbols for it,
/// or if the debug symbol file is not present on disk, return an error.
///
/// Currently only locating Mach-O dSYM bundles is supported.
pub fn locate_debug_symbols<'a, O, T>(object: &'a O, path: T) -> Result<PathBuf, Error>
where
    O: Object<'a, 'a>,
    T: AsRef<Path>,
{
    if let Some(uuid) = object.mach_uuid()? {
        return locate_dsym(path.as_ref(), uuid);
    }
    if let Some(build_id) = object.build_id()? {
        let path = locate_debug_build_id(build_id);
        if path.is_ok() {
            return path;
        }
        // If not found, try gnu_debuglink.
    }
    if let Some((filename, crc)) = object.gnu_debuglink()? {
        let filename = path_from_bytes(filename)?;
        return locate_gnu_debuglink(path.as_ref(), filename, crc);
    }
    Err(anyhow!("Object does not have debug info pointer"))
}

/// Attempt to locate the Mach-O file contained within a dSYM bundle containing the debug
/// symbols for the Mach-O file at `path` with UUID `uuid`.
pub fn locate_dsym<T>(path: T, uuid: Uuid) -> Result<PathBuf, Error>
where
    T: AsRef<Path>,
{
    if let Some(dsym_path) = locate_dsym_fastpath(path.as_ref(), uuid) {
        return Ok(dsym_path);
    }
    locate_dsym_using_spotlight(uuid)
}

/// Attempt to locate the separate debug symbol file for the object file at `path` with
/// build ID `id`.
pub fn locate_debug_build_id(id: &[u8]) -> Result<PathBuf, Error> {
    if id.len() < 2 {
        return Err(anyhow!("Build ID is too short"));
    }

    // Try "/usr/lib/debug/.build-id/12/345678etc.debug"
    let mut f = format!("/usr/lib/debug/.build-id/{:02x}/", id[0]);
    for x in &id[1..] {
        write!(&mut f, "{:02x}", x).ok();
    }
    write!(&mut f, ".debug").ok();
    let f = PathBuf::from(f);
    if f.exists() {
        return Ok(f);
    }

    Err(anyhow!("Could not locate file with build ID"))
}

/// Attempt to locate the separate debug symbol file for the object file at `path` with
/// GNU "debug link" information consisting of `filename` and `crc`.
pub fn locate_gnu_debuglink<T, U>(path: T, filename: U, _crc: u32) -> Result<PathBuf, Error>
where
    T: AsRef<Path>,
    U: AsRef<Path>,
{
    let path = fs::canonicalize(path)?;
    let parent = path.parent().ok_or_else(|| anyhow!("Bad path"))?;
    let filename = filename.as_ref();

    // TODO: check CRC

    // Try "/parent/filename" if it differs from "path"
    let f = parent.join(filename);
    if f != path && f.exists() {
        return Ok(f);
    }

    // Try "/parent/.debug/filename"
    let f = parent.join(".debug").join(filename);
    if f.exists() {
        return Ok(f);
    }

    // Try "/usr/lib/debug/parent/filename"
    let parent = parent.strip_prefix("/").unwrap();
    let f = Path::new("/usr/lib/debug").join(parent).join(filename);
    if f.exists() {
        return Ok(f);
    }

    Err(anyhow!("Could not locate GNU debug link file"))
}
