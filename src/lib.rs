#![warn(clippy::all)]

use failure::Error;
use object::{File, Object};
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

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
        fn locate_dsym_using_spotlight(_uuid: uuid::Uuid) -> Result<PathBuf, Error> {
            Err(failure::err_msg("Could not locate dSYM"))
        }
    }
}

/// Attempt to locate the path to separate debug symbols for `object` at `path`.
///
/// If `object` does not contain information that can be used to locate debug symbols for it,
/// or if the debug symbol file is not present on disk, return an error.
///
/// Currently only locating Mach-O dSYM bundles is supported.
pub fn locate_debug_symbols<T>(object: &File<'_>, path: T) -> Result<PathBuf, Error>
where
    T: AsRef<Path>,
{
    if let Some(uuid) = object.mach_uuid() {
        return locate_dsym(path.as_ref(), uuid);
    }
    if let Some(build_id) = object.build_id() {
        let path = locate_debug_build_id(build_id);
        if path.is_ok() {
            return path;
        }
        // If not found, try gnu_debuglink.
    }
    if let Some((filename, crc)) = object.gnu_debuglink() {
        let filename = path_from_bytes(filename)?;
        return locate_gnu_debuglink(path.as_ref(), filename, crc);
    }
    Err(failure::err_msg("Object does not have debug info pointer"))
}

/// Attempt to locate the Mach-O file contained within a dSYM bundle containing the debug
/// symbols for the Mach-O file at `path` with UUID `uuid`.
pub fn locate_dsym<T>(path: T, uuid: Uuid) -> Result<PathBuf, Error>
where
    T: AsRef<Path>,
{
    locate_dsym_using_spotlight(uuid)
}

/// Attempt to locate the separate debug symbol file for the object file at `path` with
/// build ID `id`.
pub fn locate_debug_build_id(id: &[u8]) -> Result<PathBuf, Error> {
    if id.len() < 2 {
        return Err(failure::err_msg("Build ID is too short"));
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

    Err(failure::err_msg("Could not locate file with build ID"))
}

/// Attempt to locate the separate debug symbol file for the object file at `path` with
/// GNU "debug link" information consisting of `filename` and `crc`.
pub fn locate_gnu_debuglink<T, U>(path: T, filename: U, _crc: u32) -> Result<PathBuf, Error>
where
    T: AsRef<Path>,
    U: AsRef<Path>,
{
    let path = fs::canonicalize(path)?;
    let parent = path.parent().ok_or_else(|| failure::err_msg("Bad path"))?;
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

    Err(failure::err_msg("Could not locate GNU debug link file"))
}
