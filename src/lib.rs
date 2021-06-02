#![warn(clippy::all)]

use anyhow::{anyhow, Error};
use core::convert::TryInto;
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
        #[allow(clippy::unnecessary_wraps)]
        fn locate_dsym_using_spotlight(_uuid: Uuid) -> Result<Option<PathBuf>, Error> {
            Ok(None)
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
/// or if the debug symbol file is not present on disk, return None.
///
/// Currently only locating Mach-O dSYM bundles is supported.
pub fn locate_debug_symbols<'a, O, T>(object: &'a O, path: T) -> Result<Option<PathBuf>, Error>
where
    O: Object<'a, 'a>,
    T: AsRef<Path>,
{
    if let Some(uuid) = object.mach_uuid()? {
        return locate_dsym(path.as_ref(), uuid);
    }
    if let Some(pdbinfo) = object.pdb_info()? {
        return locate_pdb(path.as_ref(), &pdbinfo);
    }
    if let Some(path) = object
        .build_id()?
        .and_then(|build_id| locate_debug_build_id(build_id))
    {
        return Ok(Some(path));
        // If not found, try gnu_debuglink.
    }
    if let Some((filename, crc)) = object.gnu_debuglink()? {
        let filename = path_from_bytes(filename)?;
        return locate_gnu_debuglink(path.as_ref(), filename, crc);
    }
    Ok(None)
}

/// Attempt to locate the Mach-O file contained within a dSYM bundle containing the debug
/// symbols for the Mach-O file at `path` with UUID `uuid`.
pub fn locate_dsym<T>(path: T, uuid: Uuid) -> Result<Option<PathBuf>, Error>
where
    T: AsRef<Path>,
{
    if let Some(dsym_path) = locate_dsym_fastpath(path.as_ref(), uuid) {
        return Ok(Some(dsym_path));
    }
    locate_dsym_using_spotlight(uuid)
}

/// Attempt to locate the PDB file for an executable that is at `path` with the
/// pdb infomation stored in `pdbinfo`.
pub fn locate_pdb<T>(path: T, pdbinfo: &object::CodeView) -> Result<Option<PathBuf>, Error>
where
    T: AsRef<Path>,
{
    // Search order taken from here:
    // https://docs.microsoft.com/en-us/windows/win32/debug/symbol-paths

    // First check path in PE file
    let codeview_path = PathBuf::from(path_from_bytes(pdbinfo.path())?);
    if try_match_pdb(pdbinfo.guid(), pdbinfo.age(), &codeview_path)? {
        return Ok(Some(codeview_path));
    }

    // Next check _NT_SYMBOL_PATH env var
    if let Some(path) = locate_pdb_from_env_var(&path, "_NT_SYMBOL_PATH", pdbinfo)? {
        return Ok(Some(path));
    }

    // Next check _NT_ALT_SYMBOL_PATH env var
    if let Some(path) = locate_pdb_from_env_var(&path, "_NT_ALT_SYMBOL_PATH", pdbinfo)? {
        return Ok(Some(path));
    }

    // Next check module directory
    let path = fs::canonicalize(path)?;
    if let Some(search_path) = path.parent() {
        if let Some(path) = locate_pdb_in_search_path(&path, search_path.as_os_str(), pdbinfo)? {
            return Ok(Some(path));
        }
    }

    Ok(None)
}

fn locate_pdb_from_env_var<T>(
    path: T,
    env_var: &str,
    pdbinfo: &object::CodeView,
) -> Result<Option<PathBuf>, Error>
where
    T: AsRef<Path>,
{
    if let Ok(search_paths) = std::env::var(env_var) {
        let search_paths = search_paths.split(';');
        for search_path in search_paths {
            if let Some(path) =
                locate_pdb_in_search_path(&path, std::ffi::OsStr::new(search_path), pdbinfo)?
            {
                return Ok(Some(path));
            }
        }
    }

    Ok(None)
}

fn locate_pdb_in_search_path<T>(
    path: T,
    search_path: &OsStr,
    pdbinfo: &object::CodeView,
) -> Result<Option<PathBuf>, Error>
where
    T: AsRef<Path>,
{
    if let Some(search_path) = search_path.to_str() {
        if search_path.starts_with("srv*") || search_path.starts_with("cache*") {
            // Currently srv* and cache* are unsupported
            return Ok(None);
        }
    }

    let path = path.as_ref();
    let mut search_path = PathBuf::from(search_path);
    if !search_path.exists() {
        return Ok(None);
    }

    let filename = match path.file_name() {
        Some(name) => name,
        None => return Ok(None),
    };

    let extension = match path.extension() {
        Some(ext) => ext,
        None => return Ok(None),
    };

    // First try search_path/filename.pdb
    search_path.push(filename);
    search_path.set_extension("pdb");
    if try_match_pdb(pdbinfo.guid(), pdbinfo.age(), &search_path)? {
        return Ok(Some(search_path));
    }

    // Next search_path/extension/filename.pdb
    search_path.pop();
    search_path.push(extension);
    search_path.push(filename);
    search_path.set_extension("pdb");
    if try_match_pdb(pdbinfo.guid(), pdbinfo.age(), &search_path)? {
        return Ok(Some(search_path));
    }

    // Last search_path/symbols/extension/filename.pdb
    search_path.pop();
    search_path.pop();
    search_path.push("symbols");
    search_path.push(extension);
    search_path.push(filename);
    search_path.set_extension("pdb");
    if try_match_pdb(pdbinfo.guid(), pdbinfo.age(), &search_path)? {
        return Ok(Some(search_path));
    }

    Ok(None)
}

fn try_match_pdb(guid: [u8; 16], age: u32, path: &Path) -> Result<bool, Error> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(false),
    };
    let mut pdb = match pdb::PDB::open(file) {
        Ok(pdb) => pdb,
        Err(_) => return Ok(false),
    };

    let info = pdb.pdb_information()?;
    let id = uuid::Uuid::from_fields(
        u32::from_le_bytes(guid[0..4].try_into().unwrap()),
        u16::from_le_bytes(guid[4..6].try_into().unwrap()),
        u16::from_le_bytes(guid[6..8].try_into().unwrap()),
        &guid[8..16],
    )?;
    Ok(info.age == age && info.guid == id)
}

/// Attempt to locate the separate debug symbol file for the object file at `path` with
/// build ID `id`.
pub fn locate_debug_build_id(id: &[u8]) -> Option<PathBuf> {
    if id.len() < 2 {
        return None;
    }

    // Try "/usr/lib/debug/.build-id/12/345678etc.debug"
    let mut f = format!("/usr/lib/debug/.build-id/{:02x}/", id[0]);
    for x in &id[1..] {
        let _ = write!(&mut f, "{:02x}", x);
    }
    let _ = write!(&mut f, ".debug");
    let f = PathBuf::from(f);
    if f.exists() {
        return Some(f);
    }

    None
}

/// Attempt to locate the separate debug symbol file for the object file at `path` with
/// GNU "debug link" information consisting of `filename` and `crc`.
pub fn locate_gnu_debuglink<T, U>(path: T, filename: U, _crc: u32) -> Result<Option<PathBuf>, Error>
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
        return Ok(Some(f));
    }

    // Try "/parent/.debug/filename"
    let f = parent.join(".debug").join(filename);
    if f.exists() {
        return Ok(Some(f));
    }

    // Try "/usr/lib/debug/parent/filename"
    let parent = parent.strip_prefix("/").unwrap();
    let f = Path::new("/usr/lib/debug").join(parent).join(filename);
    if f.exists() {
        return Ok(Some(f));
    }

    Ok(None)
}
