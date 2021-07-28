use anyhow::Error;
use core::convert::TryInto;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::path_utils::path_from_bytes;

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
