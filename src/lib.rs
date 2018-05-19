#[macro_use]
extern crate cfg_if;
extern crate failure;
extern crate libc;
extern crate object;
extern crate uuid;

#[cfg(target_os="macos")]
#[macro_use]
extern crate core_foundation;
#[cfg(target_os="macos")]
extern crate core_foundation_sys;

use failure::Error;
use object::{File, Object};
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

cfg_if! {
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

#[cfg(target_os="macos")]
mod dsym {
    use core_foundation::array::{CFArray, CFArrayRef};
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFAllocatorRef, CFIndex, CFOptionFlags, CFRelease, CFTypeID,
                                    kCFAllocatorDefault};
    use core_foundation_sys::string::CFStringRef;
    use failure::{self, Error};
    use libc::c_void;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use uuid::Uuid;

    type Boolean = ::std::os::raw::c_uchar;
    //const TRUE: Boolean = 1;
    const FALSE: Boolean = 0;
    #[repr(C)]
    struct __MDQuery(c_void);
    type MDQueryRef = *mut __MDQuery;
    #[repr(C)]
    struct __MDItem(c_void);
    type MDItemRef = *mut __MDItem;

    #[allow(non_upper_case_globals)]
    const kMDQuerySynchronous: CFOptionFlags = 1;
    #[link(name = "CoreServices", kind = "framework")]
    extern "C" {
        #[link_name="\u{1}_MDQueryCreate"]
        fn MDQueryCreate(allocator: CFAllocatorRef,
                         queryString: CFStringRef,
                         valueListAttrs: CFArrayRef,
                         sortingAttrs: CFArrayRef)
                         -> MDQueryRef;
        #[link_name = "\u{1}_MDQueryGetTypeID"]
        fn MDQueryGetTypeID() -> CFTypeID;
        #[link_name = "\u{1}_MDQueryExecute"]
        fn MDQueryExecute(query: MDQueryRef,
                          optionFlags: CFOptionFlags)
                          -> Boolean;
        #[link_name = "\u{1}_MDQueryGetResultCount"]
        fn MDQueryGetResultCount(query: MDQueryRef) -> CFIndex;
        #[link_name = "\u{1}_MDQueryGetResultAtIndex"]
        fn MDQueryGetResultAtIndex(query: MDQueryRef,
                                   idx: CFIndex)
                                   -> *const ::std::os::raw::c_void;
        #[link_name = "\u{1}_MDItemCreate"]
        fn MDItemCreate(allocator: CFAllocatorRef, path: CFStringRef) -> MDItemRef;
        #[link_name = "\u{1}_MDItemGetTypeID"]
        pub fn MDItemGetTypeID() -> CFTypeID;
        #[link_name = "\u{1}_MDItemCopyAttribute"]
        fn MDItemCopyAttribute(item: MDItemRef,
                               name: CFStringRef)
                               -> CFTypeRef;
        #[link_name = "\u{1}_kMDItemPath"]
        static mut kMDItemPath: CFStringRef;
    }

    struct MDQuery(MDQueryRef);

    impl MDQuery {
        pub fn create(query_string: &str) -> Result<MDQuery, Error> {
            let cf_query_string = CFString::new(&query_string);
            let query = unsafe {
                MDQueryCreate(kCFAllocatorDefault,
                              ctref(&cf_query_string),
                              ptr::null(),
                              ptr::null())
            };
            if query == ptr::null_mut() {
                return Err(failure::err_msg("MDQueryCreate failed"));
            }
            unsafe { Ok(MDQuery::wrap_under_create_rule(query)) }
        }
        pub fn execute(&self) -> Result<CFIndex, Error> {
            if unsafe { MDQueryExecute(ctref(self), kMDQuerySynchronous) } == FALSE {
                return Err(failure::err_msg("MDQueryExecute failed"));
            }
            unsafe { Ok(MDQueryGetResultCount(ctref(self))) }
        }
    }
    impl Drop for MDQuery {
        fn drop(&mut self) {
            unsafe {
                CFRelease(self.as_CFTypeRef())
            }
        }
    }
    impl_TCFType!(MDQuery, MDQueryRef, MDQueryGetTypeID);

    struct MDItem(MDItemRef);
    impl Drop for MDItem {
        fn drop(&mut self) {
            unsafe {
                CFRelease(self.as_CFTypeRef())
            }
        }
    }
    impl_TCFType!(MDItem, MDItemRef, MDItemGetTypeID);

    #[inline]
    fn ctref<T, C>(t: &T) -> C
        where T: TCFType<C>
    {
        t.as_concrete_TypeRef()
    }

    fn cftype_to_string(cft: CFType) -> Result<String, Error> {
        if !cft.instance_of::<_, CFString>() {
            return Err(failure::err_msg("Not a string"));
        }
        let cf_string = unsafe {
            CFString::wrap_under_get_rule(ctref(&cft) as CFStringRef)
        };
        Ok(cf_string.to_string())
    }

    /// Attempt to locate the Mach-O file inside a dSYM matching `uuid` using spotlight.
    fn spotlight_locate_dsym_bundle(uuid: Uuid) -> Result<String, Error> {
        let uuid = uuid.hyphenated().to_string().to_uppercase();
        let query_string = format!("com_apple_xcode_dsym_uuids == {}", uuid);
        let query = MDQuery::create(&query_string)?;
        let count = query.execute()?;
        for i in 0..count {
            let item = unsafe { MDQueryGetResultAtIndex(ctref(&query), i) as MDItemRef };
            let attr = unsafe { CFString::wrap_under_get_rule(kMDItemPath) };
            let cf_attr = unsafe { MDItemCopyAttribute(item, ctref(&attr)) };
            if cf_attr == ptr::null_mut() {
                return Err(failure::err_msg("MDItemCopyAttribute failed"));
            }
            let cf_attr = unsafe { CFType::wrap_under_get_rule(cf_attr) };
            if let Ok(path) = cftype_to_string(cf_attr) {
                return Ok(path);
            }
        }
        return Err(failure::err_msg("dSYM not found"));
    }

    /// Get the path to the Mach-O file containing DWARF debug info inside `bundle`.
    fn spotlight_get_dsym_path(bundle: &str) -> Result<String, Error> {
        let cf_bundle_string = CFString::new(bundle);
        let bundle_item = unsafe { MDItemCreate(kCFAllocatorDefault,
                                                ctref(&cf_bundle_string)) };
        if bundle_item == ptr::null_mut() {
            return Err(failure::err_msg("MDItemCreate failed"));
        }
        let bundle_item = unsafe { MDItem::wrap_under_create_rule(bundle_item) };
        let attr = CFString::from_static_string("com_apple_xcode_dsym_paths");
        let cf_attr = unsafe {
            CFType::wrap_under_get_rule(MDItemCopyAttribute(ctref(&bundle_item),
                                                            ctref(&attr)))
        };
        if !cf_attr.instance_of::<_, CFArray>() {
            return Err(failure::err_msg("dsym_paths attribute not an array"));
        }
        let cf_array = unsafe {
            CFArray::wrap_under_get_rule(ctref(&cf_attr) as CFArrayRef)
        };
        if let Some(cf_item) = cf_array.iter().nth(0) {
            let cf_item = unsafe { CFType::wrap_under_get_rule(cf_item) };
            return cftype_to_string(cf_item);
        }
        return Err(failure::err_msg("dsym_paths array is empty"));
    }

    pub fn locate(_path: &Path, uuid: Uuid) -> Result<PathBuf, Error> {
        let bundle = spotlight_locate_dsym_bundle(uuid)?;
        Ok(Path::new(&bundle).join(spotlight_get_dsym_path(&bundle)?))
    }
}

#[cfg(not(target_os="macos"))]
mod dsym {
    use failure::{self, Error};
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    /// Attempt to find the DWARF-containing file inside a dSYM bundle for the Mach-O binary
    /// at `path` using simple path manipulation.
    pub fn locate(path: &Path, _uuid: Uuid) -> Result<PathBuf, Error> {
        let filename = path.file_name()
            .ok_or(failure::err_msg("Bad path"))?;
        let mut dsym = filename.to_owned();
        dsym.push(".dSYM");
        let f = path.with_file_name(&dsym).join("Contents/Resources/DWARF").join(filename);
        if f.exists() {
            Ok(f)
        } else {
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
pub fn locate_debug_symbols<T>(object: &File, path: T) -> Result<PathBuf, Error>
    where T: AsRef<Path>,
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
    where T: AsRef<Path>,
{
    dsym::locate(path.as_ref(), uuid)
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
    let parent = path.parent().ok_or(failure::err_msg("Bad path"))?;
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
