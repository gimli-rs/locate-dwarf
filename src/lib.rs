extern crate failure;
extern crate object;
extern crate uuid;

#[cfg(target_os="macos")]
extern crate CoreFoundation_sys as cf;

use failure::Error;
use object::{DebugFileInfo, File, Object};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[cfg(target_os="macos")]
mod dsym {
    use cf::base::{Boolean, CFAllocatorRef, CFGetTypeID, CFIndex, CFOptionFlags, CFStringRef,
                   CFTypeRef, kCFAllocatorDefault};
    use cf::array::{CFArrayGetTypeID, CFArrayGetCount, CFArrayGetValueAtIndex, CFArrayRef};
    use cf::string::{CFStringCreateWithBytes, CFStringGetCStringPtr, CFStringGetTypeID,
                     kCFStringEncodingUTF8};
    use failure::{self, Error};
    use std::ffi::CStr;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use uuid::Uuid;

    //const TRUE: Boolean = 1;
    const FALSE: Boolean = 0;
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct __MDQuery {
        _unused: [u8; 0],
    }
    type MDQueryRef = *mut __MDQuery;
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct __MDItem {
        _unused: [u8; 0],
    }
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
        #[link_name = "\u{1}_MDItemCopyAttribute"]
        fn MDItemCopyAttribute(item: MDItemRef,
                               name: CFStringRef)
                               -> CFTypeRef;
        #[link_name = "\u{1}_kMDItemPath"]
        static mut kMDItemPath: CFStringRef;
    }

    fn cfstring_create(s: &str) -> Result<CFStringRef, Error> {
        let cfs = unsafe {
            CFStringCreateWithBytes(kCFAllocatorDefault,
                                    s.as_ptr(),
                                    s.len() as CFIndex,
                                    kCFStringEncodingUTF8,
                                    FALSE)
        };
        if cfs == ptr::null() {
            Err(failure::err_msg("CFStringCreateWithBytes failed"))
        } else {
            Ok(cfs)
        }
    }

    fn cfstring_to_string(cfs: CFStringRef) -> Result<String, Error> {
        let s = unsafe { CStr::from_ptr(CFStringGetCStringPtr(cfs, kCFStringEncodingUTF8)) };
        Ok(s.to_str()?.to_owned())
    }

    fn get_string_attribute(item: MDItemRef, attribute: CFStringRef) -> Result<String, Error> {
        let cf_attr = unsafe { MDItemCopyAttribute(item, attribute) };
        if unsafe { CFGetTypeID(cf_attr) != CFStringGetTypeID() } {
            return Err(failure::err_msg("Not a string attribute"));
        }
        cfstring_to_string(cf_attr as CFStringRef)
    }

    /// Attempt to locate the Mach-O file inside a dSYM matching `uuid` using spotlight.
    fn spotlight_locate_dsym_bundle(uuid: Uuid) -> Result<String, Error> {
        let uuid = uuid.hyphenated().to_string().to_uppercase();
        let query_string = format!("com_apple_xcode_dsym_uuids == {}", uuid);
        let cf_query_string = cfstring_create(&query_string)?;
        let query = unsafe {
            MDQueryCreate(kCFAllocatorDefault,
                          cf_query_string,
                          ptr::null(),
                          ptr::null())
        };
        if query == ptr::null_mut() {
            return Err(failure::err_msg("MDQueryCreate failed"));
        }
        if unsafe { MDQueryExecute(query, kMDQuerySynchronous) } == FALSE {
            return Err(failure::err_msg("MDQueryExecute failed"));
        }
        let count = unsafe { MDQueryGetResultCount(query) };
        for i in 0..count {
            let item = unsafe { MDQueryGetResultAtIndex(query, i) as MDItemRef };
            if let Ok(path) = get_string_attribute(item, unsafe { kMDItemPath }) {
                return Ok(path);
            }
        }
        return Err(failure::err_msg("dSYM not found"));
    }

    /// Get the path to the Mach-O file containing DWARF debug info inside `bundle`.
    fn spotlight_get_dsym_path(bundle: &str) -> Result<String, Error> {
        let cf_bundle_string = cfstring_create(&bundle)?;
        let bundle_item = unsafe { MDItemCreate(kCFAllocatorDefault, cf_bundle_string) };
        if bundle_item == ptr::null_mut() {
            return Err(failure::err_msg("MDItemCreate failed"));
        }
        let attr = cfstring_create("com_apple_xcode_dsym_paths")?;
        let cf_attr = unsafe { MDItemCopyAttribute(bundle_item, attr) };
        if unsafe { CFGetTypeID(cf_attr) != CFArrayGetTypeID() } {
            return Err(failure::err_msg("dsym_paths attribute not an array"));
        }
        let cf_array = cf_attr as CFArrayRef;
        let count = unsafe { CFArrayGetCount(cf_array) };
        if count == 0 {
            return Err(failure::err_msg("dsym_paths array is empty"));
        }
        let cf_item = unsafe { CFArrayGetValueAtIndex(cf_array, 0) };
        if unsafe { CFGetTypeID(cf_item) != CFStringGetTypeID() } {
            return Err(failure::err_msg("dsym_paths entry not a string"));
        }
        cfstring_to_string(cf_item as CFStringRef)
    }

    pub fn locate(_path: &Path, uuid: Uuid) -> Result<PathBuf, Error> {
        let bundle = spotlight_locate_dsym_bundle(uuid)?;
        Ok(Path::new(&bundle).join(spotlight_get_dsym_path(&bundle)?))
    }
}

#[cfg(not(target_os="macos"))]
mod dsym {
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
    let debug_info = object.debug_file_info()
        .ok_or(failure::err_msg("Object does not have debug info pointer"))?;
    match debug_info {
        DebugFileInfo::MachOUuid(uuid) => locate_dsym(path.as_ref(), uuid),
    }
}

/// Attempt to locate the Mach-O file contained within a dSYM bundle containing the debug
/// symbols for the Mach-O file at `path` with UUID `uuid`.
pub fn locate_dsym<T>(path: T, uuid: Uuid) -> Result<PathBuf, Error>
    where T: AsRef<Path>,
{
    dsym::locate(path.as_ref(), uuid)
}
