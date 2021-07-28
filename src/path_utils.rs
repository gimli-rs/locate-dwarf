use anyhow::Error;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        #[allow(clippy::unnecessary_wraps)]
        pub fn path_from_bytes(bytes: &[u8]) -> Result<&OsStr, Error> {
            Ok(OsStr::from_bytes(bytes))
        }
    } else {
        use std::str;

        pub fn path_from_bytes(bytes: &[u8]) -> Result<&str, str::Utf8Error> {
            str::from_utf8(bytes)
        }
    }
}
