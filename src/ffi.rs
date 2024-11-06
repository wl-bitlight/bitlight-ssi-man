use std::{
    ffi::{c_char, CStr, CString},
    ptr,
};

use libc::size_t;

use crate::{Error, SsiMan};

macro_rules! c_char_to_string {
    ($chars: ident) => {
        unsafe {
            if $chars.is_null() {
                panic!("{} cannot be null", stringify!($chars));
            }
            CStr::from_ptr($chars).to_string_lossy().into_owned()
        }
    };
}

fn to_c_char(string: String) -> *mut c_char {
    let c_str_content = CString::new(string).unwrap();
    c_str_content.into_raw()
}

#[cfg(feature = "sqlite")]
fn ssi_man_new(db_path: *const c_char) -> Result<SsiMan, Error> {
    if !db_path.is_null() {
        SsiMan::with_sqlite(c_char_to_string!(db_path))
    } else {
        Ok(SsiMan::with_memory())
    }
}

#[cfg(not(feature = "sqlite"))]
fn ssi_man_new(_db_path: *const c_char) -> Result<SsiMan, Error> {
    Ok(SsiMan::with_memory())
}

#[no_mangle]
pub extern "C" fn ssi_new(
    name: *const c_char,
    email: *const c_char,
    db_path: *const c_char,
) -> *mut c_char {
    ssi_man_new(db_path)
        .and_then(|mut ssi_man| {
            ssi_man.new_ssi(c_char_to_string!(name), c_char_to_string!(email), None)
        })
        .map(to_c_char)
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ssi_sign(
    ssi: *mut c_char,
    message: *const c_char,
    db_path: *const c_char,
) -> *mut c_char {
    ssi_man_new(db_path)
        .and_then(|mut ssi_man| {
            ssi_man.sign(
                c_char_to_string!(ssi),
                c_char_to_string!(message).as_bytes(),
                None,
            )
        })
        .map(to_c_char)
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ssi_list(
    db_path: *const c_char,
    out_ssis: &mut *mut *const c_char,
    out_len: *mut size_t,
) -> i32 {
    ssi_man_new(db_path)
        .and_then(|mut ssi_man| {
            ssi_man.all_identities().map(|identities| {
                let c_strings = identities
                    .into_iter()
                    .flat_map(|identity| CString::new(identity.into_owned()))
                    .collect::<Vec<_>>();

                let c_ptrs = c_strings
                    .iter()
                    .map(|s| s.as_ptr())
                    .collect::<Vec<*const c_char>>();

                let boxed_array = c_ptrs.into_boxed_slice();
                let leaked_array = Box::leak(boxed_array);

                unsafe {
                    *out_len = leaked_array.len() as size_t;
                    *out_ssis = leaked_array.as_mut_ptr();
                }

                Box::leak(Box::new(c_strings));
                0
            })
        })
        .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn free_string_array(array: *mut *const c_char, len: size_t) {
    if array.is_null() {
        return;
    }

    unsafe {
        let slice = std::slice::from_raw_parts(array, len);
        for &s in slice {
            if !s.is_null() {
                drop(CString::from_raw(s as *mut c_char))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn ssi_ffi_methods_should_success() {
        let db_path = to_c_char(
            env::temp_dir()
                .join(format!(
                    "ssi_test_{}.db",
                    OffsetDateTime::now_utc().unix_timestamp()
                ))
                .display()
                .to_string(),
        );

        let ssi = ssi_new(
            to_c_char("luna".into()),
            to_c_char("luna@bitlightlabs.com".into()),
            db_path,
        );
        assert!(!ssi.is_null());

        let mut out_ssi: *mut *const c_char = ptr::null_mut();
        let mut out_len: size_t = 0;
        ssi_list(db_path, &mut out_ssi, &mut out_len);
        assert_eq!(out_len, 1);
        let name = unsafe { *out_ssi.offset(0isize) };
        assert_eq!(c_char_to_string!(name).as_str(), "luna");
        free_string_array(out_ssi, out_len);
    }
}
