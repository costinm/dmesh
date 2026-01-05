// #![warn(missing_docs, missing_debug_implementations)]
#![doc(test(
no_crate_inject,
attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
// #![no_std]

//! Creates a mesh environment, allowing execution of on-demand services.
//!


extern crate jni;

extern crate libc;

use std::ffi::CString;
use std::os::raw::c_char;

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JValue};
use std::ffi::CStr;


// Import modules from ssh-mesh crate
pub use sshmesh::{mesh, echo_service, pmon, lmesh};

pub type Callback = unsafe extern "C" fn(*const c_char) -> ();

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn invokeCallbackViaJNA(callback: Callback) {
    let s = CString::new("Hello3 from Rust").unwrap();
    unsafe { callback(s.as_ptr()); }
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
/// Invokes a callback function through JNI, passing a string message.
///
/// This function is intended to be called from Java via JNI.
/// It takes a callback function pointer and invokes it with a hardcoded string message.
///
/// # Arguments
///
/// * `env` - JNI environment pointer
/// * `class` - Java class object (not used in this implementation)
/// * `callback` - A function pointer to a callback function that takes a *const c_char parameter
///
/// # Safety
///
/// This function is unsafe because it directly calls a C function pointer.
/// The caller must ensure that the callback function is valid and properly handles
/// the string passed to it.
pub extern "C" fn Java_com_github_costinm_dmeshnative_Rust_invokeCallbackViaJNI(
    mut env: JNIEnv,
    _class: JClass,
    callback: JObject
) {
    let s = String::from("-----------Hello1 from Rust");
    let response = env.new_string(&s)
        .expect("Couldn't create java string!");
    env.call_method(callback, "callback", "(Ljava/lang/String;)V",
                     &[JValue::Object(&JObject::from(response))]).unwrap();
}


#[unsafe(no_mangle)]
pub extern "C" fn rust_greeting(to: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(to) };
    let recipient = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    CString::new("Hello ".to_owned() + recipient).unwrap().into_raw()
}


#[no_mangle]
pub extern "C" fn hbone_client(name: *const libc::c_char) {
    let name_cstr = unsafe { CStr::from_ptr(name) };
    let name = name_cstr.to_str().unwrap();
    println!("Hello {}!", name);
}

#[no_mangle]
pub extern "C" fn hbone_start(message: *const libc::c_char) {
    let message_cstr = unsafe { CStr::from_ptr(message) };
    let message = message_cstr.to_str().unwrap();
    println!("({})", message);
}


// This is present so it's easy to test that the code works natively in Rust via `cargo test`
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    
    #[test]
    fn test_jni_function() {
        let s = CString::new("Test message").unwrap();
        let result = rust_greeting(s.as_ptr());
        let c_str = unsafe { CStr::from_ptr(result) };
        let str_slice = c_str.to_str().unwrap();
        assert_eq!(str_slice, "Hello Test message");
        unsafe { libc::free(result as *mut libc::c_void) };
    }

    #[test]
    fn simulated_main_function () {
        hbone_client(CString::new("world").unwrap().into_raw());
        hbone_start(CString::new("this is code from Rust").unwrap().into_raw());
    }
}
