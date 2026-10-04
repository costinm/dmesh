//! JNI bindings for the `app-control` Android adapter.
//!
//! Message-oriented surface (mirrors `crates/dmesh-android` conventions):
//! Java passes plain strings/byte[] and receives strings/byte[]; no per-feature
//! native methods beyond start/pair/connect/shell/stop + callbacks.
//!
//! Java class: `com.github.costinm.dmesh.control.AdbController`
//! (native library `android_control`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong};
use jni::{JNIEnv, JavaVM};

use crate::adb::AdbDevice;
use crate::keys::AdbKeys;
use crate::pairing::pair_client;

/// Per-VM state: the adbkey directory (app-private `files/adb`).
#[derive(Default)]
struct State {
    key_dir: Mutex<Option<PathBuf>>,
    keys: Mutex<Option<Arc<AdbKeys>>>,
    device: Mutex<Option<AdbDevice>>,
}

static STATE: OnceLock<Arc<State>> = OnceLock::new();

fn state(_vm: &JavaVM) -> Arc<State> {
    STATE.get_or_init(|| Arc::new(State::default())).clone()
}

fn keys_of(st: &State) -> Option<Arc<AdbKeys>> {
    st.keys.lock().unwrap().clone()
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    let _ = unsafe { JavaVM::from_raw(vm) };
    jni::sys::JNI_VERSION_1_6
}

/// `nativeStart(String baseDir) -> long`
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmesh_control_AdbController_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    base_dir: JString,
) -> jlong {
    let dir: String = match env.get_string(&base_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let vm = env.get_java_vm().unwrap();
    let st = state(&vm);
    match AdbKeys::load_or_create(&PathBuf::from(dir.as_str())) {
        Ok(keys) => {
            *st.key_dir.lock().unwrap() = Some(PathBuf::from(dir));
            *st.keys.lock().unwrap() = Some(keys);
            1
        }
        Err(e) => {
            eprintln!("android-control: key init failed: {e:?}");
            0
        }
    }
}

/// `nativePair(String host, int port, String code) -> boolean`
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmesh_control_AdbController_nativePair(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jint,
    code: JString,
) -> jboolean {
    use jni::sys::JNI_FALSE;
    use jni::sys::JNI_TRUE;
    let vm = match env.get_java_vm() {
        Ok(v) => v,
        Err(_) => return JNI_FALSE,
    };
    let st = state(&vm);
    let Some(keys) = keys_of(&st) else {
        return JNI_FALSE;
    };
    let host_s: String = env.get_string(&host).map(|s| s.into()).unwrap_or_default();
    let code_s: String = env.get_string(&code).map(|s| s.into()).unwrap_or_default();
    match pair_client(&host_s, port as u16, &code_s, &keys) {
        Ok(_res) => JNI_TRUE,
        Err(e) => {
            eprintln!("android-control: pair failed: {e:?}");
            JNI_FALSE
        }
    }
}

/// `nativeConnect(String host, int port) -> boolean`
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmesh_control_AdbController_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jint,
) -> jboolean {
    use jni::sys::JNI_FALSE;
    use jni::sys::JNI_TRUE;
    let vm = match env.get_java_vm() {
        Ok(v) => v,
        Err(_) => return JNI_FALSE,
    };
    let st = state(&vm);
    let Some(dir) = st.key_dir.lock().unwrap().clone() else {
        return JNI_FALSE;
    };
    if keys_of(&st).is_none() {
        return JNI_FALSE;
    }
    let host_s: String = env.get_string(&host).map(|s| s.into()).unwrap_or_default();
    let addr: std::net::SocketAddr = match format!("{host_s}:{}", port as u16).parse() {
        Ok(a) => a,
        Err(_) => return JNI_FALSE,
    };
    let key_path = dir.join("adbkey");
    match AdbDevice::connect(addr, &key_path) {
        Ok(dev) => {
            *st.device.lock().unwrap() = Some(dev);
            JNI_TRUE
        }
        Err(e) => {
            eprintln!("android-control: connect failed: {e:?}");
            JNI_FALSE
        }
    }
}

/// `nativeShell(String command) -> String`
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmesh_control_AdbController_nativeShell<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    command: JString<'a>,
) -> JString<'a> {
    let cmd: String = env.get_string(&command).map(|s| s.into()).unwrap_or_default();
    let out = {
        let st = STATE.get();
        match st {
            Some(st) => match st.device.lock().unwrap().as_mut() {
                Some(dev) => dev.shell(&cmd).unwrap_or_default(),
                None => String::new(),
            },
            None => String::new(),
        }
    };
    env.new_string(out).unwrap().into()
}

/// `nativeStop() -> void`
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmesh_control_AdbController_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Some(st) = STATE.get() {
        *st.device.lock().unwrap() = None;
    }
}
