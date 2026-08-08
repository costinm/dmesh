#![no_std]
#![no_main]

use core::panic::PanicInfo;
use dmesh_mod_rawwifi::ModuleContext;

#[no_mangle]
#[inline(never)]
#[link_section = ".entry"]
pub unsafe extern "C" fn module_entry(
    context: *const ModuleContext,
    payload: *const u8,
    payload_len: usize,
    args: *const u8,
    args_len: usize,
) -> i32 {
    dmesh_mod_rawwifi::dmesh_module_entry(context, payload, payload_len, args, args_len)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
