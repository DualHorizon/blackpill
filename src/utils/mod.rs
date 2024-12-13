use core::ffi::c_char;
use kernel::bindings::{call_usermodehelper, UMH_WAIT_EXEC};
use kernel::c_str;
use kernel::prelude::*;

#[macro_use]
pub(crate) mod bitfield;
pub(crate) mod misc;
pub(crate) mod x86;

/// Executes a userland program in userspace as root user.
/// Arguments:
/// - `program_path`: The path to the program to execute.
/// - `args`: The arguments to pass to the program.
/// Returns:
/// - The return code of the user-mode helper.
#[allow(dead_code)]
pub(crate) fn exec_as_root(program_path: &CStr, args: &CStr) -> Option<i32> {
    // Prepare argv and envp for the user-mode helper.
    let argv: [*mut c_char; 3] = [
        program_path.as_char_ptr() as *mut c_char,
        args.as_char_ptr() as *mut c_char,
        core::ptr::null_mut(),
    ];
    let envp: [*mut c_char; 5] = [
        c_str!("HOME=/").as_char_ptr() as *mut c_char,
        c_str!("USER=root").as_char_ptr() as *mut c_char,
        c_str!("TERM=linux").as_char_ptr() as *mut c_char,
        c_str!("PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin").as_char_ptr()
            as *mut c_char,
        core::ptr::null_mut(),
    ];

    let rc = unsafe {
        call_usermodehelper(
            argv[0] as *const c_char,
            argv.as_ptr() as *mut *mut c_char,
            envp.as_ptr() as *mut *mut c_char,
            UMH_WAIT_EXEC.try_into().unwrap(),
        )
    };

    Some(rc)
}
