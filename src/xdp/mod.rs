#![allow(dead_code)]
#![allow(unused_unsafe)]
// use kernel::bindings;
use kernel::c_str;
use kernel::prelude::*;

const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_OBJ_GET: u32 = 7;

#[repr(C)]
struct BpfAttrLookup {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
struct BpfAttrObjGet {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[repr(C)]
struct RawPacketData {
    payload: [u8; 4],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

type SysBpfFn = extern "C" fn(i32, *const u64, u64) -> i32;

pub(crate) fn init() {
    pr_info!("Initializing BPF map reader\n");

    unsafe {
        let sys_bpf_addr =
            crate::utils::get_function_address(c_str!("__x64_sys_bpf").as_char_ptr());
        pr_info!("bpf syscall addr: {:x}\n", sys_bpf_addr.unwrap());

        let sys_bpf = core::mem::transmute::<usize, SysBpfFn>(sys_bpf_addr.unwrap());

        // doesn't work, rc = -38 ERRNO: Function not implemented
        let _ret = sys_bpf(0, core::ptr::null_mut(), 0);
        pr_info!("bpf syscall ret: {}\n", _ret);

        // let _ret = __x64_sys_bpf(0, core::ptr::null_mut(), 0);

        // // Get map FD using BPF_OBJ_GET
        // let path = b"/sys/fs/bpf/packet_map\0";
        // let mut attr_get = BpfAttrObjGet {
        //     pathname: path.as_ptr() as u64,
        //     bpf_fd: 0,
        //     file_flags: 0,
        // };

        // // let map_fd = bindings::syscall(
        // //     bindings::__NR_bpf as i32,
        // //     &[
        // //         BPF_OBJ_GET as u64,
        // //         &attr_get as *const _ as u64,
        // //         core::mem::size_of::<BpfAttrObjGet>() as u64,
        // //     ],
        // // );

        // let map_fd = sys_bpf(
        //     BPF_OBJ_GET as i32,
        //     &attr_get as *const _ as u64,
        //     core::mem::size_of::<BpfAttrObjGet>() as u64,
        // );

        // if map_fd < 0 {
        //     pr_err!("Failed to get map FD\n");
        //     return;
        // }

        // // Read from map
        // let key = 0u32;
        // let mut value = [0u8; 16];

        // let mut attr_lookup = BpfAttrLookup {
        //     map_fd: map_fd as u32,
        //     key: &key as *const _ as u64,
        //     value: &mut value as *mut _ as u64,
        //     flags: 0,
        // };

        // // let ret = bindings::syscall(
        // //     bindings::__NR_bpf as i32,
        // //     &[
        // //         BPF_MAP_LOOKUP_ELEM as u64,
        // //         &attr_lookup as *const _ as u64,
        // //         core::mem::size_of::<BpfAttrLookup>() as u64,
        // //     ],
        // // );

        // let ret = sys_bpf(
        //     BPF_MAP_LOOKUP_ELEM as i32,
        //     &attr_lookup as *const _ as u64,
        //     core::mem::size_of::<BpfAttrLookup>() as u64,
        // );

        // if ret == 0 {
        //     let packet: RawPacketData = core::mem::transmute(value);
        //     pr_info!(
        //         "Packet from map - src_ip: {}, dst_ip: {}, src_port: {}, dst_port: {}\n",
        //         packet.src_ip,
        //         packet.dst_ip,
        //         packet.src_port,
        //         packet.dst_port
        //     );
        // } else {
        //     pr_err!("Failed to read from map\n");
        // }
    }
}
