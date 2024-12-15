#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[repr(C)]
#[derive(Copy, Clone)]
struct RawPacketData {
    payload: [u8; 4],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

#[map(name = "PACKET_MAP")]
static mut PACKETS: HashMap<u32, [u8; 16]> = HashMap::with_max_entries(1024, 0);

static mut PACKET_COUNT: u32 = 0;

const SIGNATURE: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

#[xdp]
pub fn stealthbpf(ctx: XdpContext) -> u32 {
    match try_stealthbpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn try_stealthbpf(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let doff_byte = unsafe { *(tcphdr as *const u8).add(12) };
    let tcp_header_len = ((doff_byte >> 4) as usize) * 4;

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len;
    let payload = match ptr_at::<[u8; 4]>(&ctx, payload_offset) {
        Ok(p) => p,
        Err(_) => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if unsafe { *payload } != SIGNATURE {
        return Ok(xdp_action::XDP_PASS);
    }

    unsafe {
        let ipv4 = &*ipv4hdr;
        let tcp = &*tcphdr;

        let packet_data = RawPacketData {
            payload: *payload,
            src_ip: u32::from_be(ipv4.src_addr),
            dst_ip: u32::from_be(ipv4.dst_addr),
            src_port: u16::from_be(tcp.source),
            dst_port: u16::from_be(tcp.dest),
        };

        let key = PACKET_COUNT;
        PACKET_COUNT += 1;

        // Convert struct to bytes
        let bytes = core::mem::transmute::<RawPacketData, [u8; 16]>(packet_data);

        if let Ok(_) = PACKETS.insert(&key, &bytes, 0) {
            info!(&ctx, "Stored packet data at index {}", key);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
