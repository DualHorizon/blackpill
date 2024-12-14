#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::CpuMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[map(name = "CPUS")]
static mut CPUS: CpuMap = CpuMap::with_max_entries(64, 0);

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
    // Parse Ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Parse IPv4 header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse TCP header
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    // Get the TCP header length from the 13th byte
    // Direct access to the byte containing data offset
    let doff_byte = unsafe { *(tcphdr as *const u8).add(12) };
    let tcp_header_len = ((doff_byte >> 4) as usize) * 4;

    // Verify minimum TCP header length
    if tcp_header_len < 20 {
        info!(&ctx, "Invalid TCP header length: {}", tcp_header_len);
        return Ok(xdp_action::XDP_PASS);
    }

    // Calculate payload offset considering variable TCP header length
    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len;

    // Try to get 4 bytes of payload
    let payload = match ptr_at::<[u8; 4]>(&ctx, payload_offset) {
        Ok(p) => p,
        Err(_) => {
            info!(&ctx, "Packet too short for payload check");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // Check payload content
    if unsafe { *payload } != SIGNATURE {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "received packet with signature");
    let payload_u32 = u32::from_ne_bytes(unsafe { *payload });
    info!(&ctx, "Payload (u32): 0x{:x}", payload_u32);

    // Handle CPU redirection
    let result = unsafe {
        let cpus = &raw mut CPUS;
        (*cpus).redirect(0, 0)
    };

    match result {
        Ok(action) => Ok(action),
        Err(_) => Ok(xdp_action::XDP_PASS),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
