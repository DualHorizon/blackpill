use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::HashMap;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;
use std::fs;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    iface: Option<String>,
}

async fn attach_to_interface(program: &mut Xdp, iface: &str) -> anyhow::Result<()> {
    program.attach(iface, XdpFlags::default())
        .context(format!("failed to attach XDP program to {}", iface))?;
    info!("Attached XDP program to interface {}", iface);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stealthbpf"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut packet_map: HashMap<_, u32, [u8; 16]> = HashMap::try_from(
        ebpf.map_mut("PACKET_MAP").context("error getting packet map")?
    )?;

    packet_map.pin("/sys/fs/bpf/packet_map")?;
    info!("Pinned packet map to /sys/fs/bpf/packet_map");

    let program: &mut Xdp = ebpf.program_mut("stealthbpf").unwrap().try_into()?;
    program.load()?;

    if let Some(iface) = opt.iface {
        attach_to_interface(program, &iface).await?;
    } else {
        let interfaces = fs::read_dir("/sys/class/net")?;
        for interface in interfaces {
            let iface = interface?.file_name();
            let iface_name = iface.to_string_lossy();
            if iface_name != "lo" {
                if let Err(e) = attach_to_interface(program, &iface_name).await {
                    warn!("Failed to attach to {}: {}", iface_name, e);
                }
            }
        }
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;

    fs::remove_file("/sys/fs/bpf/packet_map").ok();
    println!("Exiting...");
    Ok(())
}
