use anyhow::Context as _;
use aya::maps::xdp::CpuMap;
use aya::programs::{Xdp, XdpFlags};
use aya::util::nr_cpus;
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

    let nr_cpus = nr_cpus().map_err(|e| anyhow::anyhow!("failed to get number of CPUs: {:?}", e))? as u32;
    let mut cpumap = CpuMap::try_from(ebpf.map_mut("CPUS").unwrap())?;
    let flags = 0;
    let queue_size = 2048;
    for i in 0..nr_cpus {
        cpumap.set(i, queue_size, None, flags)?;
    }

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
    println!("Exiting...");
    Ok(())
}
