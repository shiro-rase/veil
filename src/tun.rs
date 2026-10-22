use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::fs::File;

pub struct TunDevice {
    pub name: String,
    pub file: File,
    pub ip: Ipv4Addr,
}

impl TunDevice {
    #[cfg(target_os = "linux")]
    pub fn create(name: &str, ip: Ipv4Addr) -> Result<Self> {
        use std::os::fd::FromRawFd;

        const TUNSETIFF: u64 = 0x400454ca;
        const IFF_TUN: i16 = 0x0001;
        const IFF_NO_PI: i16 = 0x1000;

        #[repr(C)]
        struct Ifreq {
            ifr_name: [u8; 16],
            ifr_flags: i16,
            _padding: [u8; 22],
        }

        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(anyhow!("Failed to open /dev/net/tun. Are you root/CAP_NET_ADMIN?"));
        }

        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0u8; 22],
        };

        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc::ioctl(fd, TUNSETIFF as libc::c_ulong, &ifr) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow!("ioctl TUNSETIFF failed on interface {}", name));
        }

        let std_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let tokio_file = File::from_std(std_file);

        let ip_str = format!("{}/24", ip);
        let _ = Command::new("ip").args(["addr", "add", &ip_str, "dev", name]).status();
        let _ = Command::new("ip").args(["link", "set", "dev", name, "up"]).status();

        Ok(Self {
            name: name.to_string(),
            file: tokio_file,
            ip,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(name: &str, ip: Ipv4Addr) -> Result<Self> {
        Err(anyhow!(
            "TUN device creation for {} ({}) requires Linux with CAP_NET_ADMIN",
            name,
            ip
        ))
    }
}
