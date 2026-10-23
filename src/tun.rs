use anyhow::{anyhow, Result};
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.file.read(buf).await?;
        Ok(n)
    }

    pub async fn write_packet(&mut self, buf: &[u8]) -> Result<()> {
        self.file.write_all(buf).await?;
        Ok(())
    }

    pub fn configure_dns(&self, domains: &[String]) {
        let mut domain_args = vec!["domain", &self.name];
        let prefixed: Vec<String> = domains.iter().map(|d| format!("~{}", d)).collect();
        for d in &prefixed {
            domain_args.push(d.as_str());
        }
        let _ = Command::new("resolvectl").args(["dns", &self.name, "127.0.0.1:5353"]).status();
        let _ = Command::new("resolvectl").args(&domain_args).status();
    }

    pub fn sync_hosts(routes: &[crate::proto::RouteEntry]) -> Result<()> {
        let path = "/etc/hosts";
        let content = fs::read_to_string(path).unwrap_or_default();
        let filtered_lines: Vec<&str> = content
            .lines()
            .filter(|l| !l.contains("#veil-managed"))
            .collect();

        let mut additions = Vec::new();
        for r in routes {
            additions.push(format!("{}\t{} #veil-managed", r.virtual_ip, r.domain));
        }

        let mut new_content = filtered_lines.join("\n");
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        for add in additions {
            new_content.push_str(&add);
            new_content.push('\n');
        }

        let _ = fs::write(path, new_content);
        Ok(())
    }

    pub fn setup_exit_node_routes(control_host: &str, tun_name: &str) -> Result<()> {
        let control_ip = control_host.split(':').next().unwrap_or(control_host);
        let output = Command::new("ip").args(["route", "show", "default"]).output()?;
        let out_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = out_str.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|&x| x == "via") {
            if let Some(gw) = parts.get(pos + 1) {
                let _ = Command::new("ip")
                    .args(["route", "add", control_ip, "via", gw])
                    .status();
            }
        }

        let _ = Command::new("ip")
            .args(["route", "add", "default", "dev", tun_name, "metric", "10"])
            .status();

        Ok(())
    }

    pub fn restore_routes(control_host: &str, tun_name: &str) {
        let control_ip = control_host.split(':').next().unwrap_or(control_host);
        let _ = Command::new("ip")
            .args(["route", "del", "default", "dev", tun_name, "metric", "10"])
            .status();
        let _ = Command::new("ip")
            .args(["route", "del", control_ip])
            .status();
    }

    pub fn enable_exit_node_forwarding() -> Result<()> {
        let _ = Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .status();
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-s", "10.42.0.0/24", "-j", "MASQUERADE"])
            .status();
        let _ = Command::new("iptables")
            .args(["-A", "FORWARD", "-s", "10.42.0.0/24", "-j", "ACCEPT"])
            .status();
        let _ = Command::new("iptables")
            .args(["-A", "FORWARD", "-d", "10.42.0.0/24", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            .status();
        Ok(())
    }
}
