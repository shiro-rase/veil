use anyhow::Result;
use std::fs;
use std::path::PathBuf;

pub struct ServiceInstaller;

impl ServiceInstaller {
    pub fn install_systemd(role: &str, config_path: &str) -> Result<()> {
        let exe_path = std::env::current_exe()?;
        let abs_config = PathBuf::from(config_path).canonicalize().unwrap_or_else(|_| PathBuf::from(config_path));

        let unit_content = format!(
            "[Unit]\nDescription=Veil Overlay Network ({role})\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} {role} --config {}\nRestart=always\nRestartSec=3\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n",
            exe_path.display(),
            abs_config.display()
        );

        let unit_path = format!("/etc/systemd/system/veil-{role}.service");
        fs::write(&unit_path, unit_content)?;
        println!("Systemd unit created: {}", unit_path);
        println!("Run the following to start and enable:");
        println!("  sudo systemctl daemon-reload");
        println!("  sudo systemctl enable --now veil-{role}");
        Ok(())
    }
}
