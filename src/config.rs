use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub domain: String,
    pub proxy_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub network_secret: String,
    pub control_server: String,
    #[serde(default = "default_ingress_bind")]
    pub ingress_bind: String,
    pub routes: Vec<RouteConfig>,
    pub web_bind: Option<String>,
    pub web_domain: Option<String>,
    pub cert_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    pub network_secret: String,
    pub control_server: String,
    #[serde(default = "default_dns_bind")]
    pub dns_bind: String,
    #[serde(default = "default_upstream_dns")]
    pub upstream_dns: String,
    #[serde(default = "default_client_http_bind")]
    pub local_http_bind: String,
    pub socks5_bind: Option<String>,
    pub exit_node: Option<String>,
    pub tun_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    #[serde(default = "default_control_bind")]
    pub bind_addr: String,
    pub network_secret: String,
    #[serde(default = "default_virtual_subnet")]
    pub virtual_subnet: String,
    pub acls: Option<Vec<crate::acl::AclRule>>,
    pub decoy_addr: Option<String>,
    pub web_addr: Option<String>,
}

fn default_ingress_bind() -> String {
    "0.0.0.0:80".to_string()
}

fn default_dns_bind() -> String {
    "127.0.0.1:5353".to_string()
}

fn default_upstream_dns() -> String {
    "1.1.1.1:53".to_string()
}

fn default_client_http_bind() -> String {
    "127.0.0.1:80".to_string()
}

fn default_control_bind() -> String {
    "0.0.0.0:4242".to_string()
}

fn default_virtual_subnet() -> String {
    "10.42.0.0/24".to_string()
}

impl NodeConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let cfg: Self = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }

    pub fn sample() -> Self {
        Self {
            node_id: "vps-main".to_string(),
            network_secret: "change-this-to-a-secure-secret-token".to_string(),
            control_server: "1.2.3.4:4242".to_string(),
            ingress_bind: "0.0.0.0:80".to_string(),
            routes: vec![
                RouteConfig {
                    domain: "hui.hui.hui".to_string(),
                    proxy_to: "127.0.0.1:3000".to_string(),
                },
                RouteConfig {
                    domain: "vpss2.myhost".to_string(),
                    proxy_to: "127.0.0.1:8080".to_string(),
                },
            ],
            web_bind: Some("0.0.0.0:8443".to_string()),
            web_domain: None,
            cert_dir: Some("/etc/veil/certs".to_string()),
        }
    }
}

impl ClientConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let cfg: Self = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }

    pub fn sample() -> Self {
        Self {
            client_id: "laptop-dev".to_string(),
            network_secret: "change-this-to-a-secure-secret-token".to_string(),
            control_server: "1.2.3.4:4242".to_string(),
            dns_bind: "127.0.0.1:5353".to_string(),
            upstream_dns: "1.1.1.1:53".to_string(),
            local_http_bind: "127.0.0.1:80".to_string(),
            socks5_bind: Some("127.0.0.1:1080".to_string()),
            exit_node: None,
            tun_enabled: Some(true),
        }
    }
}

impl ControlConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let cfg: Self = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }

    pub fn sample() -> Self {
        Self {
            bind_addr: "0.0.0.0:4242".to_string(),
            network_secret: "change-this-to-a-secure-secret-token".to_string(),
            virtual_subnet: "10.42.0.0/24".to_string(),
            acls: Some(vec![crate::acl::AclRule {
                client: "*".to_string(),
                allow: vec!["*".to_string()],
            }]),
            decoy_addr: Some("1.1.1.1:443".to_string()),
            web_addr: Some("0.0.0.0:9090".to_string()),
        }
    }
}
