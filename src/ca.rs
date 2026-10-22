use anyhow::Result;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair};
use std::fs;
use std::path::Path;

pub struct CertificateAuthority;

impl CertificateAuthority {
    pub fn generate_ca<P: AsRef<Path>>(out_dir: P) -> Result<()> {
        let dir = out_dir.as_ref();
        fs::create_dir_all(dir)?;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Veil Root Certificate Authority");
        dn.push(DnType::OrganizationName, "Veil Network");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let keypair = KeyPair::generate()?;
        let cert = params.self_signed(&keypair)?;

        fs::write(dir.join("veil-ca.crt"), cert.pem())?;
        fs::write(dir.join("veil-ca.key"), keypair.serialize_pem())?;
        println!("Veil Root CA generated at: {}", dir.display());
        Ok(())
    }

    pub fn generate_domain_cert<P: AsRef<Path>>(
        domains: &[String],
        out_dir: P,
    ) -> Result<()> {
        let dir = out_dir.as_ref();
        fs::create_dir_all(dir)?;

        let mut ca_params = CertificateParams::default();
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "Veil Root Certificate Authority");
        ca_dn.push(DnType::OrganizationName, "Veil Network");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_keypair = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_keypair)?;
        let issuer = Issuer::from_params(&ca_params, &ca_keypair);

        let mut params = CertificateParams::new(domains.to_vec())?;
        let mut dn = DistinguishedName::new();
        let primary_domain = domains.first().map(|s| s.as_str()).unwrap_or("veil.internal");
        dn.push(DnType::CommonName, primary_domain);
        params.distinguished_name = dn;

        let cert_keypair = KeyPair::generate()?;
        let cert = params.signed_by(&cert_keypair, &issuer)?;

        fs::write(dir.join(format!("{}.crt", primary_domain)), cert.pem())?;
        fs::write(dir.join(format!("{}.key", primary_domain)), cert_keypair.serialize_pem())?;
        fs::write(dir.join("veil-ca.crt"), ca_cert.pem())?;
        println!("Domain certificate for {:?} generated at: {}", domains, dir.display());
        Ok(())
    }
}
