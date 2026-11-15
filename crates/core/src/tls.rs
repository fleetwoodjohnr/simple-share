//! The local certificate authority behind every connection.
//!
//! Phones that "pair" install this CA once and then get a verified, warning-free
//! HTTPS connection. The CA is name-constrained: it can only vouch for private
//! IP addresses and for this computer's one `.local` name, so even a stolen CA
//! key cannot impersonate a website, or any other device's `.local` name, to a
//! paired phone. Unpaired "guest" phones still get an encrypted connection
//! after the browser's warning.

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair,
    KeyUsagePurpose, NameConstraints, SanType,
};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

const KEY_FILE: &str = "ca-key.pem";
const CERT_FILE: &str = "ca.cer";

pub struct Ca {
    key: KeyPair,
    /// Exactly what phones install; persisted so the fingerprint never changes.
    pub der: Vec<u8>,
    label: String,
}

/// A new random `.local` label: 9 characters without look-alikes (0 o 1 l i).
pub fn new_label() -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut out = String::new();
    while out.len() < 9 {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("the OS random number generator failed");
        // 248 = 8 × 31: rejecting larger bytes keeps every character equally likely.
        out.extend(b.iter().filter(|&&x| x < 248).map(|&x| ALPHABET[usize::from(x) % ALPHABET.len()] as char));
        out.truncate(9);
    }
    out
}

/// `label` → `label.local`, the only DNS name the CA may vouch for.
pub fn local_name(label: &str) -> String {
    format!("{label}.local")
}

/// The CA's identity. Rebuilt to sign leaves: a leaf names its issuer by
/// subject and key identifier, both of which depend only on the subject and the
/// key, so leaves chain to the persisted certificate.
fn ca_params(label: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Simple Share local certificate");
    dn.push(DnType::OrganizationName, "Simple Share");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let v4 = |a: [u8; 4], m: [u8; 4]| GeneralSubtree::IpAddress(CidrSubnet::V4(a, m));
    let v6 = |prefix: u16, bits: u32| {
        let mut a = [0u8; 16];
        a[..2].copy_from_slice(&prefix.to_be_bytes());
        GeneralSubtree::IpAddress(CidrSubnet::V6(a, (u128::MAX << (128 - bits)).to_be_bytes()))
    };
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            v4([10, 0, 0, 0], [255, 0, 0, 0]),
            v4([172, 16, 0, 0], [255, 240, 0, 0]),
            v4([192, 168, 0, 0], [255, 255, 0, 0]),
            v4([100, 64, 0, 0], [255, 192, 0, 0]), // carrier-grade NAT, used by some ISPs' home networks
            v4([169, 254, 0, 0], [255, 255, 0, 0]),
            v4([127, 0, 0, 0], [255, 0, 0, 0]),
            v6(0xfc00, 7),
            v6(0xfe80, 10),
            // Exactly this computer's name: no website, no other `.local` device.
            GeneralSubtree::DnsName(local_name(label)),
        ],
        excluded_subtrees: Vec::new(),
    });
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(3650);
    p
}

/// Is this an address the CA can vouch for (and so one we may share on)?
pub fn is_permitted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            v6.is_loopback() || s & 0xfe00 == 0xfc00 || s & 0xffc0 == 0xfe80
        }
    }
}

impl Ca {
    /// Load the CA for `label.local` from `dir`. A CA made for another name
    /// (or by Simple Share 0.1, which named none) cannot vouch for this one,
    /// so it is replaced.
    pub fn load_or_create(dir: &Path, label: &str) -> Result<Self, Error> {
        let (key_path, cert_path) = (dir.join(KEY_FILE), dir.join(CERT_FILE));
        if let (Ok(pem), Ok(der)) = (std::fs::read_to_string(&key_path), std::fs::read(&cert_path)) {
            // The name sits in the certificate verbatim, as an IA5String in its name constraints.
            let name = local_name(label);
            if der.windows(name.len()).any(|w| w == name.as_bytes()) {
                return Ok(Self { key: KeyPair::from_pem(&pem)?, der, label: label.into() });
            }
        }
        Self::create(dir, label)
    }

    /// A brand-new CA. Phones paired with the old one will see the warning
    /// again until they install the new certificate.
    pub fn create(dir: &Path, label: &str) -> Result<Self, Error> {
        std::fs::create_dir_all(dir)?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let der = ca_params(label).self_signed(&key)?.der().to_vec();
        write_private(&dir.join(KEY_FILE), key.serialize_pem().as_bytes())?;
        std::fs::write(dir.join(CERT_FILE), &der)?;
        Ok(Self { key, der, label: label.into() })
    }

    /// The `label` in `label.local` this CA vouches for.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// SHA-256 of the CA certificate, as iOS shows it under the profile's
    /// "More Details": hex pairs separated by spaces.
    pub fn fingerprint(&self) -> String {
        Sha256::digest(&self.der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
    }

    /// A fresh server certificate and key for `label.local` and `ip`, valid for 30 days.
    pub fn issue(&self, ip: IpAddr) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let issuer = ca_params(&self.label).self_signed(&self.key)?;
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Simple Share");
        p.distinguished_name = dn;
        p.subject_alt_names = vec![SanType::DnsName(local_name(&self.label).try_into()?), SanType::IpAddress(ip)];
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        p.not_before = now - Duration::days(1);
        p.not_after = now + Duration::days(30);
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = p.signed_by(&key, &issuer, &self.key)?;
        Ok((cert.der().to_vec(), key.serialize_der()))
    }

    /// rustls config serving a fresh certificate for `ip`. TLS 1.3 only: every
    /// browser that can run the phone page has it, and it leaves nothing to downgrade to.
    pub fn server_config(&self, ip: IpAddr) -> Result<Arc<rustls::ServerConfig>, Error> {
        let (cert, key) = self.issue(ip)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.into()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key)),
            )?;
        Ok(Arc::new(cfg))
    }
}

/// Write a file only its owner can read (0600 on Unix).
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("simple-share-tls-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Verify `leaf` as a TLS server certificate for `name`, trusting only `ca`.
    fn verify(ca: &[u8], leaf: &[u8], name: &str) -> Result<(), webpki::Error> {
        let ca = CertificateDer::from(ca.to_vec());
        let anchor = webpki::anchor_from_trusted_cert(&ca)?;
        let leaf = CertificateDer::from(leaf.to_vec());
        let cert = webpki::EndEntityCert::try_from(&leaf)?;
        cert.verify_for_usage(webpki::ALL_VERIFICATION_ALGS, &[anchor], &[], UnixTime::now(), webpki::KeyUsage::server_auth(), None, None)?;
        cert.verify_is_valid_for_subject_name(&ServerName::try_from(name).map_err(|_| webpki::Error::BadDer)?)
    }

    /// Sign an arbitrary leaf with the CA's key, as an attacker holding a
    /// stolen key would.
    fn forge(ca: &Ca, san: SanType) -> Vec<u8> {
        let issuer = ca_params(&ca.label).self_signed(&ca.key).expect("issuer");
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![san];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        p.signed_by(&key, &issuer, &ca.key).expect("sign").der().to_vec()
    }

    fn dns(name: &str) -> SanType {
        SanType::DnsName(name.try_into().expect("dns"))
    }

    #[test]
    fn leaf_for_the_local_name_and_a_lan_address_chains_to_the_persisted_ca() {
        let dir = tmp("chain");
        let ca = Ca::create(&dir, "k7m3x9p2q").expect("create");
        let (leaf, _) = ca.issue("192.168.1.20".parse().expect("ip")).expect("issue");
        verify(&ca.der, &leaf, "k7m3x9p2q.local").expect("valid for the name");
        verify(&ca.der, &leaf, "192.168.1.20").expect("valid for the address");
        // Your network's carrier-grade NAT range works too.
        let (leaf, _) = ca.issue("100.110.198.227".parse().expect("ip")).expect("issue");
        verify(&ca.der, &leaf, "100.110.198.227").expect("valid");
        assert!(verify(&ca.der, &leaf, "192.168.1.21").is_err(), "wrong address");
        assert!(verify(&ca.der, &leaf, "other.local").is_err(), "wrong name");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stolen_ca_key_cannot_impersonate_sites_or_other_local_devices() {
        let dir = tmp("constraints");
        let ca = Ca::create(&dir, "k7m3x9p2q").expect("create");
        let refused =
            |leaf: &[u8], name: &str| matches!(verify(&ca.der, leaf, name), Err(e) if format!("{e:?}").contains("NameConstraint"));
        assert!(refused(&forge(&ca, SanType::IpAddress("8.8.8.8".parse().expect("ip"))), "8.8.8.8"));
        assert!(refused(&forge(&ca, dns("www.apple.com")), "www.apple.com"));
        assert!(refused(&forge(&ca, dns("nas.local")), "nas.local"), "another device's .local name");
        assert!(refused(&forge(&ca, dns("k7m3x9p2q-2.local")), "k7m3x9p2q-2.local"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reloading_keeps_the_same_ca_and_still_signs() {
        let dir = tmp("reload");
        let first = Ca::create(&dir, "k7m3x9p2q").expect("create");
        let again = Ca::load_or_create(&dir, "k7m3x9p2q").expect("load");
        assert_eq!(first.fingerprint(), again.fingerprint());
        let (leaf, _) = again.issue("10.0.0.5".parse().expect("ip")).expect("issue");
        verify(&first.der, &leaf, "10.0.0.5").expect("leaf from reloaded CA chains to the original");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(KEY_FILE)).expect("key").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "CA key must be private");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_ca_for_another_name_is_replaced() {
        let dir = tmp("rename");
        let old = Ca::create(&dir, "k7m3x9p2q").expect("create");
        let new = Ca::load_or_create(&dir, "w4h8n2r6t").expect("load");
        assert_ne!(old.fingerprint(), new.fingerprint(), "a new address gets a new CA");
        let (leaf, _) = new.issue("10.0.0.5".parse().expect("ip")).expect("issue");
        verify(&new.der, &leaf, "w4h8n2r6t.local").expect("valid for the new name");
        assert_eq!(Ca::load_or_create(&dir, "w4h8n2r6t").expect("again").fingerprint(), new.fingerprint());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels_are_nine_unambiguous_characters() {
        let a = new_label();
        assert_eq!(a.len(), 9);
        assert!(a.chars().all(|c| "abcdefghjkmnpqrstuvwxyz23456789".contains(c)), "{a}");
        assert_ne!(a, new_label());
    }

    #[test]
    fn only_private_addresses_are_shareable() {
        for ok in ["192.168.0.2", "10.1.2.3", "172.20.0.1", "100.110.198.227", "fe80::1", "fd00::5"] {
            assert!(is_permitted(ok.parse().expect("ip")), "{ok}");
        }
        for bad in ["8.8.8.8", "100.128.0.1", "172.32.0.1", "2001:db8::1"] {
            assert!(!is_permitted(bad.parse().expect("ip")), "{bad}");
        }
    }
}
