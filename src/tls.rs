// SPDX-License-Identifier: Apache-2.0
use crate::Result;
use sha2::{Digest, Sha256};
use spiffe::{SpiffeId, cert::spiffe_id_from_der};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::{
    self, ClientConfig, DigitallySignedStruct, Error, RootCertStore, ServerConfig, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::{NoServerSessionStorage, ParsedCertificate, WebPkiClientVerifier},
};

pub struct Credentials {
    pub id: SpiffeId,
    pub generation: [u8; 32],
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    roots: Arc<RootCertStore>,
}

impl Credentials {
    pub fn load(path: &Path) -> Result<Self> {
        let pem = std::fs::read(path)?;
        let mut certs = CertificateDer::pem_slice_iter(&pem);
        let certificate = certs.next().ok_or("missing workload certificate")??;
        let mut roots = RootCertStore::empty();
        for root in certs {
            roots.add(root?)?;
        }
        if roots.is_empty() {
            return Err("missing trust bundle".into());
        }
        let key = PrivateKeyDer::from_pem_slice(&pem)?;
        let provider = CryptoProvider::get_default().expect("TLS provider installed");
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(&certificate)?,
            &roots,
            &[],
            UnixTime::now(),
            provider.signature_verification_algorithms.all,
        )?;
        Ok(Self {
            id: spiffe_id_from_der(certificate.as_ref())?,
            generation: Sha256::digest(&pem).into(),
            certificate,
            key,
            roots: Arc::new(roots),
        })
    }

    pub fn server(&self) -> Result<ServerConfig> {
        let verifier = WebPkiClientVerifier::builder(self.roots.clone()).build()?;
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![self.certificate.clone()], self.key.clone_key())?;
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(config)
    }

    pub fn client(&self, allowed: Arc<BTreeSet<SpiffeId>>) -> Result<ClientConfig> {
        let verifier = Arc::new(ServerIdentity {
            roots: self.roots.clone(),
            provider: CryptoProvider::get_default()
                .expect("TLS provider installed")
                .clone(),
            allowed,
        });
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![self.certificate.clone()], self.key.clone_key())?;
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_sni = false;
        Ok(config)
    }
}

#[derive(Debug)]
struct ServerIdentity {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    allowed: Arc<BTreeSet<SpiffeId>>,
}

impl ServerCertVerifier for ServerIdentity {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(certificate)?,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        let id = spiffe_id_from_der(certificate.as_ref())
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if !self.allowed.contains(&id) {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
