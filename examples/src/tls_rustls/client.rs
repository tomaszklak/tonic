//! This examples shows how you can combine `hyper-rustls` and `tonic` to
//! provide a custom `ClientConfig` for the tls configuration.

pub mod pb {
    tonic::include_proto!("/grpc.examples.unaryecho");
}

use hyper::Uri;
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use pb::{echo_client::EchoClient, EchoRequest};
use std::sync::Arc;
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{pem::PemObject as _, CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        // telio_log_debug!("verify_server_cert called");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn wrap_connector<H>(conn: H) -> HttpsConnector<H> {
    let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];

    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
        .with_no_client_auth();

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http2()
        .wrap_connector(conn)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let data_dir = std::path::PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "data"]);
    let fd = std::fs::File::open(data_dir.join("tls/ca.pem"))?;

    let mut roots = RootCertStore::empty();

    let mut buf = std::io::BufReader::new(&fd);
    let certs = CertificateDer::pem_reader_iter(&mut buf).collect::<Result<Vec<_>, _>>()?;
    roots.add_parsable_certificates(certs.into_iter());

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    // We have to do some wrapping here to map the request type from
    // `https://example.com` -> `https://[::1]:50051` because `rustls`
    // doesn't accept ip's as `ServerName`.
    let connector = tower::ServiceBuilder::new()
        .map_request(|_: Uri| Uri::from_static("https://[::1]:50051"))
        .layer_fn(move |s| wrap_connector(s))
        .service(http);

    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(connector);

    // Using `with_origin` will let the codegenerated client set the `scheme` and
    // `authority` from the provided `Uri`.
    let uri = Uri::from_static("https://example.com");
    let mut client = EchoClient::with_origin(client, uri);

    let request = tonic::Request::new(EchoRequest {
        message: "hello".into(),
    });

    let response = client.unary_echo(request).await?;

    println!("RESPONSE={response:?}");

    Ok(())
}
