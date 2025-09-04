//! This examples shows how you can combine `hyper-rustls` and `tonic` to
//! provide a custom `ClientConfig` for the tls configuration.

pub mod pb {
    tonic::include_proto!("/grpc.examples.unaryecho");
}

use hyper::Uri;
use hyper_rustls::HttpsConnector;
use hyper_util::rt::TokioIo;
use pb::{echo_client::EchoClient, EchoRequest};
use std::sync::Arc;
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use tonic::transport::{Channel, Endpoint};
use tower::{service_fn, util::ServiceFn};

// NOTE: In the real world certificate verification will have to stay custom
#[derive(Debug)]
struct CustomCertVerifier;

impl ServerCertVerifier for CustomCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
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

fn pq_https_connector<H>(conn: H) -> HttpsConnector<H> {
    let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];

    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CustomCertVerifier))
        .with_no_client_auth();

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http2()
        .wrap_connector(conn)
}

async fn use_custom_socket(uri: &str) -> anyhow::Result<Channel> {
    use tonic::transport::channel::ClientTlsConfig;

    let socket_factory = move |_: Uri| async move {
        // NOTE: Just a stub, in the real world socket creation is a complex custom code that needs to be used
        let socket = tokio::net::TcpSocket::new_v4()?;

        Ok::<_, std::io::Error>(TokioIo::new(dbg!(
            socket
                .connect(
                    format!("127.0.0.1:50051")
                        .parse()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
                )
                .await
        )?))
    };
    let tcp_service: ServiceFn<_> = service_fn(socket_factory);

    // TODO: Somehow use HttpConnector with the sockets producet by
    // let mut http = HttpConnector::new();
    // http.enforce_http(false);

    let https = pq_https_connector(tcp_service);

    Ok(Endpoint::try_from(uri.to_owned())?
        .tls_config(ClientTlsConfig::new())?
        .connect_with_connector(https)
        .await?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let channel = use_custom_socket("https://127.0.0.1:50051").await?;
    let mut client = EchoClient::new(channel);

    let request = tonic::Request::new(EchoRequest {
        message: "hello".into(),
    });

    let response = client.unary_echo(request).await?;

    println!("RESPONSE={response:?}");

    Ok(())
}
