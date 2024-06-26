use argh::FromArgs;
use http::Request;
use hyper::service::Service;

use hyper::Body;
use third_wheel::*;
use std::time::Instant;

/// Run a TLS mitm proxy that does no modification to the traffic
#[derive(FromArgs)]
struct StartMitm {
    /// port to bind proxy to
    #[argh(option, short = 'p', default = "8080")]
    port: u16,

    /// pem file for self-signed certificate authority certificate
    #[argh(option, short = 'c', default = "\"ca/ca_certs/cert.pem\".to_string()")]
    cert_file: String,

    /// pem file for private signing key for the certificate authority
    #[argh(option, short = 'k', default = "\"ca/ca_certs/key.pem\".to_string()")]
    key_file: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files_with_passphrase_on_key(
        &args.cert_file,
        &args.key_file,
        "third-wheel",
    )?;
    let trivial_mitm = mitm_layer(|req: Request<Body>, mut third_wheel: ThirdWheel| {
        let fut = async move {
            let init_timer = Instant::now();

            let (req_parts, req_body) = req.into_parts();

            // Parse the query
            let body_bytes = hyper::body::to_bytes(req_body).await?.to_vec();
            let len = body_bytes.len();
            println!("LEN: {}", len);


            let body = Body::from(body_bytes);
            let req = Request::<Body>::from_parts(req_parts, body);

            let parse_timer = init_timer.elapsed();
            println!("PDT: {:.4?}", parse_timer);
            let response = third_wheel.call(req).await?;
            Ok(response)
        };
        Box::pin(fut)
    });
    let mitm_proxy = MitmProxy::builder(trivial_mitm, ca).build();
    let (_, mitm_proxy_fut) = mitm_proxy.bind(format!("127.0.0.1:{}", args.port).parse().unwrap());
    mitm_proxy_fut.await.unwrap();
    Ok(())
}
