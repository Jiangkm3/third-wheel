use argh::FromArgs;
use http::header::{CONTENT_LENGTH, HOST};
use http::Request;
use hyper::{body::Bytes, service::Service};
use http::Response;

use hyper::Body;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use reqwest::Url;
use third_wheel::*;

use std::time::Instant;

const QUERY_PATH: &str = "/dns-query";
const NUM_PROXIES: usize = 16;

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
    let port = args.port;
    let podoh_mitm = mitm_layer(move |req: Request<Body>, mut third_wheel: ThirdWheel| {
        let proxy_label: u64 = (port - 8080).into();
        let fut = async move {
            let mut rng = StdRng::seed_from_u64(proxy_label);
            let init_timer = Instant::now();

            let (mut req_parts, req_body) = req.into_parts();

            // Parse the query
            let mut body_bytes = hyper::body::to_bytes(req_body).await?.to_vec();
            let num_hops_remaining = body_bytes[0] - 1;
            body_bytes[0] = num_hops_remaining;
            let mut query_body: Bytes = body_bytes.into();

            // If the next url is a proxy, route it to that proxy
            let response = if num_hops_remaining > 0 {
                // Remove constant proxy header
                req_parts.headers.remove(HOST);
                req_parts.headers.remove(CONTENT_LENGTH);

                // Sample the next proxy
                let next_proxy = format!("http://localhost:{}", 8080 + rng.next_u32() as usize % NUM_PROXIES);

                // Send the package to dummy target via another proxy
                let proxy = reqwest::Proxy::https(next_proxy).unwrap();
                let client = reqwest::Client::builder()
                    .proxy(proxy)
                    .danger_accept_invalid_certs(true)
                    .build().unwrap();
                let mut blind = Url::parse("https://odoh.cloudflare-dns.com").unwrap();
                blind.set_path(QUERY_PATH);
                let parse_timer = init_timer.elapsed();
                println!("PDT: {:.4?}", parse_timer);

                let builder = {
                    client.post(blind).headers(req_parts.headers)
                };

                let raw_resp = builder.body(query_body).send().await.unwrap();
                let status = raw_resp.status();
                let version = raw_resp.version();
                let headers = raw_resp.headers().clone();
                let raw_resp = raw_resp.bytes().await.unwrap().to_vec();
                let resp_len = raw_resp.len();

                let response = Response::new(Body::from(raw_resp));

                // println!("REP_RAW: {:?}", response);
                let (mut parts, body) = response.into_parts();
                parts.status = status;
                parts.version = version;
                parts.headers = headers;
                parts.headers.insert(CONTENT_LENGTH, resp_len.to_string().parse().unwrap());
                // parts.extensions = raw_resp.extensions().clone();
                Response::from_parts(parts, body)
            } 
            // Otherwise send the message to the target
            else {
                let _ = query_body.split_to(1);
                req_parts.headers.insert(CONTENT_LENGTH, query_body.len().to_string().parse().unwrap());
                
                let body = Body::from(query_body);
                let req = Request::<Body>::from_parts(req_parts, body);
                let parse_timer = init_timer.elapsed();
                println!("PDT: {:.4?}", parse_timer);

                let response = third_wheel.call(req).await?;
                
                let (mut rep_parts, rep_body) = response.into_parts();
                let body_bytes = hyper::body::to_bytes(rep_body).await?.to_vec();
                // Add parse time to the response message
                let raw_resp: Bytes = body_bytes.into();
                let resp_len = raw_resp.len();
                rep_parts.headers.insert(CONTENT_LENGTH, resp_len.to_string().parse().unwrap());
                Response::from_parts(rep_parts, Body::from(raw_resp))
            };
            Ok(response)
        };
        Box::pin(fut)
    });
    let mitm_proxy = MitmProxy::builder(podoh_mitm, ca).build();
    let (_, mitm_proxy_fut) = mitm_proxy.bind(format!("127.0.0.1:{}", args.port).parse().unwrap());
    mitm_proxy_fut.await.unwrap();
    Ok(())
}
