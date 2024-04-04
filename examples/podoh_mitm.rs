use std::convert::TryInto;

use argh::FromArgs;
use http::header::{CONTENT_LENGTH, HOST};
use http::Request;
use hyper::{body::Bytes, service::Service};
use http::Response;

use hyper::Body;
use rand::rngs::StdRng;
use rand::SeedableRng;
use reqwest::Url;
use third_wheel::*;
use odoh_rs::{compose, decrypt_query, parse, ObliviousDoHKeyPair, ObliviousDoHMessage, ObliviousDoHMessageType};

const QUERY_PATH: &str = "/dns-query";

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
            let key_pair = ObliviousDoHKeyPair::new(&mut rng);

            let (mut req_parts, req_body) = req.into_parts();

            // Parse the query
            let body_bytes = hyper::body::to_bytes(req_body).await?.to_vec();      
            let mut data: Bytes = body_bytes.into();
            let old_len = data.len();
            let query: ObliviousDoHMessage = parse(&mut data).unwrap();
            // Decrypt the query
            let (plaintext, _) = decrypt_query(&query, &key_pair).unwrap();
            let mut comp_dns_msg = plaintext.dns_msg;
            // comp_dns_msg = [ next_url_is_proxy (1B) | next_url_len (1B) | next_url (?B) | msg_len (8B) | key_id (32B) | encrypted_msg | dummy ]
            // Reconstruct the next url
            let next_url_is_proxy = comp_dns_msg.split_to(1)[0] == 1;
            let next_url_len = comp_dns_msg.split_to(1)[0] as usize;
            let next_url = comp_dns_msg.split_to(next_url_len).to_vec();
            let next_url_str = std::str::from_utf8(&next_url).unwrap();
            // Reconstruct the message
            let key_id = comp_dns_msg.split_to(32);
            let msg_len = comp_dns_msg.split_to(8).to_vec();
            let msg_len = u64::from_be_bytes(msg_len.try_into().unwrap()) as usize;
            let encrypted_msg = comp_dns_msg.split_to(msg_len);

            // Reconstruct the query
            let msg = ObliviousDoHMessage {
                msg_type: ObliviousDoHMessageType::Query,
                key_id: key_id,
                encrypted_msg: encrypted_msg
            };
            let query_body = compose(&msg).unwrap().freeze();
            println!("PROXY: {}, OLD_LEN: {}, NEW_LEN: {}, TARGET = {}", proxy_label, old_len, query_body.len(), next_url_str);

            // If the next url is a proxy, route it to that proxy
            let response = if next_url_is_proxy {
                // Remove constant proxy header
                req_parts.headers.remove(HOST);
                req_parts.headers.remove(CONTENT_LENGTH);

                // Send the package to dummy target via another proxy
                let proxy = reqwest::Proxy::https(next_url_str).unwrap();
                let client = reqwest::Client::builder()
                    .proxy(proxy)
                    .danger_accept_invalid_certs(true)
                    .build().unwrap();
                let mut blind = Url::parse("https://www.google.com").unwrap();
                blind.set_path(QUERY_PATH);
                let builder = {
                    client.post(blind).headers(req_parts.headers)
                };
                let raw_resp = builder.body(query_body.to_vec()).send().await.unwrap();
                let status = raw_resp.status();
                let version = raw_resp.version();
                let headers = raw_resp.headers().clone();
                let raw_resp = raw_resp.bytes().await.unwrap();
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
                // Reconstruct the header to match the new content length
                req_parts.headers.insert(HOST, next_url_str.parse().unwrap());
                req_parts.headers.insert(CONTENT_LENGTH, query_body.len().to_string().parse().unwrap());
                let body = Body::from(query_body);
                let req = Request::<Body>::from_parts(req_parts, body);
                third_wheel.call(req).await?
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
