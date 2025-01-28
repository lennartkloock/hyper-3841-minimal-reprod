use std::{fs, io, sync::Arc};

use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[tokio::main]
async fn main() {
    let server_config = get_server_config();

    let listener = tokio::net::TcpListener::bind("[::]:443").await.unwrap();
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    loop {
        let (tcp_stream, _addr) = match listener.accept().await {
            Ok((stream, addr)) => (stream, addr),
            Err(err) => {
                eprintln!("failed to accept connection: {}", err);
                continue;
            }
        };
        println!("accepted tcp connection");

        let stream = match tls_acceptor.accept(tcp_stream).await {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("failed to accept TLS connection: {}", err);
                continue;
            }
        };

        println!("accepted tls connection");
        let io = TokioIo::new(stream);

        // You can manually read the preface here
        // let mut buf = [0; 24];
        // let mut buf = ReadBuf::new(&mut buf);
        // let read = poll_fn(|cx| Pin::new(&mut io).poll_read(cx, buf.unfilled())).await;
        // tracing::info!("buf {:?} ({})", buf.filled(), String::from_utf8_lossy(buf.filled()));

        let hyper_service = hyper::service::service_fn(
            move |req: hyper::Request<hyper::body::Incoming>| async move {
                println!("got request {:?}", req);
                Ok::<_, hyper::Error>(hyper::Response::new("Hello, World!".to_string()))
            },
        );

        tokio::spawn(async move {
            println!("handling connection");
            let res = auto::Builder::new(TokioExecutor::new())
                .http1()
                .timer(TokioTimer::new())
                .http2()
                .timer(TokioTimer::new())
                .serve_connection(io, hyper_service)
                .await;

            println!("connection closed: {:?}", res);
        });
    }
}

pub fn get_server_config() -> rustls::ServerConfig {
    rustls::crypto::aws_lc_rs::default_provider().install_default().unwrap();

    let certs = load_certs("fullchain.pem").unwrap();
    let key = load_private_key("privkey.pem").unwrap();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_config.max_early_data_size = u32::MAX;
    server_config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"http/1.0".to_vec(),
    ];

    server_config
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    // Open certificate file.
    let certfile = fs::File::open(filename).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to open {}: {}", filename, e),
        )
    })?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    rustls_pemfile::certs(&mut reader).collect()
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    // Open keyfile.
    let keyfile = fs::File::open(filename).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to open {}: {}", filename, e),
        )
    })?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("no private key found in {}", filename),
        )
    })
}
