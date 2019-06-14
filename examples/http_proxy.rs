extern crate http;
extern crate http_bytes;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use std::io::{Read, Write};

fn data_transfer(mut a: &std::net::TcpStream, mut b: &std::net::TcpStream) {
    let _ = std::io::copy(&mut a, &mut b);
    let _ = a.shutdown(std::net::Shutdown::Read);
    let _ = b.shutdown(std::net::Shutdown::Write);
}

fn data_transfer_bidirectional(a: &std::net::TcpStream, b: &std::net::TcpStream) -> Result<()> {
    let aa = a.try_clone()?; // needed to avoid crossbeam and friends
    let bb = b.try_clone()?; // this causes double FD usage although
    std::thread::spawn(move || data_transfer(&bb, &aa));
    data_transfer(a, b);
    Ok(())
}

fn handle_connect_request(
    mut c: &std::net::TcpStream,
    mut s: std::net::TcpStream,
    debt: &[u8],
) -> Result<()> {
    // We already connected to the server, so just need to reply with success
    // And go on connecting

    let response = http::Response::builder().body(())?; // 200 OK
    let response = http_bytes::response_header_to_vec(&response);
    c.write_all(&response[..])?;

    s.write_all(debt)?;
    data_transfer_bidirectional(c, &s)?;

    Ok(())
}

fn propagate_request_to_server(
    c: &std::net::TcpStream,
    mut s: std::net::TcpStream,
    request: http_bytes::Request,
    debt: &[u8],
) -> Result<()> {
    if request.method() == http::method::Method::CONNECT {
        return handle_connect_request(c, s, debt);
    }

    let request_header = http_bytes::request_header_to_vec(&request);

    s.write_all(&request_header[..])?;

    s.write_all(debt)?;
    data_transfer_bidirectional(c, &s)?;

    Ok(())
}

fn handle_client_request(
    c: &std::net::TcpStream,
    request: http_bytes::Request,
    debt: &[u8],
) -> Result<()> {
    //println!("{:#?}", request);
    println!("{}\t{}", request.method(), request.uri());

    let authority = if let Some(aut) = request.uri().authority_part() {
        aut.clone()
    } else if let Some(hh) = request.headers().get(http::header::HOST) {
        let aut = hh.to_str()?;
        aut.parse()?
    } else if request.method() == http::method::Method::CONNECT {
        let aut = request.uri().to_string();
        aut.parse()?
    } else {
        return Err("No host specified to connect to\n")?;
    };

    let host = authority.host();
    let port = authority.port_part().map(|pp| pp.as_u16()).unwrap_or(80u16);

    let mut nonempty = false;

    use std::net::ToSocketAddrs;
    for sa in (host, port).to_socket_addrs()? {
        nonempty = true;
        let s = std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(10));
        if s.is_err() {
            continue;
        }
        let s = s.unwrap();
        return propagate_request_to_server(c, s, request, debt);
    }
    if nonempty {
        return Err("Failed to connect to this host")?;
    } else {
        return Err("No IP addresses for this host")?;
    }
}

fn serve_client(mut c: &std::net::TcpStream) -> Result<()> {
    let mut buf = vec![0u8; 1024];
    let mut fill_meter = 0usize;

    // Obtain header
    loop {
        let ret = c.read(&mut buf[fill_meter..])?;

        let b = &buf[0..(fill_meter + ret)];
        let ret2 = http_bytes::parse_request_header_easy(b)?;
        if let Some(rr) = ret2 {
            return handle_client_request(c, rr.0, rr.1);
        }

        fill_meter += ret;
        if fill_meter > 1024 * 100 {
            Err("Request too long")?;
        }
        buf.resize(fill_meter + 1024, 0u8);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn main() -> Result<()> {
    if std::env::args().len() != 2 {
        Err("Usage: http_proxy listen_ip:port")?;
    }
    let sa: std::net::SocketAddr = std::env::args().nth(1).unwrap().parse()?;
    let s = std::net::TcpListener::bind(sa)?;

    for c in s.incoming() {
        let mut c = c?;
        std::thread::spawn(move || {
            if let Err(e) = serve_client(&c) {
                println!("Err {}", e);
                let _ = c.write_all(
                    b"HTTP/1.1 400 Invalid Request\r\n\
                                      Content-Type: text/plain\r\n\
                                      \r\n",
                );
                let _ = c.write_all(e.to_string().as_bytes());
                let _ = c.write_all(b"\n");
            }
        });
    }

    Ok(())
}
