use super::*;
#[test]
fn request_roundtrip() {
    let q = b"GET / HTTP/1.1\r
Host: lol\r
User-Agent: none\r
\r
qwer";
    let (r, rest) = parse_request_header_easy(q).unwrap().unwrap();

    assert_eq!(rest, b"qwer");

    let v = request_header_to_vec(&r);
    let vv = String::from_utf8_lossy(&v[..]).to_lowercase();
    assert_eq!(
        vv,
        "get / http/1.1\r
host: lol\r
user-agent: none\r
\r\n"
            .as_ref()
    );
}


#[test]
#[cfg(feature="basicauth")]
fn request_auth_roundtrip_autofill() {
    let q = b"GET /Bernd HTTP/1.1\r
Host: lol\r
User-Agent: none\r
Authorization: Basic Zm9vOmJhcg==\r
\r
qwer"; 
    let mut h = [httparse::EMPTY_HEADER; 50];
    let s = http::uri::Scheme::HTTP;
    let (mut r, rest) = parse_request_header(q, &mut h, Some(s)).unwrap().unwrap();
    assert_eq!(rest, b"qwer");

    r.headers_mut().clear();

    let v = request_header_to_vec(&r);
    let vv = String::from_utf8_lossy(&v[..]).to_lowercase();
    assert_eq!(
        vv,
        "get /bernd http/1.1\r
host: lol\r
authorization: basic zm9vomjhcg==\r
\r\n"
            .as_ref()
    );
}


#[test]
fn response_roundtrip() {
    let q = b"HTTP/1.1 200 OK\r
Host: lol\r
Server: none\r
\r
qwer";
    let (r, rest) = parse_response_header_easy(q).unwrap().unwrap();

    assert_eq!(rest, b"qwer");

    let v = response_header_to_vec(&r);
    let vv = String::from_utf8_lossy(&v[..]).to_lowercase();
    assert_eq!(
        vv,
        "http/1.1 200 ok\r
host: lol\r
server: none\r
\r\n"
            .as_ref()
    );
}
