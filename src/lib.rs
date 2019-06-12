//! Adaptor between `httparse` and `http` crates.
//! HTTP 1 only, no HTTP 2.
//! Also contains code to go from `Request` or `Response` back to bytes.
//!
//! Never goes into request or response body, it always leave it unparsed.
//!
//! Not performance-optimized

pub extern crate http;
pub extern crate httparse;
extern crate bytes;

pub type Request = http::request::Request<()>;
pub type Response = http::response::Response<()>;

pub use httparse::EMPTY_HEADER;

#[derive(Debug)]
pub enum Error {
    Parse(httparse::Error),
    Path(http::uri::InvalidUri),
    HeaderName(http::header::InvalidHeaderName),
    HeaderValue(http::header::InvalidHeaderValue),
    StatusCode(http::status::InvalidStatusCode),
    InvalidAuthority(http::uri::InvalidUriBytes),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Parse(x) => x.fmt(f),
            Error::Path(x) => x.fmt(f),
            Error::HeaderName(x) => x.fmt(f),
            Error::HeaderValue(x) => x.fmt(f),
            Error::StatusCode(x) => x.fmt(f),
            Error::InvalidAuthority(x) => x.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(match self {
            Error::Parse(x) => x,
            Error::Path(x) => x,
            Error::HeaderName(x) => x,
            Error::HeaderValue(x) => x,
            Error::StatusCode(x) => x,
            Error::InvalidAuthority(x) => x,
        })
    }
}

use std::str::FromStr;
use http::uri::{Parts as UriParts,PathAndQuery,Authority};
use http::{Method,StatusCode};
use http::header::{HeaderName,HeaderValue,HOST};

/// Parse this byte buffer into a `Request` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete request.
/// Allocates a space for 50 headers (about 800 bytes) in stack each time.
pub fn parse_request_header_easy(buf: &[u8]) -> Result<Option<(Request, &[u8])>, Error> {
    let mut h = [httparse::EMPTY_HEADER; 50];
    parse_request_header(buf, h.as_mut(), None)
}

/// Parse this byte buffer into a `Response` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete response.
/// Allocates a space for 50 headers (about 800 bytes) in stack each time.
pub fn parse_response_header_easy(buf: &[u8]) -> Result<Option<(Response, &[u8])>, Error> {
    let mut h = [httparse::EMPTY_HEADER; 50];
    parse_response_header(buf, h.as_mut())
}

/// Parse this byte buffer into a `Request` plus remaining trailing bytes.
/// 
/// Returns `Ok(None)` if not enough bytes yet to produce a complete request.
/// 
/// If `scheme` is specified then information from `Host:`
/// header is filled in into URL, if it exists. In case of no
/// host header the URL would be scheme-less.
/// 
/// TODO: also fill in HTTP basic auth data if present in request
pub fn parse_request_header<'a,'b>(
    buf: &'a[u8],
    headers_buffer: &'b mut [httparse::Header<'a>],
    scheme: Option<http::uri::Scheme>,
) -> Result<Option<(Request, &'a[u8])>, Error> {
    let mut x = httparse::Request::new(headers_buffer);
    let n = match x.parse(buf).map_err(Error::Parse)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(size) => size,
    };
    let trailer = &buf[n..];
    let mut r = Request::new(());
    *r.method_mut() =
        Method::from_str(x.method.unwrap()).map_err(|_| Error::Parse(httparse::Error::Token))?;
    *r.version_mut() = http::Version::HTTP_11; // FIXME?
    let mut up : UriParts = Default::default();
    up.path_and_query = Some(PathAndQuery::from_str(x.path.unwrap()).map_err(Error::Path)?);

    for h in x.headers {
        let n = HeaderName::from_str(h.name).map_err(Error::HeaderName)?;
        let v = HeaderValue::from_bytes(h.value).map_err(Error::HeaderValue)?;
        r.headers_mut().append(n, v);
    }
    if scheme.is_some() {
        if let Some(h) = r.headers().get(HOST) {
            up.scheme = scheme;
            let a = bytes::Bytes::from(h.as_bytes());
            let a = Authority::from_shared(a).map_err(Error::InvalidAuthority)?;
            up.authority = Some(a);
        }
    }
    *r.uri_mut() = http::Uri::from_parts(up).unwrap();
    Ok(Some((r, trailer)))
}


/// Parse this byte buffer into a `Response` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete response.
pub fn parse_response_header<'a,'b>(
    buf: &'a[u8],
    headers_buffer: &'b mut [httparse::Header<'a>],
) -> Result<Option<(Response, &'a[u8])>, Error> {
    let mut x = httparse::Response::new(headers_buffer);
    let n = match x.parse(buf).map_err(Error::Parse)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(size) => size,
    };
    let trailer = &buf[n..];
    let mut r = Response::new(());
    *r.status_mut() = StatusCode::from_u16(x.code.unwrap()).map_err(Error::StatusCode)?;
    // x.reason goes to nowhere
    *r.version_mut() = http::Version::HTTP_11; // FIXME?
    for h in x.headers {
        let n = HeaderName::from_str(h.name).map_err(Error::HeaderName)?;
        let v = HeaderValue::from_bytes(h.value).map_err(Error::HeaderValue)?;
        r.headers_mut().append(n, v);
    }
    Ok(Some((r, trailer)))
}

fn io_other_error(msg: &'static str) -> std::io::Error {
    let e : Box<dyn std::error::Error + Send + Sync + 'static> = msg.into();
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Write request line and headers (but not body) of this HTTP 1.1 request
/// May add 'Host:' header automatically
/// Returns number of bytes written
/// 
/// It is recommended to use either BufWriter or Cursor for efficiency
/// 
/// Scheme and version `Request` fields are ignored
pub fn write_request_header<T>(r: &http::Request<T>, mut io: impl std::io::Write) -> std::io::Result<usize> {
    let mut len = 0;
    let verb = r.method().as_str();
    let path = r.uri().path_and_query().ok_or_else(||io_other_error("Invalid URI"))?;
    let mut need_to_insert_host = r.uri().host().is_some();
    if r.headers().contains_key(HOST) {
        need_to_insert_host = false;
    }
    macro_rules! w {
        ($x:expr) => {
            io.write_all($x)?;
            len += $x.len();
        }
    }
    w!(verb.as_bytes()); 
    w!(b" "); 
    w!(path.as_str().as_bytes());
    w!(b" HTTP/1.1\r\n");

    if need_to_insert_host {
        w!(b"Host: ");
        let host = r.uri().host().unwrap();
        w!(host.as_bytes());
        if let Some(p) = r.uri().port_part() {
            w!(b":");
            w!(p.as_str().as_bytes());
        }
        w!(b"\r\n");
    }

    for (hn, hv) in r.headers() {
        w!(hn.as_str().as_bytes());
        w!(b": ");
        w!(hv.as_bytes());
        w!(b"\r\n");
    }

    w!(b"\r\n");

    Ok(len)
}

/// Easy version of `write_request_header`.
/// See its doc for details
/// Panics on problems
pub fn request_header_to_vec(r:&Request) -> Vec<u8> {
    let v = Vec::with_capacity(120);
    let mut c = std::io::Cursor::new(v);
    write_request_header(r, &mut c).unwrap();
    c.into_inner()
}

#[cfg(test)]
mod tests {
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
        assert_eq!(vv, "get / http/1.1\r
host: lol\r
user-agent: none\r
\r\n".as_ref());
    }
}
