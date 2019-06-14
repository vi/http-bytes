//! Some ways to define this crate:
//!
//! * Adaptor between `httparse` and `http` crates.
//! * Super-lowlevel web framework, almost minimal one around `http` crate.
//! * A way to make bytes to/from HTTP request/responses
//!
//! HTTP 1 only, no HTTP 2.
//!
//! Body is not touched in any way. Not performance-optimized.
//! Request handling code tries to to Basic Authorization (can opt out).
//!
//! Supports Rust 1.28.0

#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate bytes;
pub extern crate http;
extern crate httparse;

#[cfg(feature = "basicauth")]
extern crate base64;
#[cfg(feature = "basicauth")]
extern crate percent_encoding;

/// `http`'s request variant as used by the parser part of this crate.
pub type Request = http::request::Request<()>;
/// `http`'s response variant as used by the parser part of this crate.
pub type Response = http::response::Response<()>;

pub use httparse::EMPTY_HEADER;

/// Error handling for this crate
///
/// All errors originate from dependency crates
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Error {
    /// Notable error case that may need to be
    /// handled is `httparse::Error::TooManyHeaders`
    Parse(httparse::Error),
    Path(http::uri::InvalidUri),
    HeaderName(http::header::InvalidHeaderName),
    HeaderValue(http::header::InvalidHeaderValue),
    StatusCode(http::status::InvalidStatusCode),
    InvalidAuthority(http::uri::InvalidUriBytes),
    #[cfg(feature = "basicauth")]
    /// If `basicauth` cargo feature is enabled, this variant is absent
    BasicAuth(base64::DecodeError),
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
            #[cfg(feature = "basicauth")]
            Error::BasicAuth(x) => x.fmt(f),
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
            #[cfg(feature = "basicauth")]
            Error::BasicAuth(x) => x,
        })
    }
}

use http::header::{HeaderName, HeaderValue, HOST};
use http::uri::{Authority, Parts as UriParts, PathAndQuery};
use http::{Method, StatusCode};
use std::str::FromStr;

/// Parse this byte buffer into a `Request` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete request.
/// Allocates a space for 50 headers (about 800 bytes) in stack each time.
///
/// ```rust
/// let (r, _b) = http_bytes::parse_request_header_easy(b"GET / HTTP/1.0\r\n\r\n").unwrap().unwrap();
/// assert_eq!(r.method(), http_bytes::http::method::Method::GET);
/// assert_eq!(r.uri(), &"/".parse::<http_bytes::http::uri::Uri>().unwrap());
/// ```
pub fn parse_request_header_easy(buf: &[u8]) -> Result<Option<(Request, &[u8])>, Error> {
    let mut h = [httparse::EMPTY_HEADER; 50];
    parse_request_header(buf, h.as_mut(), None)
}

/// Parse this byte buffer into a `Response` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete response.
/// Allocates a space for 50 headers (about 800 bytes) in stack each time.
/// ```rust
/// let (r, _b) = http_bytes::parse_response_header_easy(b"HTTP/1.0 200 OK\r\n\r\n").unwrap().unwrap();
/// assert_eq!(r.status(), http_bytes::http::StatusCode::OK);
/// ```
pub fn parse_response_header_easy(buf: &[u8]) -> Result<Option<(Response, &[u8])>, Error> {
    let mut h = [httparse::EMPTY_HEADER; 50];
    parse_response_header(buf, h.as_mut())
}

/// Parse this byte buffer into a `Request` plus remaining trailing bytes.
///
/// Returns `Ok(None)` if not enough bytes yet to produce a complete request.
///
/// If you need to get request header length, subtract length of returned buffer
/// from length of original buffer.
///
/// If `scheme` is specified then information from `Host:`
/// header is filled in into URI, if it exists. In case of no
/// host header the URI would be scheme-less.
///
/// If default Cargo feature `basicauth` is enabled and
/// `Authorization: Basic` HTTP header is found, it is also filled in
/// into URI, if there is schema and host.
///
///
/// ```rust
/// let mut headers_buffer = vec![http_bytes::EMPTY_HEADER; 20];
/// let (r, b) = http_bytes::parse_request_header(
///     b"GET /ololo HTTP/1.1\r\n\
///       Host: example.com\r\n\
///       Authorization: Basic cm1zOnJtcw==\r\n\
///       user-agent: unittest\r\n\
///       \r\n",
///     &mut headers_buffer[..],
///     Some(http_bytes::http::uri::Scheme::HTTP),
/// ).unwrap().unwrap();
/// assert_eq!(b, b"");
/// assert_eq!(r.method(), http_bytes::http::method::Method::GET);
/// let mut u = "http://example.com/ololo";
/// #[cfg(feature="basicauth")] { u = "http://rms:rms@example.com/ololo"; }
/// assert_eq!(r.uri(), &u.parse::<http_bytes::http::uri::Uri>().unwrap());
/// assert_eq!(r.headers().get(http_bytes::http::header::USER_AGENT),
///     Some(&http_bytes::http::header::HeaderValue::from_str("unittest").unwrap()));
/// ```
pub fn parse_request_header<'a, 'b>(
    buf: &'a [u8],
    headers_buffer: &'b mut [httparse::Header<'a>],
    scheme: Option<http::uri::Scheme>,
) -> Result<Option<(Request, &'a [u8])>, Error> {
    let mut parsed_request = httparse::Request::new(headers_buffer);
    let header_size = match parsed_request.parse(buf).map_err(Error::Parse)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(size) => size,
    };
    let trailer = &buf[header_size..];
    let mut request = Request::new(());
    *request.method_mut() = Method::from_str(parsed_request.method.unwrap())
        .map_err(|_| Error::Parse(httparse::Error::Token))?;
    *request.version_mut() = http::Version::HTTP_11; // FIXME?
    let mut up: UriParts = Default::default();
    up.path_and_query =
        Some(PathAndQuery::from_str(parsed_request.path.unwrap()).map_err(Error::Path)?);

    for header in parsed_request.headers {
        let n = HeaderName::from_str(header.name).map_err(Error::HeaderName)?;
        let v = HeaderValue::from_bytes(header.value).map_err(Error::HeaderValue)?;
        request.headers_mut().append(n, v);
    }
    if scheme.is_some() {
        if let Some(hv) = request.headers().get(HOST) {
            up.scheme = scheme;
            let authority_buf = bytes::Bytes::from(hv.as_bytes());
            #[allow(unused_mut)]
            let mut authority_buf = authority_buf;
            #[cfg(feature = "basicauth")]
            {
                use percent_encoding::{percent_encode, USERINFO_ENCODE_SET};
                use std::io::Write;

                #[derive(Clone, Copy)]
                struct CorrectedUserinfoEncodeSet;
                impl percent_encoding::EncodeSet for CorrectedUserinfoEncodeSet {
                    fn contains(&self, byte: u8) -> bool {
                        if byte == b'%' {
                            return true;
                        }
                        USERINFO_ENCODE_SET.contains(byte)
                    }
                }

                if let Some(u) = request.headers().get(http::header::AUTHORIZATION) {
                    let u = u.as_bytes();
                    let mut b = false;
                    b |= u.starts_with(b"Basic ");
                    b |= u.starts_with(b"basic ");
                    b |= u.starts_with(b"BASIC ");
                    if b && u.len() > 8 {
                        let u = &u[6..];
                        let u = base64::decode(u).map_err(Error::BasicAuth)?;

                        // percent-encode
                        let u = u[..]
                            .split(|v| *v == b':')
                            .map(|v| percent_encode(v, CorrectedUserinfoEncodeSet).to_string())
                            .collect::<Vec<_>>()
                            .join(":")
                            .into_bytes();
                        // Prepend `user:password@` to variable `authbuf` above.
                        // Without pulling in std::fmt preferrably
                        let l = u.len();
                        let mut u = std::io::Cursor::new(u);
                        u.set_position(l as u64);
                        u.write_all(b"@").unwrap();
                        u.write_all(authority_buf.as_ref()).unwrap();
                        authority_buf = bytes::Bytes::from(u.into_inner());
                    }
                }
            }
            let a = Authority::from_shared(authority_buf).map_err(Error::InvalidAuthority)?;
            up.authority = Some(a);
        }
    }
    *request.uri_mut() = http::Uri::from_parts(up).unwrap();
    Ok(Some((request, trailer)))
}

/// Parse this byte buffer into a `Response` plus remaining trailing bytes.
///
/// Returns `Ok(None)` if not enough bytes yet to produce a complete response.
///
/// If you need to get response header length, subtract length of returned buffer
/// from length of original buffer.
///
/// ```rust
/// let mut headers_buffer = vec![http_bytes::EMPTY_HEADER; 20];
/// let (r, b) = http_bytes::parse_response_header(
///     b"HTTP/1.1 200 OK\r\n\
///       Host: example.com\r\n\
///       Content-Type: text/plain\r\n\
///       \r\n\
///       Hello, world\n",
///     &mut headers_buffer[..],
/// ).unwrap().unwrap();
/// assert_eq!(b, b"Hello, world\n");
/// assert_eq!(r.status(), http_bytes::http::StatusCode::OK);
/// assert_eq!(r.headers().get(http_bytes::http::header::CONTENT_TYPE),
///     Some(&http_bytes::http::header::HeaderValue::from_str("text/plain").unwrap()));
/// ```
pub fn parse_response_header<'a, 'b>(
    buf: &'a [u8],
    headers_buffer: &'b mut [httparse::Header<'a>],
) -> Result<Option<(Response, &'a [u8])>, Error> {
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
    let e: Box<dyn std::error::Error + Send + Sync + 'static> = msg.into();
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Write request line and headers (but not body) of this HTTP 1.1 request
/// May add 'Host:' header automatically
/// Returns number of bytes written
///
/// It is recommended to use either BufWriter or Cursor for efficiency
///
/// Scheme and version `Request` fields are ignored
///
/// If default Cargo feature `basicauth` is enabled and request contains
/// username and password in URL then `Authorization: Basic` HTTP header is
/// automatically added
pub fn write_request_header<T>(
    r: &http::Request<T>,
    mut io: impl std::io::Write,
) -> std::io::Result<usize> {
    let mut len = 0;
    let verb = r.method().as_str();
    let path = r
        .uri()
        .path_and_query()
        .ok_or_else(|| io_other_error("Invalid URI"))?;

    let need_to_insert_host = r.uri().host().is_some() && !r.headers().contains_key(HOST);

    macro_rules! w {
        ($x:expr) => {
            io.write_all($x)?;
            len += $x.len();
        };
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
    #[cfg(feature = "basicauth")]
    {
        let already_present = r.headers().get(http::header::AUTHORIZATION).is_some();
        let at_sign = r
            .uri()
            .authority_part()
            .map_or(false, |x| x.as_str().contains('@'));
        if !already_present && at_sign {
            w!(b"Authorization: Basic ");
            let a = r.uri().authority_part().unwrap().as_str();
            let a = &a[0..(a.find('@').unwrap())];
            let a = a
                .as_bytes()
                .split(|v| *v == b':')
                .map(|v| percent_encoding::percent_decode(v).collect::<Vec<u8>>())
                .collect::<Vec<Vec<u8>>>()
                .join(&b':');
            let a = base64::encode(&a);
            w!(a.as_bytes());
            w!(b"\r\n");
        }
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

/// Write response line and headers (but not body) of this HTTP 1.1 response
///
/// Returns number of bytes written
///
/// It is recommended to use either BufWriter or Cursor for efficiency
pub fn write_response_header<T>(
    r: &http::Response<T>,
    mut io: impl std::io::Write,
) -> std::io::Result<usize> {
    let mut len = 0;
    macro_rules! w {
        ($x:expr) => {
            io.write_all($x)?;
            len += $x.len();
        };
    }

    let status = r.status();
    let code = status.as_str();
    let reason = status.canonical_reason().unwrap_or("Unknown");
    let headers = r.headers();

    w!(b"HTTP/1.1 ");
    w!(code.as_bytes());
    w!(b" ");
    w!(reason.as_bytes());
    w!(b"\r\n");

    for (hn, hv) in headers {
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
pub fn request_header_to_vec<T>(r: &http::Request<T>) -> Vec<u8> {
    let v = Vec::with_capacity(120);
    let mut c = std::io::Cursor::new(v);
    write_request_header(r, &mut c).unwrap();
    c.into_inner()
}

/// Easy version of `write_response_header`.
/// See its doc for details
/// Panics on problems
pub fn response_header_to_vec<T>(r: &http::Response<T>) -> Vec<u8> {
    let v = Vec::with_capacity(120);
    let mut c = std::io::Cursor::new(v);
    write_response_header(r, &mut c).unwrap();
    c.into_inner()
}

#[cfg(test)]
mod fuzztest;
#[cfg(test)]
mod test;
