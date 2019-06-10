//! Adaptor between `httparse` and `http` crates.
//! HTTP 1 only, no HTTP 2.
//! Also contains code to go from `Request` or `Response` back to bytes.
//!
//! Never goes into request or response body, it always leave it unparsed.
//!
//! Not performance-optimized

extern crate http;
extern crate httparse;

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
}

use std::str::FromStr;


/// Parse this byte buffer into a `Request` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete request.
/// Allocates a space for 50 headers (about 800 bytes) in stack each time.
pub fn parse_request_easy(buf: &[u8]) -> Result<Option<(Request, &[u8])>, Error> {
    let mut h = [httparse::EMPTY_HEADER; 50];
    parse_request(buf, h.as_mut())
}

/// Parse this byte buffer into a `Response` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete response.
/// Allocates a space for 50 headers (about 800 bytes) in stack each time.
pub fn parse_response_easy(buf: &[u8]) -> Result<Option<(Response, &[u8])>, Error> {
    let mut h = [httparse::EMPTY_HEADER; 50];
    parse_response(buf, h.as_mut())
}

/// Parse this byte buffer into a `Request` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete request.
pub fn parse_request<'a,'b>(
    buf: &'a[u8],
    headers_buffer: &'b mut [httparse::Header<'a>],
) -> Result<Option<(Request, &'a[u8])>, Error> {
    let mut x = httparse::Request::new(headers_buffer);
    let n = match x.parse(buf).map_err(Error::Parse)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(size) => size,
    };
    let trailer = &buf[n..];
    let mut r = Request::new(());
    *r.method_mut() =
        http::Method::from_str(x.method.unwrap()).map_err(|_| Error::Parse(httparse::Error::Token))?;
    *r.version_mut() = http::Version::HTTP_11; // FIXME?
    *r.uri_mut() = http::Uri::from_str(x.path.unwrap()).map_err(Error::Path)?;
    for h in x.headers {
        let n = http::header::HeaderName::from_str(h.name).map_err(Error::HeaderName)?;
        let v = http::header::HeaderValue::from_bytes(h.value).map_err(Error::HeaderValue)?;
        r.headers_mut().append(n, v);
    }
    Ok(Some((r, trailer)))
}


/// Parse this byte buffer into a `Response` plus remaining trailing bytes.
/// Returns `Ok(None)` if not enough bytes yet to produce a complete response.
pub fn parse_response<'a,'b>(
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
    *r.status_mut() = http::StatusCode::from_u16(x.code.unwrap()).map_err(Error::StatusCode)?;
    // x.reason goes to nowhere
    *r.version_mut() = http::Version::HTTP_11; // FIXME?
    for h in x.headers {
        let n = http::header::HeaderName::from_str(h.name).map_err(Error::HeaderName)?;
        let v = http::header::HeaderValue::from_bytes(h.value).map_err(Error::HeaderValue)?;
        r.headers_mut().append(n, v);
    }
    Ok(Some((r, trailer)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
