#![allow(unused)]
#![warn(unused_must_use)]
use super::*;

extern crate proptest;
extern crate proptest_http;

use self::proptest::prelude::*;

use self::proptest_http::request::RequestStrategy;
use self::proptest_http::response::ResponseStrategy;

fn compare_header_values(a: &HeaderValue, b:&HeaderValue) -> bool {
    std::str::from_utf8(&a.as_bytes()[..]).unwrap().trim()
    ==
    std::str::from_utf8(&b.as_bytes()[..]).unwrap().trim()
}

fn compare_headers(a: &http::header::HeaderMap, b:&http::header::HeaderMap) -> bool {
    for (n,v) in a {
        if let Some(v2) = b.get(n) {
            if compare_header_values(v, v2) {
                // OK;
            } else {
                eprintln!(
                    "Different value of header {:?}: `{:?}` vs `{:?}`",
                    n,
                    v,
                    v2,
                );
                return false;
            }
        } else {
            eprintln!("Missing header: {:?}", n);
            return false;
        }
    }
    let (al, bl) = (a.len(), b.len());
    if al != bl {
        eprintln!("Invalid header count: {} vs {}", al, bl);
        return false;
    }
    return true;
}

fn compare_requests(a: &super::Request, b:&super::Request) -> bool {
    use http::header::{HOST,AUTHORIZATION};
    let mut bh = b.headers().clone();
    // Remove extra Host and Authorization, which may be added by the framework
    if a.headers().get(HOST).is_none() {
        bh.remove(HOST);
    }
    if a.headers().get(AUTHORIZATION).is_none() {
        bh.remove(AUTHORIZATION);
    }
    if !compare_headers(a.headers(), &bh) {
        return false;
    }
    let host_header = a.headers().get(HOST).is_some();
    let auth_header = a.headers().get(AUTHORIZATION).is_some();
    if host_header || auth_header {
        // Authority part of URI may be mangled, so comparing only path and query
        let (aa,bb) = (a.uri().path_and_query(), b.uri().path_and_query());
        if aa != bb {
            eprintln!("Path and query mismatch: {:?} vs {:?}", aa, bb);
            return false;
        }
    } else {
        #[cfg(feature="basicauth")] {
            if a.uri() != b.uri() {
                eprintln!("URI mismatch: {} vs {}", a.uri(), b.uri());
                return false;
            }
        }
        #[cfg(not(feature="basicauth"))] {
            if a.uri().path_and_query() != b.uri().path_and_query() ||
               a.uri().host() != b.uri().host() ||
               a.uri().port_part() != b.uri().port_part() {
                eprintln!("URI mismatch: {} vs {}", a.uri(), b.uri());
                return false;
            }
        }
    }
    true
}

proptest! {
    #[test]
    fn fuzztest_request_roundtrip(r in RequestStrategy) {
        //dbg!(&r);
        let v = request_header_to_vec(&r.0);
        let mut scheme = r.0.uri().scheme_part().cloned();
        if r.0.headers().get(http::header::HOST).is_some() {
            scheme = None;
        }
        let mut h = [httparse::EMPTY_HEADER; 50];
        let rr = parse_request_header(
            &v[..],
            &mut h,
            scheme,
        ).unwrap().unwrap().0;
        //dbg!(&rr);
        assert!(compare_requests(&r.0, &rr));
    }
}


proptest! {
    #[test]
    fn fuzztest_response_roundtrip(r in ResponseStrategy) {
        //dbg!(&r);
        let v = response_header_to_vec(&r.0);
        
        let mut h = [httparse::EMPTY_HEADER; 50];
        let rr = parse_response_header(
            &v[..],
            &mut h,
        ).unwrap().unwrap().0;
        //dbg!(&rr);
        assert_eq!(r.0.status(), rr.status());
        assert!(compare_headers(r.0.headers(), rr.headers()));
    }
}
