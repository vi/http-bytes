[![Build Status](https://travis-ci.org/vi/http-bytes.svg?branch=master)](https://travis-ci.com/vi/http-bytes)

# http-bytes

Some ways to define this crate:

* Adaptor between `httparse` and `http` crates.
* Super-lowlevel web framework, almost minimal one around `http` crate.
* A way to turn bytes to/from HTTP request/responses

HTTP 1 only, no HTTP 2.

Body is not touched in any way. Not performance-optimized.
Request handling code tries to to Basic Authorization (can opt out).

Supports Rust 1.28.0

License: MIT/Apache-2.0
