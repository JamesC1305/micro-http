# Unreleased

## Added

- Added `RequestParser` for incremental parsing from caller-owned buffers.
- Implemented `Eq` for `common::headers::Encoding`, `common::headers::MediaType`,
  `common::headers::Headers`, `common::HttpHeaderError`, `common::Body`, `common::Version`,
  `common::RequestError`, `request::Uri`, `request::RequestLine`, `response::StatusCode`,
  `response::ResponseHeaders`
- Allowed to set custom headers in HTTP responses.

## Changed

- Reject request and header lines containing bare CR or LF characters.
- Reject empty or non-token header names, including whitespace before the colon
  and folded header lines.
- Reject repeated Content-Length headers and non-digit values. Only SP and HTAB
  are accepted as surrounding whitespace.
- Mark `HttpServer::new_from_fd` as `unsafe` as the correctness of the unsafe code
  in this method relies on an invariant the caller has to uphold
- Always set 'Content-Length' in non-100/204 responses regardless of whether the
  body is empty. Otherwise, the client waits for the server to close the
  connection or for timeout to occur.

# v0.1.0

- micro-http v0.1.0 first release.
