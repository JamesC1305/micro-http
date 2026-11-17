// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::ascii::{CR, CRLF_LEN, LF};
use crate::common::{Body, HttpHeaderError, RequestError, Version};
use crate::headers::Headers;
use crate::request::{Request, RequestLine};
use crate::server::MAX_PAYLOAD_SIZE;

/// Describes where the parser is within the current HTTP request.
#[derive(Debug)]
enum ParserState {
    WaitingForRequestLine,
    WaitingForHeaders,
    WaitingForBody,
    RequestReady,
}

/// Incrementally parses HTTP requests from a caller-owned buffer.
///
/// Complete lines and body bytes are consumed, but an incomplete trailing line
/// remains in the caller's buffer. The parser imposes no line or total request
/// size limit; callers must bound the bytes they buffer. After an error, do not
/// continue parsing the connection.
///
/// # Examples
///
/// ```
/// use micro_http::RequestParser;
///
/// let mut parser = RequestParser::new();
/// let first = b"GET / HTTP/1.1\r\nAccept: text/";
/// let (consumed, request) = parser.parse(first).unwrap();
/// assert_eq!(consumed, b"GET / HTTP/1.1\r\n".len());
/// assert!(request.is_none());
///
/// // Retain the unconsumed partial line and append the next bytes received.
/// let mut remaining = first[consumed..].to_vec();
/// remaining.extend_from_slice(b"plain\r\n\r\n");
/// let (consumed, request) = parser.parse(&remaining).unwrap();
/// assert_eq!(consumed, remaining.len());
/// assert_eq!(request.unwrap().uri().get_abs_path(), "/");
/// ```
#[derive(Debug)]
pub struct RequestParser {
    state: ParserState,
    pending_request: Option<Request>,
    body_vec: Vec<u8>,
    body_bytes_to_be_read: u32,
    payload_max_size: usize,
    expect_continue: Option<Version>,
}

impl Default for RequestParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestParser {
    /// Creates a parser accepting request bodies of up to 51,200 bytes,
    /// the default payload limit used by the HTTP server.
    pub fn new() -> Self {
        Self {
            state: ParserState::WaitingForRequestLine,
            pending_request: None,
            body_vec: Vec::new(),
            body_bytes_to_be_read: 0,
            payload_max_size: MAX_PAYLOAD_SIZE,
            expect_continue: None,
        }
    }

    /// Sets the largest accepted request body, in bytes.
    ///
    /// A larger declared `Content-Length` returns
    /// [`RequestError::SizeLimitExceeded`] as soon as the headers end, before
    /// any body byte is consumed.
    pub fn set_payload_max_size(&mut self, size: usize) {
        self.payload_max_size = size;
    }

    /// Parses bytes starting at the first byte previous calls did not consume.
    ///
    /// Returns the consumed byte count and at most one completed request. Never
    /// consumes bytes beyond that request. After returning a request, the parser
    /// is ready for the next one. An incomplete trailing line is not consumed;
    /// complete lines and partial bodies can be consumed without completing a
    /// request.
    ///
    /// # Errors
    /// Returns [`RequestError`] if the request is malformed or its declared body
    /// exceeds the payload limit. Do not keep parsing that connection after an
    /// error.
    pub fn parse(&mut self, buf: &[u8]) -> Result<(usize, Option<Request>), RequestError> {
        let mut start = 0;
        loop {
            let complete = match self.state {
                ParserState::WaitingForRequestLine => self.parse_request_line(buf, &mut start)?,
                ParserState::WaitingForHeaders => self.parse_headers(buf, &mut start)?,
                ParserState::WaitingForBody => self.parse_body(buf, &mut start)?,
                ParserState::RequestReady => {
                    self.state = ParserState::WaitingForRequestLine;
                    self.body_bytes_to_be_read = 0;
                    return Ok((start, self.pending_request.take()));
                }
            };
            if !complete {
                return Ok((start, None));
            }
        }
    }

    pub(crate) fn take_expect_continue(&mut self) -> Option<Version> {
        self.expect_continue.take()
    }

    pub(crate) fn waiting_for_request_line(&self) -> bool {
        matches!(self.state, ParserState::WaitingForRequestLine)
    }

    fn read_line(buf: &[u8]) -> Result<Option<&[u8]>, RequestError> {
        match buf.iter().position(|byte| matches!(*byte, CR | LF)) {
            Some(index) if buf[index] == LF => Err(RequestError::InvalidRequest),
            Some(index) => match buf.get(index + 1) {
                Some(&LF) => Ok(Some(&buf[..index])),
                Some(_) => Err(RequestError::InvalidRequest),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    fn parse_request_line(&mut self, buf: &[u8], start: &mut usize) -> Result<bool, RequestError> {
        let Some(line) = Self::read_line(&buf[*start..])? else {
            return Ok(false);
        };
        self.pending_request = Some(Request {
            request_line: RequestLine::try_from(line)?,
            headers: Headers::default(),
            body: None,
            files: Vec::new(),
        });
        *start += line.len() + CRLF_LEN;
        self.state = ParserState::WaitingForHeaders;
        Ok(true)
    }

    fn parse_headers(&mut self, buf: &[u8], start: &mut usize) -> Result<bool, RequestError> {
        let Some(line) = Self::read_line(&buf[*start..])? else {
            return Ok(false);
        };
        let request = self
            .pending_request
            .as_mut()
            .ok_or(RequestError::HeadersWithoutPendingRequest)?;
        if line.is_empty() {
            let content_length = request.headers.content_length();
            if content_length == 0 {
                self.state = ParserState::RequestReady;
            } else {
                if content_length as usize > self.payload_max_size {
                    return Err(RequestError::SizeLimitExceeded(
                        self.payload_max_size,
                        content_length as usize,
                    ));
                }
                if request.headers.expect() {
                    self.expect_continue = Some(request.http_version());
                }
                self.body_bytes_to_be_read = content_length;
                request.body = Some(Body::new(Vec::new()));
                self.state = ParserState::WaitingForBody;
            }
        } else {
            match request.headers.parse_header_line(line) {
                // Preserve the treatment of unsupported values in HttpConnection.
                Ok(())
                | Err(RequestError::HeaderError(HttpHeaderError::UnsupportedValue(_, _))) => {}
                Err(error) => return Err(error),
            }
        }
        *start += line.len() + CRLF_LEN;
        Ok(true)
    }

    fn parse_body(&mut self, buf: &[u8], start: &mut usize) -> Result<bool, RequestError> {
        let count = (self.body_bytes_to_be_read as usize).min(buf.len() - *start);
        self.body_vec
            .extend_from_slice(&buf[*start..*start + count]);
        *start += count;
        self.body_bytes_to_be_read -= count as u32;
        if self.body_bytes_to_be_read != 0 {
            return Ok(false);
        }
        let request = self
            .pending_request
            .as_mut()
            .ok_or(RequestError::BodyWithoutPendingRequest)?;
        if self.body_vec.len() != request.headers.content_length() as usize {
            return Err(RequestError::InvalidRequest);
        }
        request.body = Some(Body::new(std::mem::take(&mut self.body_vec)));
        self.state = ParserState::RequestReady;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumed_lines_and_incomplete_line() {
        let mut parser = RequestParser::default();
        assert!(parser.parse(b"GET / HTTP/1.1").unwrap().1.is_none());
        assert_eq!(parser.parse(b"GET / HTTP/1.1").unwrap().0, 0);
        let input = b"GET / HTTP/1.1\r\nAccept: text/plain\r\nX-Part: val";
        let (consumed, request) = parser.parse(input).unwrap();
        assert_eq!(consumed, b"GET / HTTP/1.1\r\nAccept: text/plain\r\n".len());
        assert!(request.is_none());
        assert_eq!(parser.parse(&input[consumed..]).unwrap().0, 0);
        let remaining = b"X-Part: value\r\n\r\n";
        let (consumed, request) = parser.parse(remaining).unwrap();
        assert_eq!(consumed, remaining.len());
        assert_eq!(request.unwrap().headers.custom_entries()["X-Part"], "value");
    }

    #[test]
    fn test_pipeline_and_next_request() {
        let mut parser = RequestParser::new();
        let get = b"GET http://169.254.169.254/ HTTP/1.1\r\nAccept: text/plain\r\n\r\n";
        let input = [get.as_slice(), get, b"GET /partial"].concat();
        for offset in [0, get.len()] {
            let (consumed, request) = parser.parse(&input[offset..]).unwrap();
            assert_eq!(consumed, get.len());
            assert_eq!(request.unwrap().uri().get_abs_path(), "/");
        }
        assert_eq!(parser.parse(&input[2 * get.len()..]).unwrap().0, 0);
        assert!(parser
            .parse(b"GET /next HTTP/1.0\r\n\r\n")
            .unwrap()
            .1
            .is_some());
    }

    #[test]
    fn test_every_request_prefix() {
        let get = b"GET http://169.254.169.254/ HTTP/1.1\r\nAccept: text/plain\r\n\r\n";
        for len in 0..get.len() {
            let mut parser = RequestParser::new();
            let (consumed, request) = parser.parse(&get[..len]).unwrap();
            assert!(request.is_none(), "{len}");
            let (rest, request) = parser.parse(&get[consumed..]).unwrap();
            assert_eq!(consumed + rest, get.len(), "{len}");
            assert!(request.is_some(), "{len}");
        }
    }

    #[test]
    fn test_body_across_calls() {
        let mut parser = RequestParser::new();
        let first = b"PUT / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab";
        let (consumed, request) = parser.parse(first).unwrap();
        assert_eq!(consumed, first.len());
        assert!(request.is_none());
        assert_eq!(parser.parse(b"").unwrap().0, 0);
        let (consumed, request) = parser.parse(b"cdeGET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(request.unwrap().body.unwrap().raw(), b"abcde");
        assert!(parser.parse(b"GET / HTTP/1.1\r\n\r\n").unwrap().1.is_some());
    }

    #[test]
    fn test_payload_limit_at_header_end() {
        for suffix in [b"\r\n".as_slice(), b"\r\nabcde"] {
            let mut parser = RequestParser::new();
            parser.set_payload_max_size(4);
            let headers = b"PUT / HTTP/1.1\r\nContent-Length: 5\r\n";
            assert_eq!(parser.parse(headers).unwrap().0, headers.len());
            assert_eq!(
                parser.parse(suffix).unwrap_err(),
                RequestError::SizeLimitExceeded(4, 5)
            );
            assert!(parser.body_vec.is_empty());
        }
        let mut parser = RequestParser::new();
        let headers = format!(
            "PUT / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_PAYLOAD_SIZE + 1
        );
        assert_eq!(
            parser.parse(headers.as_bytes()).unwrap_err(),
            RequestError::SizeLimitExceeded(MAX_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE + 1)
        );
        parser = RequestParser::new();
        parser.set_payload_max_size(0);
        assert_eq!(
            parser
                .parse(b"PUT / HTTP/1.1\r\nContent-Length: 1\r\n\r\n")
                .unwrap_err(),
            RequestError::SizeLimitExceeded(0, 1)
        );
    }

    #[test]
    fn test_expect_continue_signal() {
        let mut parser = RequestParser::new();
        let headers = b"PUT / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n";
        assert!(parser.parse(headers).unwrap().1.is_none());
        assert_eq!(parser.take_expect_continue(), Some(Version::Http10));
        assert_eq!(parser.take_expect_continue(), None);
        assert!(parser.parse(b"x").unwrap().1.is_some());
        assert!(parser
            .parse(b"GET / HTTP/1.1\r\nExpect: 100-continue\r\n\r\n")
            .unwrap()
            .1
            .is_some());
        assert_eq!(parser.take_expect_continue(), None);
    }

    #[test]
    fn test_no_line_or_total_size_limit() {
        let mut parser = RequestParser::new();
        let input = format!(
            "GET /{} HTTP/1.1\r\nX-Large: {}\r\n\r\n",
            "a".repeat(3000),
            "b".repeat(3000)
        );
        let (consumed, request) = parser.parse(input.as_bytes()).unwrap();
        assert_eq!(consumed, input.len());
        assert!(request.is_some());
    }

    #[test]
    fn test_parse_request_line() {
        let mut parser = RequestParser::new();
        let mut buffer = [0; 1024];
        assert_eq!(parser.parse_request_line(&buffer, &mut 1), Ok(false));
        buffer[..8].copy_from_slice(b"foo\r\nbar");
        assert_eq!(
            parser.parse_request_line(&buffer, &mut 0).unwrap_err(),
            RequestError::InvalidRequest
        );
        buffer[..29].copy_from_slice(b"GET http://foo/bar HTTP/1.1\r\n");
        assert_eq!(parser.parse_request_line(&buffer, &mut 0), Ok(true));
    }

    #[test]
    fn test_parse_headers() {
        let mut parser = RequestParser::new();
        let mut buffer = [0; 1024];
        buffer[0] = CR;
        buffer[1] = LF;
        assert_eq!(
            parser.parse_headers(&buffer, &mut 0).unwrap_err(),
            RequestError::HeadersWithoutPendingRequest
        );
        buffer[0] = 0;
        buffer[1] = CR;
        buffer[2] = LF;
        assert_eq!(
            parser.parse_headers(&buffer, &mut 0).unwrap_err(),
            RequestError::HeadersWithoutPendingRequest
        );
        parser.pending_request = Some(Request {
            request_line: RequestLine::new(crate::Method::Get, "http://foo/bar", Version::Http11),
            headers: Headers::new(0, true, true),
            body: None,
            files: Vec::new(),
        });
        assert_eq!(
            parser.parse_headers(&buffer, &mut 0).unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidFormat("\0".to_string()))
        );
        assert_eq!(
            parser.parse_headers(b"Custom-Header-Testing: 1", &mut 0),
            Ok(false)
        );
        assert_eq!(
            parser.parse_headers(b"Custom-Header-Testing: 1\r\n", &mut 0),
            Ok(true)
        );
        assert_eq!(parser.parse_headers(b"\r\n", &mut 0), Ok(true));
    }

    #[test]
    fn test_parse_body() {
        let mut parser = RequestParser::new();
        let buffer = [0; 1024];
        parser.body_bytes_to_be_read = 1;
        assert_eq!(parser.parse_body(b"", &mut 0), Ok(false));
        assert_eq!(
            parser.parse_body(&buffer, &mut 0).unwrap_err(),
            RequestError::BodyWithoutPendingRequest
        );
        parser.pending_request = Some(Request {
            request_line: RequestLine::new(crate::Method::Get, "http://foo/bar", Version::Http11),
            headers: Headers::new(0, true, true),
            body: None,
            files: Vec::new(),
        });
        parser.body_vec = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            parser.parse_body(&buffer, &mut 0).unwrap_err(),
            RequestError::InvalidRequest
        );
        parser.body_vec.clear();
        assert_eq!(parser.parse_body(&buffer, &mut 0), Ok(true));
    }

    #[test]
    fn test_frame_request_line_endings() {
        let get = b"GET http://169.254.169.254/ HTTP/1.1\r\nAccept: text/plain\r\n\r\n";
        for next in [
            b"GET http://169.254.169.254/ HTTP/1.1\n\n".as_slice(),
            b"GET http://169.254.169.254/ HTTP/1.1\rX\r\n\r\n",
            b"GET http://169.254.169.254/ HTTP/1.1\r",
        ] {
            let mut parser = RequestParser::new();
            let pipelined = [get.as_slice(), next].concat();
            let (consumed, request) = parser.parse(&pipelined).unwrap();
            assert_eq!(consumed, get.len());
            assert!(request.is_some());
            if next.ends_with(b"\r") {
                let (consumed, request) = parser.parse(next).unwrap();
                assert_eq!(consumed, 0);
                assert!(request.is_none());
            } else {
                assert_eq!(
                    parser.parse(next).unwrap_err(),
                    RequestError::InvalidRequest
                );
            }
        }
        for invalid in [
            b"\n".as_slice(),
            b"GET http://169.254.169.254/ HTTP/1.1\n\n",
            b"GET http://169.254.169.254/ HTTP/1.1\r\n\n",
            b"GET http://169.254.169.254/ HTTP/1.1\r\r\n\r\n",
            b"GET http://169.254.169.254/ HTTP/1.1\r\nX-A: a\nb\r\n\r\n",
            b"GET http://169.254.169.254/ HTTP/1.1\r\nX-A: a\rb\r\n\r\n",
            b"GET /\n HTTP/1.1\r\n\r\n",
            b"GET /\r HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                RequestParser::new().parse(invalid).unwrap_err(),
                RequestError::InvalidRequest,
                "{invalid:?}"
            );
            assert_eq!(
                Request::try_from(invalid, None).unwrap_err(),
                RequestError::InvalidRequest
            );
        }
    }

    #[test]
    fn test_partial_line_endings() {
        for prefix in [b"".as_slice(), b"GET / HTTP/1.1\r\n"] {
            for line in [b"X\n".as_slice(), b"X\rX"] {
                let input = [prefix, line].concat();
                assert_eq!(
                    RequestParser::new().parse(&input).unwrap_err(),
                    RequestError::InvalidRequest
                );
            }
            let input = [prefix, b"X\r"].concat();
            let (consumed, request) = RequestParser::new().parse(&input).unwrap();
            assert_eq!(consumed, prefix.len());
            assert!(request.is_none());
        }
    }

    #[test]
    fn test_frame_request_accepted_body_headers() {
        for accepted in [
            "",
            "Content-Length: 0\r\n",
            "content-length:  0 \r\n",
            "X-metadata-token-ttl-seconds: 60\r\nAccept: text/plain\r\n",
        ] {
            let input =
                format!("PUT http://169.254.169.254/latest/api/token HTTP/1.1\r\n{accepted}\r\n");
            let mut parser = RequestParser::new();
            parser.set_payload_max_size(0);
            let (consumed, request) = parser.parse(input.as_bytes()).unwrap();
            assert_eq!(consumed, input.len(), "{accepted:?}");
            assert!(request.is_some(), "{accepted:?}");
        }
    }

    #[test]
    fn test_frame_request_header_names() {
        for rejected in [
            "Transfer-Encoding : chunked\r\n",
            " Transfer-Encoding: chunked\r\n",
            "Content-Length\u{a0}: 5\r\n",
            ": 5\r\n",
            "Content-Length\r\n",
            "\tX-Folded: value\r\n",
            "X A: value\r\n",
            "X(A): value\r\n",
        ] {
            let input =
                format!("PUT http://169.254.169.254/latest/api/token HTTP/1.1\r\n{rejected}\r\n");
            let mut parser = RequestParser::new();
            parser.set_payload_max_size(0);
            assert!(
                matches!(
                    parser.parse(input.as_bytes()).unwrap_err(),
                    RequestError::HeaderError(HttpHeaderError::InvalidFormat(_))
                ),
                "{rejected:?}"
            );
            assert!(matches!(
                Request::try_from(input.as_bytes(), None).unwrap_err(),
                RequestError::HeaderError(HttpHeaderError::InvalidFormat(_))
            ));
        }
        let valid = b"GET / HTTP/1.1\r\n!#$%&'*+-.^_`|~0123456789AZaz: value\r\n\r\n";
        assert!(RequestParser::new().parse(valid).unwrap().1.is_some());
        assert!(Request::try_from(valid, None).is_ok());
    }

    #[test]
    fn test_frame_request_content_length() {
        let request = |headers: &str| {
            format!("PUT http://169.254.169.254/latest/api/token HTTP/1.1\r\n{headers}\r\n")
        };
        for rejected in [
            "Content-Length: 5\r\nContent-Length: 0\r\n",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Content-Length: 0\r\ncontent-length: 0\r\n",
            "Content-Length: +0\r\n",
            "Content-Length: -0\r\n",
            "Content-Length:\r\n",
            "Content-Length: \t\r\n",
            "Content-Length: 0,0\r\n",
            "Content-Length: 0 0\r\n",
            "Content-Length: 0;\r\n",
            "Content-Length: \u{a0}0\r\n",
            "Content-Length: 0\u{b}\r\n",
            "Content-Length: 4294967296\r\n",
        ] {
            let input = request(rejected);
            assert!(
                matches!(
                    RequestParser::new().parse(input.as_bytes()).unwrap_err(),
                    RequestError::HeaderError(HttpHeaderError::InvalidValue(_, _))
                ),
                "{rejected:?}"
            );
            assert!(matches!(
                Request::try_from(input.as_bytes(), None).unwrap_err(),
                RequestError::HeaderError(HttpHeaderError::InvalidValue(_, _))
            ));
        }
        let mut parser = RequestParser::new();
        parser.set_payload_max_size(0);
        assert_eq!(
            parser
                .parse(request("Content-Length: 1\r\n").as_bytes())
                .unwrap_err(),
            RequestError::SizeLimitExceeded(0, 1)
        );
        let mut parser = RequestParser::new();
        assert!(parser
            .parse(b"PUT / HTTP/1.1\r\nContent-Length: 0\r\n")
            .unwrap()
            .1
            .is_none());
        assert!(matches!(
            parser.parse(b"Content-Length: 0\r\n").unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidValue(_, _))
        ));
        let mut parser = RequestParser::new();
        for _ in 0..2 {
            let input = b"PUT / HTTP/1.1\r\nContent-Length: \t0001 \t\r\n\r\nx";
            let (consumed, request) = parser.parse(input).unwrap();
            assert_eq!(consumed, input.len());
            assert_eq!(request.unwrap().body.unwrap().raw(), b"x");
            assert_eq!(
                Request::try_from(input, None)
                    .unwrap()
                    .headers
                    .content_length(),
                1
            );
        }
    }
}
