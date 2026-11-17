// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::ascii::{CR, CRLF_LEN, LF};
use crate::common::{Body, ConnectionError, HttpHeaderError, RequestError};
use crate::headers::Headers;
use crate::request::{find, Request, RequestLine};
use crate::server::MAX_PAYLOAD_SIZE;

/// Describes where the parser is within the current HTTP request.
pub(crate) enum ParserState {
    WaitingForRequestLine,
    WaitingForHeaders,
    WaitingForBody,
    RequestReady,
}

/// Parses the request bytes buffered by an HTTP connection.
pub(crate) struct RequestParser {
    /// A partial request that is still being received.
    pub(crate) pending_request: Option<Request>,
    /// The state of the parser regarding the current request that
    /// is being processed.
    pub(crate) state: ParserState,
    /// Contains all bytes pertaining to the body of the request that
    /// is currently being processed.
    body_vec: Vec<u8>,
    /// Represents how many bytes from the body of the request are still
    /// to be read.
    pub(crate) body_bytes_to_be_read: u32,
    /// Optional payload max size.
    pub(crate) payload_max_size: usize,
}

impl RequestParser {
    pub(crate) fn new() -> Self {
        Self {
            pending_request: None,
            state: ParserState::WaitingForRequestLine,
            body_vec: vec![],
            body_bytes_to_be_read: 0,
            payload_max_size: MAX_PAYLOAD_SIZE,
        }
    }

    /// Parses bytes in `buffer` for a valid request line.
    /// Returns `false` if there are no more bytes to be parsed in the buffer.
    ///
    /// # Errors
    /// `ParseError` is returned if unable to parse request line or the indices are out of bounds.
    pub(crate) fn parse_request_line(
        &mut self,
        buffer: &[u8],
        start: &mut usize,
        end: usize,
    ) -> Result<bool, ConnectionError> {
        if end < *start {
            return Err(ConnectionError::ParseError(RequestError::Underflow));
        }
        if end > buffer.len() {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        // The slice access is safe because `end` is checked to be smaller than the buffer size
        // and larger than `start`.
        match find(&buffer[*start..end], &[CR, LF]) {
            Some(line_end_index) => {
                // The unchecked addition `start + line_end_index` is safe because `line_end_index`
                // is returned by `find` and thus guaranteed to be in-bounds. This also makes the
                // slice access safe.
                let line = &buffer[*start..(*start + line_end_index)];

                // The unchecked addition is safe because of the previous `find()`.
                *start = *start + line_end_index + CRLF_LEN;

                // Form the request with a valid request line, which is the bare minimum
                // for a valid request.
                self.pending_request = Some(Request {
                    request_line: RequestLine::try_from(line)
                        .map_err(ConnectionError::ParseError)?,
                    headers: Headers::default(),
                    body: None,
                    files: Vec::new(),
                });
                self.state = ParserState::WaitingForHeaders;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Parses bytes in `buffer` for header fields.
    /// Returns `false` if there are no more bytes to be parsed in the buffer.
    ///
    /// # Errors
    /// `ParseError` is returned if unable to parse header or the indices are out of bounds.
    pub(crate) fn parse_headers(
        &mut self,
        buffer: &[u8],
        line_start_index: &mut usize,
        end_cursor: usize,
    ) -> Result<bool, ConnectionError> {
        if end_cursor > buffer.len() {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        if end_cursor < *line_start_index {
            return Err(ConnectionError::ParseError(RequestError::Underflow));
        }
        // Safe to access the slice as the bounds are checked above.
        match find(&buffer[*line_start_index..end_cursor], &[CR, LF]) {
            // `line_start_index` points to the end of the most recently found CR LF
            // sequence. That means that if we found the next CR LF sequence at this index,
            // they are, in fact, a CR LF CR LF sequence, which marks the end of the header
            // fields, per HTTP specification.

            // We have found the end of the header.
            Some(0) => {
                // The current state is `WaitingForHeaders`, ensuring a valid request formed from a
                // request line.
                let request = self
                    .pending_request
                    .as_mut()
                    .ok_or(ConnectionError::ParseError(
                        RequestError::HeadersWithoutPendingRequest,
                    ))?;
                if request.headers.content_length() == 0 {
                    self.state = ParserState::RequestReady;
                } else {
                    if request.headers.content_length() as usize > self.payload_max_size {
                        return Err(ConnectionError::ParseError(
                            RequestError::SizeLimitExceeded(
                                self.payload_max_size,
                                request.headers.content_length() as usize,
                            ),
                        ));
                    }
                    self.body_bytes_to_be_read = request.headers.content_length();
                    request.body = Some(Body::new(vec![]));
                    self.state = ParserState::WaitingForBody;
                }

                // Update the index for the next header.
                *line_start_index = line_start_index
                    .checked_add(CRLF_LEN)
                    .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;
                Ok(true)
            }
            // We have found the end of a header line.
            Some(relative_line_end_index) => {
                let request = self
                    .pending_request
                    .as_mut()
                    .ok_or(ConnectionError::ParseError(
                        RequestError::HeadersWithoutPendingRequest,
                    ))?;
                // The `line_end_index` relative to the whole buffer.
                let line_end_index = relative_line_end_index
                    .checked_add(*line_start_index)
                    .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;

                // Get the line slice and parse it.
                // The slice access is safe because `line_end_index` is a sum of `line_end_index`
                // and something else, and `line_end_index` itself is guaranteed to be within
                // `buffer`'s bounds by the `find()`.
                let line = &buffer[*line_start_index..line_end_index];
                match request.headers.parse_header_line(line) {
                    // If a header is unsupported we ignore it.
                    Ok(_)
                    | Err(RequestError::HeaderError(HttpHeaderError::UnsupportedValue(_, _))) => {}
                    // If parsing the header invalidates the request, we propagate
                    // the error.
                    Err(e) => return Err(ConnectionError::ParseError(e)),
                };

                // Update the `line_start_index` to where we finished parsing.
                *line_start_index = line_end_index
                    .checked_add(CRLF_LEN)
                    .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;
                Ok(true)
            }
            // If we have an incomplete header line.
            None => Ok(false),
        }
    }

    /// Parses bytes in `buffer` to be put into the request body, if there should be one.
    /// Returns `false` if there are no more bytes to be parsed in the buffer.
    ///
    /// # Errors
    /// `ParseError` is returned when the body is larger than the specified content-length.
    pub(crate) fn parse_body(
        &mut self,
        buffer: &[u8],
        line_start_index: &mut usize,
        end_cursor: usize,
    ) -> Result<bool, ConnectionError> {
        // If what we have just read is not enough to complete the request and
        // there are more bytes pertaining to the body of the request.
        if end_cursor > buffer.len() {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        let start_to_end = end_cursor
            .checked_sub(*line_start_index)
            .ok_or(ConnectionError::ParseError(RequestError::Underflow))?
            as u32;
        if self.body_bytes_to_be_read > start_to_end {
            // Append everything that we read to our current incomplete body and update
            // `body_bytes_to_be_read`.
            // The slice access is safe, otherwise `checked_sub` would have failed.
            self.body_vec
                .extend_from_slice(&buffer[*line_start_index..end_cursor]);
            // Safe to subtract directly as the `if` condition prevents underflow.
            self.body_bytes_to_be_read -= start_to_end;

            return Ok(false);
        }

        // Append only the remaining necessary bytes to the body of the request.
        let line_end = line_start_index
            .checked_add(self.body_bytes_to_be_read as usize)
            .ok_or(ConnectionError::ParseError(RequestError::Overflow))?;
        // The slice access is safe as `line_end` is a sum of `line_start_index` + something else.
        self.body_vec
            .extend_from_slice(&buffer[*line_start_index..line_end]);
        *line_start_index = line_end;
        self.body_bytes_to_be_read = 0;

        let request = self
            .pending_request
            .as_mut()
            .ok_or(ConnectionError::ParseError(
                RequestError::BodyWithoutPendingRequest,
            ))?;
        // If there are no more bytes to be read for this request.
        // Assign the body of the request.
        let placeholder: Vec<_> = self
            .body_vec
            .drain(..request.headers.content_length() as usize)
            .collect();
        request.body = Some(Body::new(placeholder));

        // If we read more bytes than we should have into the body of the request.
        if !self.body_vec.is_empty() {
            return Err(ConnectionError::ParseError(RequestError::InvalidRequest));
        }

        self.state = ParserState::RequestReady;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{Method, Version};

    const BUFFER_SIZE: usize = 1024;

    #[test]
    fn test_parse_request_line() {
        let mut parser = RequestParser::new();
        let mut buffer = [0; BUFFER_SIZE];

        // Error case: end past buffer end.
        assert_eq!(
            parser
                .parse_request_line(&buffer, &mut 0, buffer.len() + 1)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Error case: start is past end.
        assert_eq!(
            parser.parse_request_line(&buffer, &mut 1, 0).unwrap_err(),
            ConnectionError::ParseError(RequestError::Underflow)
        );

        // OK case.
        assert_eq!(
            parser.parse_request_line(&buffer, &mut 1, BUFFER_SIZE),
            Ok(false)
        );

        // Error case: invalid content.
        buffer[0..8].copy_from_slice(b"foo\r\nbar");
        assert_eq!(
            parser
                .parse_request_line(&buffer, &mut 0, BUFFER_SIZE)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::InvalidRequest)
        );

        // OK case.
        buffer[0..29].copy_from_slice(b"GET http://foo/bar HTTP/1.1\r\n");
        assert_eq!(
            parser.parse_request_line(&buffer, &mut 0, BUFFER_SIZE),
            Ok(true)
        );
    }

    #[test]
    fn test_parse_headers() {
        let mut parser = RequestParser::new();
        let mut buffer = [0; BUFFER_SIZE];

        // Error case: end_cursor past buffer end.
        assert_eq!(
            parser
                .parse_headers(&buffer, &mut 0, buffer.len() + 1)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Error case: line_start_index is past end_cursor.
        assert_eq!(
            parser.parse_headers(&buffer, &mut 1, 0).unwrap_err(),
            ConnectionError::ParseError(RequestError::Underflow)
        );

        // Error case: no request pending.
        // CRLF can be at the start of the buffer...
        buffer[0] = CR;
        buffer[1] = LF;
        assert_eq!(
            parser
                .parse_headers(&buffer, &mut 0, BUFFER_SIZE)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::HeadersWithoutPendingRequest)
        );
        // ...or somewhere in the middle.
        buffer[0] = 0;
        buffer[1] = CR;
        buffer[2] = LF;
        assert_eq!(
            parser
                .parse_headers(&buffer, &mut 0, BUFFER_SIZE)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::HeadersWithoutPendingRequest)
        );

        // Error case: invalid header.
        parser.pending_request = Some(Request {
            request_line: RequestLine::new(Method::Get, "http://foo/bar", Version::Http11),
            headers: Headers::new(0, true, true),
            body: None,
            files: Vec::new(),
        });
        assert_eq!(
            parser
                .parse_headers(&buffer, &mut 0, BUFFER_SIZE)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::HeaderError(HttpHeaderError::InvalidFormat(
                "\0".to_string()
            )))
        );

        // OK case: incomplete header line.
        let hdr = b"Custom-Header-Testing: 1";
        buffer[..hdr.len()].copy_from_slice(hdr);
        assert_eq!(parser.parse_headers(&buffer, &mut 0, hdr.len()), Ok(false));

        // OK case: complete header line.
        let hdr = b"Custom-Header-Testing: 1\r\n";
        buffer[..hdr.len()].copy_from_slice(hdr);
        assert_eq!(parser.parse_headers(&buffer, &mut 0, hdr.len()), Ok(true));

        // OK case: complete header line, end of header.
        let hdr = b"\r\n";
        buffer[..hdr.len()].copy_from_slice(hdr);
        assert_eq!(parser.parse_headers(&buffer, &mut 0, hdr.len()), Ok(true));
    }

    #[test]
    fn test_parse_body() {
        let mut parser = RequestParser::new();
        let buffer = [0; BUFFER_SIZE];

        // Error case: end_cursor past buffer end.
        assert_eq!(
            parser
                .parse_body(&buffer, &mut 0usize, buffer.len() + 1)
                .unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Error case: line_start_index is past end_cursor.
        assert_eq!(
            parser.parse_body(&buffer, &mut 1usize, 0usize).unwrap_err(),
            ConnectionError::ParseError(RequestError::Underflow)
        );

        // OK case: consume the buffer.
        parser.body_bytes_to_be_read = 1;
        assert_eq!(parser.parse_body(&buffer, &mut 0usize, 0usize), Ok(false));

        // Error case: there's more body to be parsed, but no pending request set.
        assert_eq!(
            parser.parse_body(&buffer, &mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::BodyWithoutPendingRequest)
        );

        // Error case: read more bytes than we should have into the body of the request.
        parser.pending_request = Some(Request {
            request_line: RequestLine::new(Method::Get, "http://foo/bar", Version::Http11),
            headers: Headers::new(0, true, true),
            body: None,
            files: Vec::new(),
        });
        parser.body_vec = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            parser.parse_body(&buffer, &mut 0, BUFFER_SIZE).unwrap_err(),
            ConnectionError::ParseError(RequestError::InvalidRequest)
        );

        // OK case.
        parser.body_vec.clear();
        assert_eq!(parser.parse_body(&buffer, &mut 0, BUFFER_SIZE), Ok(true));
    }
}
