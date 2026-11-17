// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

pub use crate::common::{ConnectionError, HttpHeaderError, RequestError};
use crate::request::Request;
use crate::request_parser::RequestParser;
use crate::response::{Response, StatusCode};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

const BUFFER_SIZE: usize = 1024;
const SCM_MAX_FD: usize = 253;

/// Owns one stream and exchanges HTTP requests and responses over it.
///
/// Reads bytes into a fixed 1024-byte buffer and receives any file descriptors
/// sent alongside them. Hands the buffered bytes to its request parser, queues
/// completed requests, and writes queued responses back to the stream.
pub struct HttpConnection<T> {
    /// Parses the request bytes received on this connection.
    parser: RequestParser,
    /// Stream implementing `Read` and `Write`, capable of sending and
    /// receiving bytes.
    stream: T,
    /// Buffer where we store the bytes we read from the stream.
    buffer: [u8; BUFFER_SIZE],
    /// The index in the buffer from where we have to start reading in
    /// the next `try_read` call.
    read_cursor: usize,
    /// A queue of all requests that have been fully received and parsed.
    parsed_requests: VecDeque<Request>,
    /// A queue of requests that are waiting to be sent.
    response_queue: VecDeque<Response>,
    /// A buffer containing the bytes of a response that is currently
    /// being sent.
    response_buffer: Option<Vec<u8>>,
    /// The list of files that has been received and which must be associated
    /// with the pending request.
    files: Vec<File>,
}

impl<T: Read + Write + ScmSocket> HttpConnection<T> {
    /// Creates an empty connection.
    pub fn new(stream: T) -> Self {
        Self {
            parser: RequestParser::new(),
            stream,
            buffer: [0; BUFFER_SIZE],
            read_cursor: 0,
            parsed_requests: VecDeque::new(),
            response_queue: VecDeque::new(),
            response_buffer: None,
            files: Vec::new(),
        }
    }

    /// This function sets the limit for PUT/PATCH requests. It overwrites the
    /// default limit of 0.05MiB with the one allowed by server.
    pub fn set_payload_max_size(&mut self, request_payload_max_size: usize) {
        self.parser.set_payload_max_size(request_payload_max_size);
    }

    /// Tries to read new bytes from the stream and automatically update the request.
    /// Meant to be used only with non-blocking streams and an `EPOLL` structure.
    /// Should be called whenever an `EPOLLIN` event is signaled.
    ///
    /// # Errors
    /// `StreamError` is returned when an IO operation fails.
    /// `ConnectionClosed` is returned when a client prematurely closes the connection.
    /// `ParseError` is returned when a parsing operation fails.
    pub fn try_read(&mut self) -> Result<(), ConnectionError> {
        // Read some bytes from the stream, which will be appended to what is already
        // present in the buffer from a previous call of `try_read`. There are already
        // `read_cursor` bytes present in the buffer.
        let end_cursor = self.read_bytes()?;

        let mut start = 0;
        loop {
            let result = self.parser.parse(&self.buffer[start..end_cursor]);
            if let Some(version) = self.parser.take_expect_continue() {
                self.response_queue
                    .push_back(Response::new(version, StatusCode::Continue));
            }
            let (consumed, request) = result.map_err(ConnectionError::ParseError)?;
            start += consumed;
            if let Some(mut request) = request {
                request.files = self.files.drain(..).collect();
                self.parsed_requests.push_back(request);
            } else {
                // Preserve the connection's 1024-byte limit and distinct errors
                // for an incomplete request line and an incomplete header line.
                if start == 0 && end_cursor == BUFFER_SIZE {
                    let error = if self.parser.waiting_for_request_line() {
                        RequestError::InvalidRequest
                    } else {
                        RequestError::HeaderError(HttpHeaderError::SizeLimitExceeded(
                            String::from_utf8_lossy(&self.buffer).into_owned(),
                        ))
                    };
                    return Err(ConnectionError::ParseError(error));
                }
                self.shift_buffer_left(start, end_cursor)
                    .map_err(ConnectionError::ParseError)?;
                return Ok(());
            }
        }
    }

    /// Reads a maximum of 1024 bytes from the stream into `buffer`.
    /// The return value represents the end index of what we have just appended.
    ///
    /// # Errors
    /// `StreamError` is returned if any error occurred while reading the stream.
    /// `ConnectionClosed` is returned if the client closed the connection.
    /// `Overflow` is returned if an arithmetic overflow occurs while parsing the request.
    fn read_bytes(&mut self) -> Result<usize, ConnectionError> {
        if self.read_cursor >= BUFFER_SIZE {
            return Err(ConnectionError::ParseError(RequestError::Overflow));
        }
        // Append new bytes to what we already have in the buffer.
        // The slice access is safe, the index is checked above.
        let (bytes_read, new_files) = self.recv_with_fds()?;

        // Update the internal list of files that must be associated with the
        // request.
        self.files.extend(new_files);

        // If the read returned 0 then the client has closed the connection.
        if bytes_read == 0 {
            return Err(ConnectionError::ConnectionClosed);
        }
        bytes_read
            .checked_add(self.read_cursor)
            .ok_or(ConnectionError::ParseError(RequestError::Overflow))
    }

    /// Receive data along with optional files descriptors.
    /// It is a wrapper around the same function from vmm-sys-util.
    ///
    /// # Errors
    /// `StreamError` is returned if any error occurred while reading the stream.
    fn recv_with_fds(&mut self) -> Result<(usize, Vec<File>), ConnectionError> {
        let buf = &mut self.buffer[self.read_cursor..];
        // We must allocate the maximum number of receivable file descriptors
        // if don't want to miss any of them. Allocating a too small number
        // would lead to the incapacity of receiving the file descriptors.
        let mut fds = [0; SCM_MAX_FD];
        let mut iovecs = [libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        }];

        // SAFETY: Safe because we have mutably borrowed buf and it's safe to write
        // arbitrary data to a slice.
        let (read_count, fd_count) = unsafe {
            self.stream
                .recv_with_fds(&mut iovecs, &mut fds)
                .map_err(ConnectionError::StreamReadError)?
        };

        Ok((
            read_count,
            fds.iter()
                .take(fd_count)
                .map(|fd| {
                    // SAFETY: Safe because all fds are owned by us after they have been
                    // received through the socket.
                    unsafe { File::from_raw_fd(*fd) }
                })
                .collect(),
        ))
    }

    /// Tries to write the first available response to the provided stream.
    /// Meant to be used only with non-blocking streams and an `EPOLL` structure.
    /// Should be called whenever an `EPOLLOUT` event is signaled. If no bytes
    /// were written to the stream or error occurred while trying to write to stream,
    /// we will discard all responses from response_queue because there is no way
    /// to deliver it to client.
    ///
    /// # Errors
    /// `StreamError` is returned when an IO operation fails.
    /// `ConnectionClosed` is returned when trying to write on a closed connection.
    /// `InvalidWrite` is returned when trying to write on a connection with an
    /// empty outgoing buffer.
    pub fn try_write(&mut self) -> Result<(), ConnectionError> {
        if self.response_buffer.is_none() {
            if let Some(response) = self.response_queue.pop_front() {
                let mut response_buffer_vec: Vec<u8> = Vec::new();
                response
                    .write_all(&mut response_buffer_vec)
                    .map_err(ConnectionError::StreamWriteError)?;
                self.response_buffer = Some(response_buffer_vec);
            } else {
                return Err(ConnectionError::InvalidWrite);
            }
        }

        let mut response_fully_written = false;
        let mut connection_closed = false;

        if let Some(response_buffer_vec) = self.response_buffer.as_mut() {
            let bytes_to_be_written = response_buffer_vec.len();
            match self.stream.write(response_buffer_vec.as_slice()) {
                Ok(0) => connection_closed = true,
                Ok(bytes_written) => {
                    if bytes_written != bytes_to_be_written {
                        response_buffer_vec.drain(..bytes_written);
                    } else {
                        response_fully_written = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => connection_closed = true,
            }
        }

        if connection_closed {
            self.clear_write_buffer();
            return Err(ConnectionError::ConnectionClosed);
        } else if response_fully_written {
            self.response_buffer.take();
        }

        Ok(())
    }

    /// Discards all pending writes from the connection.
    pub fn clear_write_buffer(&mut self) {
        self.response_queue.clear();
        self.response_buffer.take();
    }

    /// Send a response back to the source of a request.
    pub fn enqueue_response(&mut self, response: Response) {
        self.response_queue.push_back(response);
    }

    fn shift_buffer_left(
        &mut self,
        line_start_index: usize,
        end_cursor: usize,
    ) -> Result<(), RequestError> {
        if end_cursor > self.buffer.len() {
            return Err(RequestError::Overflow);
        }
        // We don't want to shift something that is already at the beginning.
        let delta_bytes = end_cursor
            .checked_sub(line_start_index)
            .ok_or(RequestError::Underflow)?;
        if line_start_index != 0 {
            // Move the bytes from `line_start_index` to the beginning of the buffer.
            for cursor in 0..delta_bytes {
                // The unchecked addition is safe, guaranteed by the result of the substraction
                // above.
                // The slice access is safe, as `line_start_index + cursor` is <= `end_cursor`,
                // checked at the start of the function.
                self.buffer[cursor] = self.buffer[line_start_index + cursor];
            }

            // Clear the rest of the buffer.
            for cursor in delta_bytes..end_cursor {
                self.buffer[cursor] = 0;
            }
        }

        // Update `read_cursor`.
        self.read_cursor = delta_bytes;
        Ok(())
    }

    /// Returns the first parsed request in the queue or `None` if the queue
    /// is empty.
    pub fn pop_parsed_request(&mut self) -> Option<Request> {
        self.parsed_requests.pop_front()
    }

    /// Returns `true` if there are bytes waiting to be written into the stream.
    pub fn pending_write(&self) -> bool {
        self.response_buffer.is_some() || !self.response_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};
    use std::net::Shutdown;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::common::Body;
    use crate::common::{Method, Version};
    use crate::headers::Headers;
    use crate::request::RequestLine;
    use crate::server::MAX_PAYLOAD_SIZE;

    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_try_read_expect() {
        // Test request with `Expect` header.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 Content-Length: 26\r\n\
                                 X-Transfer-Mode: unencoded\r\n\r\n",
            )
            .unwrap();
        assert!(conn.try_read().is_ok());

        sender.write_all(b"this is not\n\r\na json \nbody").unwrap();
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();

        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, true),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
            files: Vec::new(),
        };

        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_long_headers() {
        // Long request headers.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 X-Transfer-Mode: unencoded\r\n",
            )
            .unwrap();

        for i in 0..90 {
            sender.write_all(b"Custom-Header-Testing: 1").unwrap();
            sender.write_all(i.to_string().as_bytes()).unwrap();
            sender.write_all(b"\r\n").unwrap();
        }
        sender
            .write_all(b"Content-Length: 26\r\n\r\nthis is not\n\r\na json \nbody")
            .unwrap();
        assert!(conn.try_read().is_ok());
        assert!(conn.try_read().is_ok());
        assert!(conn.try_read().is_ok());
        let request = conn.pop_parsed_request().unwrap();

        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, true),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
            files: Vec::new(),
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_split_ending() {
        // Long request with '\r\n' on BUFFER_SIZEth and 1025th positions in the request.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 X-Transfer-Mode: unencoded\r\n",
            )
            .unwrap();

        for i in 0..32 {
            sender.write_all(b"Custom-Header-Testing: 1").unwrap();
            sender.write_all(i.to_string().as_bytes()).unwrap();
            sender.write_all(b"\r\n").unwrap();
        }
        sender
            .write_all(b"Head: aaaaa\r\nContent-Length: 26\r\n\r\nthis is not\n\r\na json \nbody")
            .unwrap();
        assert!(conn.try_read().is_ok());
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, true),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
            files: Vec::new(),
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_invalid_request() {
        // Invalid request.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 X-Transfer-Mode: unencoded\r\n",
            )
            .unwrap();

        for i in 0..40 {
            sender.write_all(b"Custom-Header-Testing: 1").unwrap();
            sender.write_all(i.to_string().as_bytes()).unwrap();
            sender.write_all(b"\r\n").unwrap();
        }
        sender
            .write_all(b"Content-Length: alpha\r\n\r\nthis is not\n\r\na json \nbody")
            .unwrap();
        assert!(conn.try_read().is_ok());
        let request_error = conn.try_read().unwrap_err();
        assert_eq!(
            request_error,
            ConnectionError::ParseError(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Content-Length".to_string(),
                " alpha".to_string()
            )))
        );
    }

    #[test]
    fn test_try_read_long_request_body() {
        // Long request body.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 X-Transfer-Mode: unencoded\r\n\
                                 Content-Length: 1400\r\n\r\n",
            )
            .unwrap();

        let mut request_body: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            request_body.write_all(b"This is a test").unwrap();
        }
        sender.write_all(request_body.as_slice()).unwrap();
        assert!(conn.try_read().is_ok());
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(1400, true),
            body: Some(Body::new(request_body)),
            files: Vec::new(),
        };

        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_large_req_line() {
        // Request line longer than BUFFER_SIZE bytes.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender.write_all(b"PATCH http://localhost/home").unwrap();

        let mut request_body: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..200 {
            request_body.write_all(b"/home").unwrap();
        }
        sender.write_all(request_body.as_slice()).unwrap();
        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ParseError(RequestError::InvalidRequest)
        );
    }

    #[test]
    fn test_try_read_large_header_line() {
        // Header line longer than BUFFER_SIZE bytes.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(b"PATCH http://localhost/home HTTP/1.1\r\nhead: ")
            .unwrap();

        let mut request_body: Vec<u8> = Vec::with_capacity(1030);
        for _ in 0..86 {
            request_body.write_all(b"abcdefghijkl").unwrap();
        }
        request_body.write_all(b"\r\n\r\n").unwrap();
        sender.write_all(request_body.as_slice()).unwrap();
        assert!(conn.try_read().is_ok());

        let expected_msg = &format!("head: {}", String::from_utf8(request_body).unwrap())[..1024];
        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ParseError(RequestError::HeaderError(
                HttpHeaderError::SizeLimitExceeded(expected_msg.to_string())
            ))
        );
    }

    #[test]
    fn test_try_read_no_body_request() {
        // Request without body.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 Expect: 100-continue\r\n\
                                 X-Transfer-Mode: unencoded\r\n\r\n",
            )
            .unwrap();
        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(0, true),
            body: None,
            files: Vec::new(),
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_segmented_req_line() {
        // Segmented request line.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender.write_all(b"PATCH http://local").unwrap();
        assert!(conn.try_read().is_ok());

        sender.write_all(b"host/home HTTP/1.1\r\n\r\n").unwrap();

        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(0, false),
            body: None,
            files: Vec::new(),
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_long_req_line_b2b() {
        // Long request line after another request.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        // Req line 23 + 10*x + 13 = 36 + 10* x    984 free in first try read
        sender
            .write_all(b"PATCH http://localhost/home HTTP/1.1\r\n\r\nPATCH http://localhost/")
            .unwrap();

        let mut request_line: Vec<u8> = Vec::with_capacity(980);
        for _ in 0..98 {
            request_line.write_all(b"localhost/").unwrap();
        }
        request_line.write_all(b" HTTP/1.1\r\n\r\n").unwrap();
        sender.write_all(request_line.as_slice()).unwrap();

        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let expected_request = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(0, false),
            body: None,
            files: Vec::new(),
        };
        assert_eq!(request, expected_request);

        conn.try_read().unwrap();
        let request = conn.pop_parsed_request().unwrap();
        let mut expected_request_as_bytes = Vec::new();
        expected_request_as_bytes
            .write_all(b"http://localhost/")
            .unwrap();
        expected_request_as_bytes.append(request_line.as_mut());
        let expected_request = Request {
            request_line: RequestLine::new(
                Method::Patch,
                std::str::from_utf8(&expected_request_as_bytes[..997]).unwrap(),
                Version::Http11,
            ),
            headers: Headers::new(0, false),
            body: None,
            files: Vec::new(),
        };
        assert_eq!(request, expected_request);
    }

    #[test]
    fn test_try_read_double_request() {
        // Double request in a single read.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 X-Transfer-Mode: unencoded\r\n\
                                 Content-Length: 26\r\n\r\nthis is not\n\r\na json \nbody",
            )
            .unwrap();
        sender
            .write_all(
                b"PUT http://farhost/away HTTP/1.1\r\nContent-Length: 23\r\n\r\nthis is another request",
            )
            .unwrap();

        let expected_request_first = Request {
            request_line: RequestLine::new(Method::Patch, "http://localhost/home", Version::Http11),
            headers: Headers::new(26, false),
            body: Some(Body::new(b"this is not\n\r\na json \nbody".to_vec())),
            files: Vec::new(),
        };

        conn.try_read().unwrap();
        let request_first = conn.pop_parsed_request().unwrap();
        let request_second = conn.pop_parsed_request().unwrap();

        let expected_request_second = Request {
            request_line: RequestLine::new(Method::Put, "http://farhost/away", Version::Http11),
            headers: Headers::new(23, false),
            body: Some(Body::new(b"this is another request".to_vec())),
            files: Vec::new(),
        };
        assert_eq!(request_first, expected_request_first);
        assert_eq!(request_second, expected_request_second);
    }

    #[test]
    fn test_try_read_connection_closed() {
        // Connection abruptly closed.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH http://localhost/home HTTP/1.1\r\n\
                                 X-Transfer-Mode: unencoded\r\n\
                                 Content-Len",
            )
            .unwrap();

        conn.try_read().unwrap();
        sender.shutdown(std::net::Shutdown::Both).unwrap();

        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ConnectionClosed
        );
    }

    #[test]
    fn test_enqueue_response() {
        // Response without body.
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(sender);

        let response = Response::new(Version::Http11, StatusCode::OK);
        let mut expected_response: Vec<u8> = vec![];
        response.write_all(&mut expected_response).unwrap();

        conn.enqueue_response(response);
        assert!(conn.try_write().is_ok());

        let mut response_buffer = vec![0u8; expected_response.len()];
        receiver.read_exact(&mut response_buffer).unwrap();
        assert_eq!(response_buffer, expected_response);

        // Response with body.
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(sender);
        let mut response = Response::new(Version::Http11, StatusCode::OK);
        let mut body: Vec<u8> = vec![];
        body.write_all(br#"{ "json": "body", "hello": "world" }"#)
            .unwrap();
        response.set_body(Body::new(body));
        let mut expected_response: Vec<u8> = vec![];
        response.write_all(&mut expected_response).unwrap();

        conn.enqueue_response(response);
        assert!(conn.try_write().is_ok());

        let mut response_buffer = vec![0u8; expected_response.len()];
        receiver.read_exact(&mut response_buffer).unwrap();
        assert_eq!(response_buffer, expected_response);
    }

    #[test]
    fn test_try_read_negative_content_len() {
        // Request with negative `Content-Length` header.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT http://localhost/home HTTP/1.1\r\n\
                                 Content-Length: -1\r\n\r\n",
            )
            .unwrap();
        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ParseError(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Content-Length".to_string(),
                " -1".to_string()
            )))
        );
    }

    #[test]
    fn test_payload_size_limit() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);
        conn.set_payload_max_size(5);
        sender
            .write_all(
                b"PUT http://localhost/home HTTP/1.1\r\n\
                                 Content-Length: 51200\r\n\r\naaaaaa",
            )
            .unwrap();
        assert_eq!(
            conn.try_read().unwrap_err(),
            ConnectionError::ParseError(RequestError::SizeLimitExceeded(5, MAX_PAYLOAD_SIZE))
        );
    }

    #[test]
    fn test_read_bytes() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);

        // Cursor positioned at buffer end. Read should fail.
        conn.read_cursor = BUFFER_SIZE;
        sender.write_all(b"hello\0").unwrap();
        assert_eq!(
            conn.read_bytes().unwrap_err(),
            ConnectionError::ParseError(RequestError::Overflow)
        );

        // Cursor positioned before buffer end. Partial read should succeed.
        conn.read_cursor = BUFFER_SIZE - 3;
        sender.write_all(b"hello\0").unwrap();
        assert_eq!(conn.read_bytes(), Ok(BUFFER_SIZE));

        // Read the remaining 9 bytes - 3 left from the first "hello" and the 2nd full "hello".
        conn.read_cursor = 0;
        assert_eq!(conn.read_bytes(), Ok(9));
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            conn.read_bytes().unwrap_err(),
            ConnectionError::ConnectionClosed
        );
    }

    #[test]
    fn test_read_bytes_with_files() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).expect("Can't modify socket");
        let mut conn = HttpConnection::new(receiver);

        // Create 3 files, edit the content and rewind back to the start.
        let mut file1 = TempFile::new().unwrap().into_file();
        let mut file2 = TempFile::new().unwrap().into_file();
        let mut file3 = TempFile::new().unwrap().into_file();
        file1.write_all(b"foo").unwrap();
        file1.seek(SeekFrom::Start(0)).unwrap();
        file2.write_all(b"bar").unwrap();
        file2.seek(SeekFrom::Start(0)).unwrap();
        file3.write_all(b"foobar").unwrap();
        file3.seek(SeekFrom::Start(0)).unwrap();

        // Send 2 file descriptors along with 3 bytes of data.
        assert_eq!(
            sender.send_with_fds(
                &[[1, 2, 3].as_ref()],
                &[file1.into_raw_fd(), file2.into_raw_fd()]
            ),
            Ok(3)
        );

        // Check we receive the right amount of data along with the right
        // amount of file descriptors.
        assert_eq!(conn.read_bytes(), Ok(3));
        assert_eq!(conn.files.len(), 2);

        // Check the content of the data received
        assert_eq!(conn.buffer[0], 1);
        assert_eq!(conn.buffer[1], 2);
        assert_eq!(conn.buffer[2], 3);

        // Check the file descriptors are usable by checking the content that
        // can be read.
        let mut buf = [0; 10];
        assert_eq!(conn.files[0].read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"foo");
        assert_eq!(conn.files[1].read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"bar");

        // Send the 3rd file descriptor along with 1 byte of data.
        assert_eq!(
            sender.send_with_fds(&[[10].as_ref()], &[file3.into_raw_fd()]),
            Ok(1)
        );

        // Check the amount of data along with the amount of file descriptors
        // are updated.
        assert_eq!(conn.read_bytes(), Ok(1));
        assert_eq!(conn.files.len(), 3);

        // Check the content of the new data received
        assert_eq!(conn.buffer[0], 10);

        // Check the latest file descriptor is usable by checking the content
        // that can be read.
        let mut buf = [0; 10];
        assert_eq!(conn.files[2].read(&mut buf).unwrap(), 6);
        assert_eq!(&buf[..6], b"foobar");

        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            conn.read_bytes().unwrap_err(),
            ConnectionError::ConnectionClosed
        );
    }

    #[test]
    fn test_shift_buffer_left() {
        let (_, receiver) = UnixStream::pair().unwrap();
        let mut conn = HttpConnection::new(receiver);

        assert_eq!(
            conn.shift_buffer_left(0, conn.buffer.len() + 1)
                .unwrap_err(),
            RequestError::Overflow
        );
        assert_eq!(
            conn.shift_buffer_left(1, 0).unwrap_err(),
            RequestError::Underflow
        );
        assert!(conn.shift_buffer_left(1, conn.buffer.len()).is_ok());
    }
}
