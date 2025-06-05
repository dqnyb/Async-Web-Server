# AWS - Asynchronous Web Server

## Overview

**AWS** (Asynchronous Web Server) is a lightweight and efficient HTTP server implemented in **C**, designed to handle multiple client requests using **non-blocking I/O**, **epoll** for event-driven multiplexing, **sendfile** for efficient static file serving, and **libaio** for asynchronous disk I/O on dynamic resources.

This project is intended for learning purposes and demonstrates how low-level asynchronous mechanisms in Linux can be used to build a performant web server from scratch.

---

## Features

- ✅ Event-driven architecture using `epoll`
- ✅ Asynchronous file reading using `libaio`
- ✅ Zero-copy file transmission using `sendfile()`
- ✅ Basic HTTP/1.1 request handling via `http-parser`
- ✅ Static and dynamic resource support
- ✅ Modular and extensible codebase
- ✅ Graceful error handling (404 responses)
- ✅ Lightweight and dependency-minimal

---

## Technical Stack

| Component       | Usage                                              |
|----------------|----------------------------------------------------|
| `epoll`         | Manages non-blocking socket and I/O events         |
| `libaio`        | Reads files from disk asynchronously               |
| `sendfile()`    | Transfers static files directly from disk to socket|
| `http-parser`   | Parses incoming HTTP requests                      |
| `non-blocking sockets` | Enables I/O operations without blocking       |

---

## Project Structure
aws/
├── main.c # Main loop and connection handler
├── aws.h # Struct definitions and state machine
├── static/ # Static files (e.g., index.html, style.css)
├── dynamic/ # Dynamic files served via AIO
├── utils/
│ ├── debug.h # Debug macros (logging, color print)
│ ├── util.h # Generic helper functions
│ ├── sock_util.c # Socket setup utilities
│ ├── w_epoll.h # Epoll wrapper for readability
├── Makefile # Build script
├── README.md # This file


---

## How It Works

### 1. Server Startup
- The server initializes a listening socket on port `8888`, configured as **non-blocking**.
- `epoll` is used to monitor events (new connections, data arrival, readiness to write).

### 2. Accepting Connections
- On an `EPOLLIN` event on the listening socket, new clients are accepted.
- Each connection is tracked via a `struct connection`, storing its file descriptor, state, and buffer information.

### 3. HTTP Parsing
- Incoming data is parsed using `http-parser`.
- When a full HTTP request is received, the target resource is analyzed:
  - If the path starts with `/static/` → serve with `sendfile()`
  - If the path starts with `/dynamic/` → serve via `libaio`

### 4. Static File Handling (`sendfile`)
- Efficiently sends file content using `sendfile()`, avoiding user space copy.
- This minimizes CPU usage and improves throughput.

### 5. Dynamic File Handling (`libaio`)
- Performs asynchronous read from disk using Linux AIO (`io_submit`, `io_getevents`).
- Data is read into a buffer and sent to the client in chunks using `send()`.

### 6. Response Generation
- Responses include appropriate HTTP headers.
- If a resource is not found, a 404 response is generated with a simple message.

---

## Connection State Machine

Each connection transitions through the following states:

- `STATE_RECV`: Receiving and parsing HTTP request
- `STATE_SEND_HEADER`: Sending response headers
- `STATE_SEND_FILE`: Sending file content (`sendfile` or `send`)
- `STATE_END`: Closing or resetting the connection

This allows incremental I/O without blocking the main event loop.

---

## Compilation

### Requirements

- GCC or Clang (C99+)
- Linux system with epoll and libaio support
- `libaio` and `http-parser` development headers installed

### Build Instructions

```bash
# Clone the project
git clone https://github.com/yourname/aws.git
cd aws

# Build the server
make
