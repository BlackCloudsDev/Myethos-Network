# Myethos.Network

Modern asynchronous networking layer for Conquer Online server development.

> ⚠️ This project is currently under active development and is published for
> community review, testing, and architectural feedback.

## Overview

Myethos.Network is a custom networking layer designed for a modern
Conquer Online server implementation using modern .NET APIs.

The main goal is to provide a clean, asynchronous, and reliable socket
architecture while avoiding unnecessary allocations and legacy networking
patterns.

## Current Focus

The networking layer currently focuses on:

- Asynchronous TCP socket handling
- Connection lifecycle management
- Packet framing
- Partial reads and writes
- Send queues
- Concurrent connection handling
- Cancellation and graceful shutdown
- Connection limits
- Idle connection handling
- Low-allocation networking
- `Span<T>` / `Memory<T>` based processing

## Code Review

This repository is currently open for technical review.

I am particularly interested in finding:

- Race conditions
- Socket lifecycle bugs
- Connection leaks
- Packet corruption
- Partial read/write issues
- Threading and concurrency problems
- Deadlocks
- Cancellation issues
- Memory allocation problems
- Performance bottlenecks
- Error-handling issues
- Problems that may only appear under heavy load
- Security issues related to malformed or malicious packets

If you have experience with high-performance networking or
Conquer Online server development, feedback and criticism are welcome.

## Status

🚧 Work in progress.

The architecture may change significantly based on testing and community
feedback.

## License

This project is licensed under the MIT License.
