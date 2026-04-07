# Dancing Dragon

A security monitoring tool that detects and prevents malicious process execution from temporary directories using eBPF (extended Berkeley Packet Filter) technology.

## Overview

Dancing Dragon is a Linux kernel-level monitoring system that tracks system calls to detect suspicious activity patterns, particularly:

- **Process execution** from temporary directories (`/tmp`, `/var/tmp`, `/dev/shm`)
- **File access patterns** that may indicate malicious behavior

The tool uses eBPF to hook into kernel syscalls without requiring kernel module installation or significant system overhead.

## Features

- **Real-time syscall monitoring**: Captures `execve` and `openat` syscalls at the kernel level
- **Threat detection**: Identifies processes executed from temporary directories
- **Hash-based matching**: Computes and matches file hashes against known malicious signatures
- **Automated response**: Can terminate detected malicious processes
- **Low overhead**: Uses eBPF for efficient in-kernel filtering
- **Ring buffer communication**: Efficient kernel-to-userspace event delivery

## Project Structure

```
Dancingdragon/
├── main.go                 # Main entry point and event loop orchestration
├── dance_bpf.go           # eBPF object loading and bindings
├── go.mod                 # Go module definition
├── hooks/
│   ├── bpf/
│   │   ├── dance.c        # eBPF kernel program source
│   │   └── vmlinux.h      # Kernel-generated BTF types
│   ├── events/
│   │   └── events.go      # Event structure definitions
│   ├── handlers/
│   │   └── handlers.go    # Event processing and response logic
│   └── utils/
│       └── utils.go       # Utility functions (hashing, matching)
├── LD_PRELOAD/            # LD_PRELOAD related components
└── README.md              # This file
```


### Build

Build the project using the provided build task:

```bash
cd /var/tmp/blackhole/Dancingdragon
go generate // go generate compiles the eBPF kernel program (hello.c) into an object file (hello_bpf.o) and generates a Go source file (hello_bpf.go) that embeds the object and provides helper functions to work with it.
go build -o dancing_dragon ./hooks
```

## Usage

### Running the Monitor

Execute with root privileges (required for kernel module attachment):

```bash
sudo ./dancing_dragon
```

### Output

When executed, Dancing Dragon monitors syscalls and logs:

- eBPF program attachment status
- Detected suspicious process executions
- Process details (PID, PPID, UID, path)
- File hash information
- Actions taken on detected threats

Example output:
```
eBPF programs attached to execve and openat tracepoints. Press Ctrl+C to exit.
⚠️  ALERT: Execution from /tmp detected!
PID: 12345, PPID: 1, UID: 0, Path: /tmp/malware, exePath: /tmp/malware
File hash: a1b2c3d4e5f6...
```

## How It Works

### Kernel-Level Monitoring (eBPF)

The `hooks/bpf/dance.c` eBPF program attaches to kernel tracepoints:

1. **sys_enter_execve**: Triggered when a process is executed
2. **sys_enter_openat**: Triggered when a file is opened

These tracepoints capture:
- Process information (PID, PPID, UID)
- File paths being accessed
- Timestamp of the event

### Event Processing (Userspace)

The Go userspace program:

1. Loads the compiled eBPF objects
2. Attaches tracepoints to the kernel
3. Reads events from the kernel ring buffer
4. Parses and dispatches events to appropriate handlers
5. Takes action based on detection logic

### Threat Response

When a suspicious process is detected:

1. Computes SHA256 hash of the executable
2. Checks hash against known malicious signatures
3. Optionally terminates the process (if configured)

## Architecture

```
┌─────────────────────────────────────────┐
│          Linux Kernel                   │
│  ┌──────────────────────────────────┐   │
│  │   eBPF Programs (dance.c)        │   │
│  │ ┌─────────────┐  ┌────────────┐  │   │
│  │ │execve hook  │  │ openat hook│  │   │
│  │ └─────────────┘  └────────────┘  │   │
│  │         ↓            ↓           │   │
│  │   ┌──────────────────────────┐   │   │
│  │   │   Ring Buffer Events     │   │   │
│  │   └──────────────────────────┘   │   │
│  └──────────────────────────────────┘   │
│                  ↓                      │
└─────────────────────────────────────────┘
                  ↓
        ┌─────────────────────┐
        │  Go Userspace       │
        │  ┌───────────────┐  │
        │  │ Event Reader  │  │
        │  └───────────────┘  │
        │         ↓           │
        │  ┌───────────────┐  │
        │  │   Handlers    │  │
        │  └───────────────┘  │
        │         ↓           │
        │  ┌───────────────┐  │
        │  │ Response Mgmt │  │
        │  └───────────────┘  │
        └─────────────────────┘
```

## Configuration

Threat detection behavior is controlled in `hooks/handlers/handlers.go`:

- **Monitored directories**: `/tmp`, `/var/tmp`, `/dev/shm`
- **Hash matching**: Configure known malicious hashes in `hooks/utils/utils.go`
- **Auto-kill**: Process termination is performed when hashes match

## Performance Considerations

- **Kernel overhead**: Minimal due to eBPF in-kernel filtering
- **Memory usage**: Ring buffer configured for 16MB max
- **Event throughput**: Scales with syscall frequency
- **CPU impact**: Negligible for typical workloads

## Development

### Modifying eBPF Program

1. Edit `hooks/bpf/dance.c`
2. Rebuild: `go generate ./...`
3. Rebuild the binary: `go build -o dancing_dragon ./hooks`

### Adding Event Types

1. Define new event structures in `hooks/events/events.go`
2. Add handling logic in `hooks/handlers/handlers.go`
3. Update `hooks/bpf/dance.c` to capture new event type


## Security Considerations

- This tool monitors system-wide syscalls and requires root access
- Event processing happens in userspace with elevated privileges
- Consider the security implications of auto-terminating processes
- Use in trusted environments or with careful configuration review

## License

Dual MIT/GPL (as specified in eBPF program)
