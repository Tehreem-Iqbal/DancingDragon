package events

const (
	MaxPathLength = 256
)

// EventHeader contains event metadata (type and size)
type EventHeader struct {
	Type uint32
	Size uint32
}

// ProcInfo contains information about a process execution event (execve syscall)
type ProcInfo struct {
	Hdr      EventHeader
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	_        uint32
	ProcPath [MaxPathLength]byte
}

// FileInfo contains information about a file open event (openat syscall)
type FileInfo struct {
	Hdr      EventHeader
	Pid      uint32
	_        uint32
	Filename [MaxPathLength]byte
	Dirfd    int64
}
