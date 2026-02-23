// Package main monitors syscalls using eBPF to detect
// process executions and file access from temporary directories.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf dance hooks/bpf/dance.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"dancing_dragon/hooks/events"
	"dancing_dragon/hooks/handlers"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	EventExecve = 1
	EventOpenat = 2
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("removing memory lock:", err)
	}

	var objs danceObjects
	if err := loadDanceObjects(&objs, nil); err != nil {
		log.Fatal("loading eBPF objects:", err)
	}
	defer objs.Close()

	tp, tp2, err := attachTracepoints(&objs)
	if err != nil {
		log.Fatal("attaching tracepoints:", err)
	}
	defer tp.Close()
	defer tp2.Close()

	if err := startEventLoop(&objs); err != nil {
		log.Fatal("starting event loop:", err)
	}
}

func attachTracepoints(objs *danceObjects) (link.Link, link.Link, error) {
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveTp, nil)
	if err != nil {
		return nil, nil, err
	}

	tp2, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenatTp, nil)
	if err != nil {
		tp.Close()
		return nil, nil, err
	}

	log.Println("eBPF programs attached to execve and openat tracepoints. Press Ctrl+C to exit.")
	return tp, tp2, nil
}

// read events from the eBPF ring buffer
func startEventLoop(objs *danceObjects) error {
	reader, err := ringbuf.NewReader(objs.RbEvent)
	if err != nil {
		return err
	}
	defer reader.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		log.Println("\nreceived shutdown signal, exiting...")
		reader.Close()
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("reading from ring buffer: %v", err)
			continue
		}
		handleEvent(record.RawSample)
	}
}

// parse binary event data and dispatches to appropriate handler
func handleEvent(data []byte) {
	var hdr events.EventHeader

	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &hdr); err != nil {
		log.Printf("parsing ring buffer record: %v", err)
		return
	}

	switch hdr.Type {
	case EventExecve:
		log.Println("EventExecve detected")
		var event events.ProcInfo
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing execve event: %v", err)
			return
		}
		handlers.HandleExecveEvent(&event)

	case EventOpenat:
		log.Println("EventOpenat detected")
		var event events.FileInfo
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing openat event: %v", err)
			return
		}
		handlers.HandleOpenatEvent(&event)

	default:
		log.Printf("unknown event type: %d", hdr.Type)
	}
}
