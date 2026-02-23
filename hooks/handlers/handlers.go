// Package handlers processes syscall events
package handlers

import (
	"bytes"
	"dancing_dragon/hooks/events"
	"dancing_dragon/hooks/utils"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	tmpPath    = "/tmp"
	varTmpPath = "/var/tmp"
	devShmPath = "/dev/shm"
)

func HandleExecveEvent(event *events.ProcInfo) {
	procPath := string(bytes.Trim(event.ProcPath[:], "\x00"))

	exeLink := "/proc/" + strconv.Itoa(int(event.Pid)) + "/exe"
	exePath, err := os.Readlink(exeLink)
	if err != nil {
		log.Println("Reading exe link", err)
		return
	}

	if strings.HasPrefix(exePath, tmpPath) || strings.HasPrefix(exePath, varTmpPath) || strings.HasPrefix(exePath, devShmPath) {
		log.Printf("⚠️  ALERT: Execution from /tmp detected!")
		log.Printf("PID: %d\n, PPID: %d\n, UID: %d\n, Path: %s\n, exePath: %s\n", event.Pid, event.Ppid, event.Uid, procPath, exePath)

		hash, err := utils.ComputeFileHash(exePath)
		if err != nil {
			log.Printf("Could not compute hash for %s: %v\n", exePath, err)
			return
		}
		log.Printf("File hash: %s", hash)

		if utils.MatchHash(hash) {
			process, err := os.FindProcess(int(event.Pid))
			if err != nil {
				log.Println("Find process:", err)
				return
			}
			err = process.Kill()
		}
	}
}

func HandleOpenatEvent(event *events.FileInfo) {
	interpreter := "/proc/" + strconv.Itoa(int(event.Pid)) + "/exe"
	exePath, err := os.Readlink(interpreter)
	if err != nil {
		log.Println("Reading exe link", err)
		return
	}

	filename := string(bytes.Trim(event.Filename[:], "\x00"))

	var filePath string
	if filepath.IsAbs(filename) {
		filePath = filename
	} else {
		filePath = utils.GetDirFromFd(event.Pid, event.Dirfd) + "/" + filename
	}

	if utils.IsInterpreter(exePath) && (strings.HasPrefix(filePath, tmpPath) || strings.HasPrefix(filePath, varTmpPath) || strings.HasPrefix(filePath, devShmPath)) {
		log.Printf("⚠️  ALERT: Script execution detected!")
		log.Printf("PID: %d\n, Filename: %s\n, exePath: %s\n", event.Pid, filename, exePath)

		hash, err := utils.ComputeFileHash(filePath)
		if err != nil {
			log.Printf("   Could not compute hash for %s: %v\n", filePath, err)
			return
		}
		log.Printf("File hash: %s", hash)

		if utils.MatchHash(hash) {
			process, err := os.FindProcess(int(event.Pid))
			if err != nil {
				log.Println("Find process:", err)
				return
			}
			log.Printf("Killing process %d \n", event.Pid)
			err = process.Kill()
		}
	}
}
