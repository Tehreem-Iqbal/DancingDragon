// Package utils provides file hashing, file descriptor resolution, and threat detection.
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

const (
	AT_FDCWD = -100

	VirusTotalAPI = "https://www.virustotal.com/api/v3/files/"

	VirusTotalAPIKey = "bfa4af320d59c3b60996f2e836467dd3c8435ae470053df87907821c07881067"
)

// ComputeFileHash calculates SHA256 hash of a file
func ComputeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetDirFromFd resolves directory path from a file descriptor
func GetDirFromFd(pid uint32, dirfd int64) string {
	pidStr := strconv.Itoa(int(pid))

	if dirfd == AT_FDCWD {
		cwdPath, err := os.Readlink(filepath.Join("/proc", pidStr, "cwd"))
		if err != nil {
			return "unknown (cwd)"
		}
		return cwdPath
	}

	if dirfd >= 0 {
		fdPath := filepath.Join("/proc", pidStr, "fd", strconv.FormatInt(dirfd, 10))
		dirPath, err := os.Readlink(fdPath)
		if err != nil {
			return "unknown (fd:" + strconv.FormatInt(dirfd, 10) + ")"
		}
		return dirPath
	}

	return "unknown (fd:" + strconv.FormatInt(dirfd, 10) + ")"
}

// IsInterpreter checks if executable is a script interpreter
func IsInterpreter(path string) bool {
	base := filepath.Base(path)

	interpreters := map[string]bool{
		"sh":      true,
		"bash":    true,
		"dash":    true,
		"zsh":     true,
		"fish":    true,
		"python":  true,
		"python3": true,
		"perl":    true,
		"ruby":    true,
		"java":    true,
	}

	return interpreters[base]
}

// MatchHash checks if file hash is marked as malicious in VirusTotal
func MatchHash(hash string) bool {
	req, err := http.NewRequest("GET", VirusTotalAPI+hash, nil)
	if err != nil {
		log.Printf("creating VirusTotal request: %v", err)
		return false
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("X-Apikey", VirusTotalAPIKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("making VirusTotal request: %v", err)
		return false
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("reading VirusTotal response: %v", err)
		return false
	}

	var response struct {
		Data struct {
			Attributes struct {
				PopularThreatClassification struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("parsing VirusTotal response: %v", err)
		return true
	}

	threatLabel := response.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel
	if threatLabel != "" {
		log.Printf("threat classification: %s", threatLabel)
		return true
	}

	return false
}
