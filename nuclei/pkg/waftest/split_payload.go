package waftest

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
)

// SplitPayloadFile chunks a large payload text file into smaller temp files.
func SplitPayloadFile(originalPath string, linesPerChunk int) ([]string, error) {
	file, err := os.Open(originalPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var chunks []string
	scanner := bufio.NewScanner(file)

	// Increase buffer size for large lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var currentChunk *os.File
	var currentLines int
	var chunkIndex int

	baseName := filepath.Base(originalPath)
	tempDir := os.TempDir()

	for scanner.Scan() {
		line := scanner.Text()

		if currentChunk == nil {
			tempPath := filepath.Join(tempDir, fmt.Sprintf("chunk_%d_%s", chunkIndex, baseName))
			tempFile, err := os.Create(tempPath)
			if err != nil {
				return nil, err
			}
			currentChunk = tempFile
			chunks = append(chunks, tempPath)
			chunkIndex++
		}

		_, err := currentChunk.WriteString(line + "\n")
		if err != nil {
			return nil, err
		}
		currentLines++

		if currentLines >= linesPerChunk {
			currentChunk.Close()
			currentChunk = nil
			currentLines = 0
		}
	}

	if currentChunk != nil {
		currentChunk.Close()
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// If the file was empty or too small to chunk, just return it as a single chunk
	if len(chunks) == 0 {
		return []string{originalPath}, nil
	}

	return chunks, nil
}
