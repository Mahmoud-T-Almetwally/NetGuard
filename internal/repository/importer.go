package repository

import (
	"bufio"
	"encoding/csv"
	// "encoding/json"
	"io"
	"log"
	"strings"
	"netguard/internal/config" // Import config to access SourceConfig
)

// ParseAndStream now takes the full SourceConfig object
func ParseAndStream(reader io.Reader, outChan chan<- BlockedDomain, src config.SourceConfig) {
	defer close(outChan)

	switch src.Format {
	case "csv":
		parseCSV(reader, outChan, src)
	case "text":
		parseText(reader, outChan, src)
	case "json":
		parseJson(reader, outChan, src)
	case "hosts":
		fallthrough
	default:
		parseHosts(reader, outChan, src)
	}
}

// 1. HOSTS Format Parser (Standard)
func parseHosts(reader io.Reader, outChan chan<- BlockedDomain, src config.SourceConfig) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			outChan <- BlockedDomain{
				Domain: parts[1], // 0.0.0.0 domain.com
				Source: src.Name, // Use the configured name (e.g., "steven_black")
				Action: "BLOCK",
			}
		}
	}
}

func parseJson(reader io.Reader, outChan chan<- BlockedDomain, src config.SourceConfig){

}

// 2. TEXT Format Parser (One domain per line)
func parseText(reader io.Reader, outChan chan<- BlockedDomain, src config.SourceConfig) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }

		outChan <- BlockedDomain{
			Domain: line,
			Source: src.Name,
			Action: "BLOCK",
		}
	}
}

// 3. CSV Format Parser (Column aware)
func parseCSV(reader io.Reader, outChan chan<- BlockedDomain, src config.SourceConfig) {
	csvReader := csv.NewReader(reader)
	
	// Read Header
	header, err := csvReader.Read()
	if err != nil {
		log.Printf("Failed to read CSV header for %s: %v", src.Name, err)
		return
	}

	// Find the index of the target column
	targetIndex := -1
	targetCol := strings.ToLower(src.TargetColumn)
	
	for i, col := range header {
		if strings.ToLower(col) == targetCol {
			targetIndex = i
			break
		}
	}

	if targetIndex == -1 {
		log.Printf("Column '%s' not found in CSV for %s", src.TargetColumn, src.Name)
		return
	}

	// Stream rows
	for {
		record, err := csvReader.Read()
		if err == io.EOF { break }
		if err != nil { continue }

		if len(record) > targetIndex {
			domain := strings.TrimSpace(record[targetIndex])
			if domain != "" {
				outChan <- BlockedDomain{
					Domain: domain,
					Source: src.Name,
					Action: "BLOCK",
				}
			}
		}
	}
}