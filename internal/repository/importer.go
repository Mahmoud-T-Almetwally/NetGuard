package repository

import (
	"bufio"
	"io"
	"strings"	
)

func ParseAndStream(reader io.Reader, outChan chan<- BlockedDomain, sourceTag string) {
	scanner := bufio.NewScanner(reader)

	defer close(outChan)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)

		if len(parts) >= 2 {
			domain := parts[1]

			outChan <- BlockedDomain{
				Domain: domain,
				Source: sourceTag,
				Action: "BLOCK",
			}
		}
	}
}