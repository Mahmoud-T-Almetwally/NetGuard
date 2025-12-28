package packet

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ExtractDomain(payload []byte) (string, bool) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.NoCopy)

	// --- A. Check for DNS (UDP Port 53) ---
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		
		if len(dns.Questions) > 0 {
			// string(dns.Questions[0].Name) returns bytes like "google.com"
			return string(dns.Questions[0].Name), true
		}
	}

	// --- B. Check for HTTPS (TCP Port 443) ---
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		
		// If there is data in the packet (not just an ACK/SYN)
		if len(tcp.Payload) > 0 {
			return parseTLSClientHello(tcp.Payload)
		}
	}

	return "", false
}

// parseTLSClientHello manually parses the TLS handshake bytes to find SNI.
func parseTLSClientHello(data []byte) (string, bool) {
	// TLS Record Header (5 bytes)
	// Content Type (1 byte): 0x16 = Handshake
	// Version (2 bytes): 0x0301 (TLS 1.0) or similar
	// Length (2 bytes)
	if len(data) < 5 || data[0] != 0x16 {
		return "", false
	}

	// Skip Record Header
	pos := 5

	// Handshake Header (4 bytes)
	// Message Type (1 byte): 0x01 = Client Hello
	// Length (3 bytes)
	if pos+4 > len(data) || data[pos] != 0x01 {
		return "", false
	}
	pos += 4 // Skip Handshake Header

	// Client Hello Structure:
	// Version (2 bytes)
	// Random (32 bytes)
	pos += 2 + 32

	// Session ID (1 byte length + N bytes)
	if pos+1 > len(data) { return "", false }
	sessionIdLen := int(data[pos])
	pos += 1 + sessionIdLen

	// Cipher Suites (2 bytes length + N bytes)
	if pos+2 > len(data) { return "", false }
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Compression Methods (1 byte length + N bytes)
	if pos+1 > len(data) { return "", false }
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	// Extensions (2 bytes length + N bytes)
	if pos+2 > len(data) { return "", false }
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	// Loop through extensions to find SNI (Type 0x0000)
	end := pos + extensionsLen
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // SNI Extension Found
			// Inside SNI Extension:
			// List Length (2 bytes) - Skip
			// Name Type (1 byte) - Should be 0x00 (Host Name)
			// Name Length (2 bytes)
			// Name (N bytes)
			if pos+5 < end {
				nameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
				if pos+5+nameLen <= end {
					return string(data[pos+5 : pos+5+nameLen]), true
				}
			}
		}
		pos += extLen
	}

	return "", false
}