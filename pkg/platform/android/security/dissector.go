package security

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unicode"
)

// DissectedPacket contains a Wireshark-like dissection of a network packet.
type DissectedPacket struct {
	Timestamp      int64             `json:"timestamp,omitempty"`
	IPVersion      int               `json:"ip_version"`
	HeaderLength   int               `json:"header_length"`
	TotalLength    int               `json:"total_length"`
	TTL            int               `json:"ttl"`
	Protocol       string            `json:"protocol"`
	IPFlags        string            `json:"ip_flags"`
	SourceIP       string            `json:"source_ip"`
	DestinationIP  string            `json:"destination_ip"`
	SourcePort     int               `json:"source_port"`
	DestinationPort int              `json:"destination_port"`
	TCPFlags       string            `json:"tcp_flags,omitempty"`
	TCPSeq         uint32            `json:"tcp_seq,omitempty"`
	TCPAck         uint32            `json:"tcp_ack,omitempty"`
	TCPWindow      int               `json:"tcp_window,omitempty"`
	PayloadLength  int               `json:"payload_length"`
	PayloadHex     string            `json:"payload_hex,omitempty"`
	PayloadASCII   string            `json:"payload_ascii,omitempty"`
	DetectedProto  string            `json:"detected_protocol,omitempty"` // e.g. "TLS", "HTTP", "DNS"
	AppInfo        string            `json:"app_info,omitempty"`
	ExtraMetadata  map[string]string `json:"extra_metadata,omitempty"`
}

// DissectPacket parses raw wire bytes and produces a comprehensive dissection report.
func DissectPacket(rawBytes []byte) (*DissectedPacket, error) {
	if len(rawBytes) < 20 {
		return nil, fmt.Errorf("packet too short (%d bytes, min 20 required)", len(rawBytes))
	}

	version := int(rawBytes[0] >> 4)
	if version != 4 && version != 6 {
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}

	res := &DissectedPacket{
		IPVersion:     version,
		ExtraMetadata: make(map[string]string),
	}

	var ipHeaderLen int
	var protoNum byte
	var payload []byte

	if version == 4 {
		ihl := int(rawBytes[0] & 0x0F)
		ipHeaderLen = ihl * 4
		if len(rawBytes) < ipHeaderLen {
			return nil, fmt.Errorf("malformed IPv4 packet: length %d < header length %d", len(rawBytes), ipHeaderLen)
		}

		res.HeaderLength = ipHeaderLen
		res.TotalLength = int(binary.BigEndian.Uint16(rawBytes[2:4]))
		res.TTL = int(rawBytes[8])
		protoNum = rawBytes[9]

		// IP Flags
		flagByte := rawBytes[6]
		var ipFlags []string
		if flagByte&0x40 != 0 {
			ipFlags = append(ipFlags, "DF")
		}
		if flagByte&0x20 != 0 {
			ipFlags = append(ipFlags, "MF")
		}
		if len(ipFlags) == 0 {
			res.IPFlags = "None"
		} else {
			res.IPFlags = strings.Join(ipFlags, "|")
		}

		res.SourceIP = net.IP(rawBytes[12:16]).String()
		res.DestinationIP = net.IP(rawBytes[16:20]).String()
	} else {
		// IPv6 (40 bytes fixed header)
		ipHeaderLen = 40
		if len(rawBytes) < 40 {
			return nil, fmt.Errorf("malformed IPv6 packet")
		}
		res.HeaderLength = 40
		payloadLen := int(binary.BigEndian.Uint16(rawBytes[4:6]))
		res.TotalLength = 40 + payloadLen
		protoNum = rawBytes[6]
		res.TTL = int(rawBytes[7]) // Hop limit
		res.SourceIP = net.IP(rawBytes[8:24]).String()
		res.DestinationIP = net.IP(rawBytes[24:40]).String()
	}

	transportBytes := rawBytes[ipHeaderLen:]

	switch protoNum {
	case 6: // TCP
		res.Protocol = "TCP"
		if len(transportBytes) < 20 {
			return nil, fmt.Errorf("truncated TCP header (len %d < 20)", len(transportBytes))
		}
		res.SourcePort = int(binary.BigEndian.Uint16(transportBytes[0:2]))
		res.DestinationPort = int(binary.BigEndian.Uint16(transportBytes[2:4]))
		res.TCPSeq = binary.BigEndian.Uint32(transportBytes[4:8])
		res.TCPAck = binary.BigEndian.Uint32(transportBytes[8:12])

		dataOffset := int(transportBytes[12]>>4) * 4
		flagsByte := transportBytes[13]

		var flags []string
		if flagsByte&0x02 != 0 {
			flags = append(flags, "SYN")
		}
		if flagsByte&0x10 != 0 {
			flags = append(flags, "ACK")
		}
		if flagsByte&0x08 != 0 {
			flags = append(flags, "PSH")
		}
		if flagsByte&0x01 != 0 {
			flags = append(flags, "FIN")
		}
		if flagsByte&0x04 != 0 {
			flags = append(flags, "RST")
		}
		if flagsByte&0x20 != 0 {
			flags = append(flags, "URG")
		}
		res.TCPFlags = strings.Join(flags, "|")
		res.TCPWindow = int(binary.BigEndian.Uint16(transportBytes[14:16]))

		if len(transportBytes) > dataOffset {
			payload = transportBytes[dataOffset:]
		}

	case 17: // UDP
		res.Protocol = "UDP"
		if len(transportBytes) < 8 {
			return nil, fmt.Errorf("truncated UDP header (len %d < 8)", len(transportBytes))
		}
		res.SourcePort = int(binary.BigEndian.Uint16(transportBytes[0:2]))
		res.DestinationPort = int(binary.BigEndian.Uint16(transportBytes[2:4]))
		if len(transportBytes) > 8 {
			payload = transportBytes[8:]
		}

	case 1: // ICMP
		res.Protocol = "ICMP"
		return nil, fmt.Errorf("unsupported transport protocol ICMP (1)")

	default:
		return nil, fmt.Errorf("unsupported transport protocol: %d", protoNum)
	}

	res.PayloadLength = len(payload)
	if len(payload) > 0 {
		previewLimit := 256
		if len(payload) < previewLimit {
			previewLimit = len(payload)
		}
		res.PayloadHex = hex.EncodeToString(payload[:previewLimit])

		var asciiBuilder strings.Builder
		for _, b := range payload[:previewLimit] {
			if unicode.IsPrint(rune(b)) && b < 128 {
				asciiBuilder.WriteByte(b)
			} else {
				asciiBuilder.WriteByte('.')
			}
		}
		res.PayloadASCII = asciiBuilder.String()

		// High-level Protocol Sniffing
		inspectPayload(res, payload)
	}

	return res, nil
}

// inspectPayload sniffs TLS ClientHello, HTTP methods, and DNS questions.
func inspectPayload(res *DissectedPacket, payload []byte) {
	if len(payload) == 0 {
		return
	}

	// 1. TLS Handshake Detection (0x16, 0x03, 0x01/0x02/0x03)
	if payload[0] == 0x16 && len(payload) > 5 && payload[1] == 0x03 {
		res.DetectedProto = "TLS"
		if len(payload) > 43 && payload[5] == 0x01 { // ClientHello
			sni := extractTLSSNI(payload)
			if sni != "" {
				res.DetectedProto = "TLS (ClientHello)"
				res.AppInfo = fmt.Sprintf("SNI: %s", sni)
				res.ExtraMetadata["sni"] = sni
			}
		}
		return
	}

	// 2. HTTP Detection
	str := string(payload)
	if strings.HasPrefix(str, "GET ") || strings.HasPrefix(str, "POST ") ||
		strings.HasPrefix(str, "CONNECT ") || strings.HasPrefix(str, "HEAD ") ||
		strings.HasPrefix(str, "PUT ") || strings.HasPrefix(str, "DELETE ") {
		res.DetectedProto = "HTTP"
		lines := strings.Split(str, "\r\n")
		if len(lines) > 0 {
			res.AppInfo = lines[0] // e.g. "GET / HTTP/1.1"
			for _, line := range lines[1:] {
				if strings.HasPrefix(strings.ToLower(line), "host:") {
					res.ExtraMetadata["host"] = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
					break
				}
			}
		}
		return
	}

	// 3. DNS Detection (Port 53 or 853)
	if res.DestinationPort == 53 || res.SourcePort == 53 {
		res.DetectedProto = "DNS"
		domain := extractDNSDomain(payload)
		if domain != "" {
			res.AppInfo = fmt.Sprintf("Query: %s", domain)
			res.ExtraMetadata["query"] = domain
		}
		return
	}
}

// extractTLSSNI extracts the Server Name Indication string from a TLS ClientHello packet.
func extractTLSSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}
	// Skip TLS Record Header (5 bytes) + Handshake Type & Length (4 bytes) + Version (2 bytes) + Random (32 bytes)
	pos := 43
	if pos >= len(data) {
		return ""
	}
	// Session ID length
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return ""
	}
	// Cipher Suites length
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return ""
	}
	// Compression Methods length
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen
	if pos+2 > len(data) {
		return ""
	}
	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // server_name extension
			if pos+2 <= end {
				listLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
				if pos+2+listLen <= end && pos+5 <= end {
					nameType := data[pos+2]
					if nameType == 0 { // host_name
						nameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
						if pos+5+nameLen <= end {
							return string(data[pos+5 : pos+5+nameLen])
						}
					}
				}
			}
		}
		pos += extLen
	}
	return ""
}

// extractDNSDomain extracts simple domain from standard DNS query header.
func extractDNSDomain(data []byte) string {
	if len(data) < 12 {
		return ""
	}
	pos := 12
	var labels []string
	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			break
		}
		pos++
		if pos+length > len(data) {
			break
		}
		labels = append(labels, string(data[pos:pos+length]))
		pos += length
	}
	if len(labels) > 0 {
		return strings.Join(labels, ".")
	}
	return ""
}
