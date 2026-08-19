package security

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	PCAPMagicLittleEndian uint32 = 0xa1b2c3d4
	PCAPVersionMajor      uint16 = 2
	PCAPVersionMinor      uint16 = 4
	PCAPSnapLen           uint32 = 65535
	PCAPLinkTypeRawIP     uint32 = 101 // DLT_RAW (Raw IPv4/IPv6 without Link layer)
	PCAPLinkTypeEthernet  uint32 = 1   // DLT_EN10MB (Standard Ethernet 14-byte header)
)

var pcapWriteMu sync.Mutex

// WritePcapGlobalHeader writes the 24-byte PCAP file header if the file does not exist or is empty.
func WritePcapGlobalHeader(f *os.File, linkType uint32) error {
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.Size() > 0 {
		return nil // Header already written
	}

	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], PCAPMagicLittleEndian)
	binary.LittleEndian.PutUint16(header[4:6], PCAPVersionMajor)
	binary.LittleEndian.PutUint16(header[6:8], PCAPVersionMinor)
	binary.LittleEndian.PutUint32(header[8:12], 0) // thiszone
	binary.LittleEndian.PutUint32(header[12:16], 0) // sigfigs
	binary.LittleEndian.PutUint32(header[16:20], PCAPSnapLen)
	binary.LittleEndian.PutUint32(header[20:24], linkType)

	_, err = f.Write(header)
	return err
}

// WritePacketToPcap appends a raw network packet to a standard PCAP file.
func WritePacketToPcap(filePath string, packetBytes []byte, timestampMs int64) error {
	pcapWriteMu.Lock()
	defer pcapWriteMu.Unlock()

	if len(packetBytes) == 0 {
		return nil
	}

	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for pcap: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open pcap file %s: %w", filePath, err)
	}
	defer f.Close()

	if err := WritePcapGlobalHeader(f, PCAPLinkTypeRawIP); err != nil {
		return fmt.Errorf("failed to write global pcap header: %w", err)
	}

	if timestampMs <= 0 {
		timestampMs = time.Now().UnixMilli()
	}

	tsSec := uint32(timestampMs / 1000)
	tsUsec := uint32((timestampMs % 1000) * 1000)
	pktLen := uint32(len(packetBytes))

	pktHeader := make([]byte, 16)
	binary.LittleEndian.PutUint32(pktHeader[0:4], tsSec)
	binary.LittleEndian.PutUint32(pktHeader[4:8], tsUsec)
	binary.LittleEndian.PutUint32(pktHeader[8:12], pktLen)
	binary.LittleEndian.PutUint32(pktHeader[12:16], pktLen)

	if _, err := f.Write(pktHeader); err != nil {
		return err
	}
	_, err = f.Write(packetBytes)
	return err
}

// SynthesizeRawIPv4Packet constructs a valid wire-format IPv4 + TCP/UDP packet.
func SynthesizeRawIPv4Packet(
	proto string,
	srcIPStr string,
	srcPort int,
	dstIPStr string,
	dstPort int,
	tcpFlags byte,
	seq uint32,
	ack uint32,
	window uint16,
	payload []byte,
) []byte {
	isTCP := strings.EqualFold(proto, "TCP") || proto == ""
	ipProto := byte(6) // TCP
	transportHeaderLen := 20
	if !isTCP {
		ipProto = byte(17) // UDP
		transportHeaderLen = 8
	}

	srcIP := net.ParseIP(srcIPStr).To4()
	if srcIP == nil {
		srcIP = net.IPv4(10, 0, 0, 2).To4()
	}

	dstIP := net.ParseIP(dstIPStr).To4()
	if dstIP == nil {
		dstIP = net.IPv4(8, 8, 8, 8).To4()
	}

	if srcPort <= 0 {
		srcPort = 49152 + rand.Intn(16383)
	}
	if window == 0 {
		window = 64240
	}

	totalLen := 20 + transportHeaderLen + len(payload)
	packet := make([]byte, totalLen)

	// --- 1. IPv4 Header (20 bytes) ---
	packet[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	packet[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234) // ID
	packet[6] = 0x40                               // Don't Fragment flag
	packet[7] = 0x00
	packet[8] = 64      // TTL
	packet[9] = ipProto // Protocol (6 TCP, 17 UDP)
	// Checksum initially 0
	copy(packet[12:16], srcIP)
	copy(packet[16:20], dstIP)

	// Calculate and insert IPv4 Header Checksum
	chk := calculateIPChecksum(packet[0:20])
	binary.BigEndian.PutUint16(packet[10:12], chk)

	// --- 2. Transport Header ---
	transportOffset := 20
	if isTCP {
		binary.BigEndian.PutUint16(packet[transportOffset:transportOffset+2], uint16(srcPort))
		binary.BigEndian.PutUint16(packet[transportOffset+2:transportOffset+4], uint16(dstPort))
		binary.BigEndian.PutUint32(packet[transportOffset+4:transportOffset+8], seq)
		binary.BigEndian.PutUint32(packet[transportOffset+8:transportOffset+12], ack)
		packet[transportOffset+12] = 0x50 // Data Offset 5 (20 bytes header)
		packet[transportOffset+13] = tcpFlags
		binary.BigEndian.PutUint16(packet[transportOffset+14:transportOffset+16], window)
		// Checksum (at 16:18) and Urgent Pointer (at 18:20) left as 0
		if len(payload) > 0 {
			copy(packet[transportOffset+20:], payload)
		}
	} else {
		binary.BigEndian.PutUint16(packet[transportOffset:transportOffset+2], uint16(srcPort))
		binary.BigEndian.PutUint16(packet[transportOffset+2:transportOffset+4], uint16(dstPort))
		binary.BigEndian.PutUint16(packet[transportOffset+4:transportOffset+6], uint16(transportHeaderLen+len(payload)))
		// Checksum left as 0
		if len(payload) > 0 {
			copy(packet[transportOffset+8:], payload)
		}
	}

	return packet
}

func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
