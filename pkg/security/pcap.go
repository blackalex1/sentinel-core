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
	PCAPLinkTypeRawIP     uint32 = 101 // DLT_RAW
	PCAPLinkTypeEthernet  uint32 = 1   // DLT_EN10MB
)

var pcapMu sync.Mutex

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
	pcapMu.Lock()
	defer pcapMu.Unlock()

	if len(packetBytes) == 0 {
		return nil
	}

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

// SynthesizeRawIPv4Packet constructs a wire-format IPv4 + TCP/UDP packet.
func SynthesizeRawIPv4Packet(
	proto string,
	srcIPStr string,
	srcPort int,
	dstIPStr string,
	dstPort int,
	tcpFlags int,
	seq uint32,
	ack uint32,
	window uint16,
	payload []byte,
) ([]byte, error) {
	srcIP := net.ParseIP(srcIPStr).To4()
	if srcIP == nil {
		srcIP = net.IPv4(10, 0, 0, 2).To4()
	}
	dstIP := net.ParseIP(dstIPStr).To4()
	if dstIP == nil {
		dstIP = net.IPv4(198, 51, 100, 1).To4()
	}

	isTCP := strings.ToUpper(proto) == "TCP" || proto == ""

	var transportHeader []byte
	var ipProto byte

	if isTCP {
		ipProto = 6 // TCP
		th := make([]byte, 20)
		binary.BigEndian.PutUint16(th[0:2], uint16(srcPort))
		binary.BigEndian.PutUint16(th[2:4], uint16(dstPort))
		binary.BigEndian.PutUint32(th[4:8], seq)
		binary.BigEndian.PutUint32(th[8:12], ack)
		th[12] = 0x50 // Data offset: 5 * 32-bit words (20 bytes)
		th[13] = byte(tcpFlags)
		if window == 0 {
			window = 64240
		}
		binary.BigEndian.PutUint16(th[14:16], window)
		// Checksum calculation with pseudo-header
		transportHeader = th
	} else {
		ipProto = 17 // UDP
		th := make([]byte, 8)
		binary.BigEndian.PutUint16(th[0:2], uint16(srcPort))
		binary.BigEndian.PutUint16(th[2:4], uint16(dstPort))
		binary.BigEndian.PutUint16(th[4:6], uint16(8+len(payload)))
		binary.BigEndian.PutUint16(th[6:8], 0) // Optional checksum
		transportHeader = th
	}

	totalLen := 20 + len(transportHeader) + len(payload)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // IPv4, Header Length = 5 words (20 bytes)
	ipHeader[1] = 0x00 // DSCP / ECN
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Intn(65535)))
	ipHeader[6] = 0x40 // Don't Fragment
	ipHeader[7] = 0x00
	ipHeader[8] = 64 // TTL
	ipHeader[9] = ipProto
	// Checksum placeholder at 10..12
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)

	// Compute IPv4 checksum
	var csum uint32
	for i := 0; i < 20; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(ipHeader[i : i+2]))
	}
	for (csum >> 16) > 0 {
		csum = (csum & 0xffff) + (csum >> 16)
	}
	binary.BigEndian.PutUint16(ipHeader[10:12], ^uint16(csum))

	// Assemble final packet
	packet := append(ipHeader, transportHeader...)
	packet = append(packet, payload...)
	return packet, nil
}

// SynthesizeAndRecordThreatPcap creates and logs an incident PCAP packet.
func SynthesizeAndRecordThreatPcap(
	pcapPath string,
	proto string,
	srcIP string,
	srcPort int,
	dstIP string,
	dstPort int,
	threatType string,
	timestampMs int64,
) error {
	payload := []byte(fmt.Sprintf("SENTINEL_THREAT_CAPTURE: type=%s dst=%s:%d", threatType, dstIP, dstPort))
	pkt, err := SynthesizeRawIPv4Packet(proto, srcIP, srcPort, dstIP, dstPort, 0x02 /* SYN */, rand.Uint32(), 0, 64240, payload)
	if err != nil {
		return err
	}
	return WritePacketToPcap(pcapPath, pkt, timestampMs)
}
