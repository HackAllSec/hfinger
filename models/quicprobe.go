package models

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"time"
)

func probeQUICVersions(targetURL string) []string {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return nil
	}
	address := net.JoinHostPort(parsed.Hostname(), targetPort(parsed, "443"))
	conn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	packet := buildQUICVersionNegotiationProbe()
	if _, err := conn.Write(packet); err != nil {
		return nil
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return parseQUICVersionNegotiation(buf[:n])
}

func buildQUICVersionNegotiationProbe() []byte {
	dcid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	packet := []byte{0xc0}
	packet = append(packet, 0x0a, 0x0a, 0x0a, 0x0a)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, 0x00)
	return packet
}

func parseQUICVersionNegotiation(packet []byte) []string {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		return nil
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != 0 {
		return nil
	}
	offset := 5
	if offset >= len(packet) {
		return nil
	}
	dcidLen := int(packet[offset])
	offset++
	if offset+dcidLen >= len(packet) {
		return nil
	}
	offset += dcidLen
	scidLen := int(packet[offset])
	offset++
	if offset+scidLen > len(packet) {
		return nil
	}
	offset += scidLen
	versions := make([]string, 0, (len(packet)-offset)/4)
	for offset+4 <= len(packet) {
		value := binary.BigEndian.Uint32(packet[offset : offset+4])
		if value != 0 {
			versions = append(versions, fmt.Sprintf("0x%08x", value))
		}
		offset += 4
	}
	return versions
}
