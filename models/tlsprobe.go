package models

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type rawJA3SInfo struct {
	Hash string
	Raw  string
}

func probeRawJA3S(targetURL string) rawJA3SInfo {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return rawJA3SInfo{}
	}
	address := net.JoinHostPort(parsed.Hostname(), targetPort(parsed, "443"))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return rawJA3SInfo{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write(buildClientHello(parsed.Hostname())); err != nil {
		return rawJA3SInfo{}
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 22 {
		return rawJA3SInfo{}
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length <= 0 || length > 16384 {
		return rawJA3SInfo{}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return rawJA3SInfo{}
	}
	raw, ok := parseServerHelloJA3S(payload)
	if !ok {
		return rawJA3SInfo{}
	}
	sum := md5.Sum([]byte(raw))
	return rawJA3SInfo{Hash: hex.EncodeToString(sum[:]), Raw: raw}
}

func buildClientHello(host string) []byte {
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	cipherSuites := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0x009e, 0x009c}
	extensions := buildClientHelloExtensions(host)

	var hello []byte
	hello = append(hello, 0x03, 0x03)
	hello = append(hello, randomBytes...)
	hello = append(hello, 0x00)
	hello = appendUint16(hello, uint16(len(cipherSuites)*2))
	for _, suite := range cipherSuites {
		hello = appendUint16(hello, suite)
	}
	hello = append(hello, 0x01, 0x00)
	hello = appendUint16(hello, uint16(len(extensions)))
	hello = append(hello, extensions...)

	handshake := []byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
	handshake = append(handshake, hello...)

	record := []byte{0x16, 0x03, 0x01}
	record = appendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	return record
}

func buildClientHelloExtensions(host string) []byte {
	var extensions []byte
	if host != "" && net.ParseIP(host) == nil {
		name := []byte(host)
		serverName := []byte{0x00}
		serverName = appendUint16(serverName, uint16(len(name)))
		serverName = append(serverName, name...)
		list := appendUint16(nil, uint16(len(serverName)))
		list = append(list, serverName...)
		extensions = appendExtension(extensions, 0x0000, list)
	}
	extensions = appendExtension(extensions, 0x000a, []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})
	extensions = appendExtension(extensions, 0x000b, []byte{0x01, 0x00})
	extensions = appendExtension(extensions, 0x000d, []byte{0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03})
	extensions = appendExtension(extensions, 0x0010, []byte{0x00, 0x0e, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	extensions = appendExtension(extensions, 0x002b, []byte{0x03, 0x04, 0x03, 0x03, 0x03, 0x02})
	return extensions
}

func appendExtension(dst []byte, extensionType uint16, data []byte) []byte {
	dst = appendUint16(dst, extensionType)
	dst = appendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}

func parseServerHelloJA3S(payload []byte) (string, bool) {
	if len(payload) < 4 || payload[0] != 0x02 {
		return "", false
	}
	handshakeLength := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if handshakeLength <= 0 || 4+handshakeLength > len(payload) {
		return "", false
	}
	body := payload[4 : 4+handshakeLength]
	if len(body) < 38 {
		return "", false
	}
	version := binary.BigEndian.Uint16(body[0:2])
	offset := 34
	sessionLength := int(body[offset])
	offset++
	if offset+sessionLength+3 > len(body) {
		return "", false
	}
	offset += sessionLength
	cipher := binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 3
	extensions := []string{}
	if offset+2 <= len(body) {
		extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		end := offset + extensionsLength
		if end > len(body) {
			return "", false
		}
		for offset+4 <= end {
			extensionType := binary.BigEndian.Uint16(body[offset : offset+2])
			extensionLength := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
			offset += 4
			if offset+extensionLength > end {
				return "", false
			}
			extensions = append(extensions, strconv.Itoa(int(extensionType)))
			offset += extensionLength
		}
	}
	return fmt.Sprintf("%d,%d,%s", version, cipher, strings.Join(extensions, "-")), true
}

func appendUint16(dst []byte, value uint16) []byte {
	return append(dst, byte(value>>8), byte(value))
}

func targetPort(parsed *url.URL, fallback string) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	return fallback
}
