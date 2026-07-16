package models

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type ServiceFingerprint struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol,omitempty"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
}

func ProbeServices(host string, ports []int, timeout time.Duration) []ServiceFingerprint {
	results := make([]ServiceFingerprint, 0, len(ports))
	for _, port := range ports {
		if result, ok := probeService(host, port, timeout); ok {
			results = append(results, result)
		}
	}
	return results
}

func WriteServiceJSONL(path string, results []ServiceFingerprint) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return err
		}
	}
	return nil
}

func PrintServiceResults(results []ServiceFingerprint) {
	for _, result := range results {
		data, _ := json.Marshal(result)
		fmt.Println(string(data))
	}
}

func ParsePorts(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("ports cannot be empty")
	}
	seen := map[int]struct{}{}
	var ports []int
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, err
			}
			if start > end {
				start, end = end, start
			}
			for port := start; port <= end; port++ {
				if validPort(port) {
					if _, ok := seen[port]; !ok {
						seen[port] = struct{}{}
						ports = append(ports, port)
					}
				}
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		if !validPort(port) {
			return nil, fmt.Errorf("invalid port %d", port)
		}
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func probeService(host string, port int, timeout time.Duration) (ServiceFingerprint, bool) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ServiceFingerprint{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	result := ServiceFingerprint{Host: host, Port: port}
	if port == 5432 {
		return probePostgreSQL(conn, result), true
	}
	if port == 3389 {
		return probeRDP(conn, result), true
	}
	if port == 1883 || port == 8883 {
		return probeMQTT(conn, result), true
	}
	if port == 6379 {
		return probeRedis(conn, result), true
	}
	if port == 3306 {
		return readMySQLHandshake(conn, result), true
	}
	return readGenericBanner(conn, result), true
}

func readGenericBanner(conn net.Conn, result ServiceFingerprint) ServiceFingerprint {
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	banner = cleanBanner(banner)
	switch {
	case strings.HasPrefix(banner, "SSH-"):
		result.Protocol = "ssh"
		result.Product = "SSH"
		result.Version = strings.TrimPrefix(banner, "SSH-")
		result.Confidence = 95
		result.Evidence = []string{"SSH identification string"}
	case banner != "":
		result.Protocol = "tcp"
		result.Banner = banner
		result.Confidence = 50
		result.Evidence = []string{"generic TCP banner"}
	}
	result.Banner = banner
	return result
}

func probeRedis(conn net.Conn, result ServiceFingerprint) ServiceFingerprint {
	_, _ = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	banner := cleanBanner(string(buf[:n]))
	result.Protocol = "redis"
	result.Product = "Redis"
	result.Banner = banner
	if strings.HasPrefix(banner, "+PONG") || strings.Contains(strings.ToUpper(banner), "NOAUTH") {
		result.Confidence = 95
		result.Evidence = []string{"Redis RESP PING response"}
	}
	return result
}

func readMySQLHandshake(conn net.Conn, result ServiceFingerprint) ServiceFingerprint {
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n < 6 {
		return result
	}
	payload := buf[4:n]
	if len(payload) < 2 || payload[0] != 0x0a {
		return result
	}
	versionEnd := 1
	for versionEnd < len(payload) && payload[versionEnd] != 0x00 {
		versionEnd++
	}
	result.Protocol = "mysql"
	result.Product = "MySQL"
	result.Version = string(payload[1:versionEnd])
	result.Banner = cleanBanner(result.Version)
	result.Confidence = 95
	result.Evidence = []string{"MySQL protocol handshake"}
	return result
}

func probePostgreSQL(conn net.Conn, result ServiceFingerprint) ServiceFingerprint {
	packet := make([]byte, 8)
	binary.BigEndian.PutUint32(packet[0:4], 8)
	binary.BigEndian.PutUint32(packet[4:8], 80877103)
	_, _ = conn.Write(packet)
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	result.Protocol = "postgresql"
	result.Product = "PostgreSQL"
	result.Banner = cleanBanner(string(buf[:n]))
	if n > 0 && (buf[0] == 'S' || buf[0] == 'N') {
		result.Confidence = 90
		result.Evidence = []string{"PostgreSQL SSLRequest response"}
	}
	return result
}

func probeRDP(conn net.Conn, result ServiceFingerprint) ServiceFingerprint {
	_, _ = conn.Write([]byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00})
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	result.Protocol = "rdp"
	result.Product = "RDP"
	result.Banner = fmt.Sprintf("%x", buf[:n])
	if n >= 4 && buf[0] == 0x03 && buf[1] == 0x00 {
		result.Confidence = 90
		result.Evidence = []string{"RDP TPKT negotiation response"}
	}
	return result
}

func probeMQTT(conn net.Conn, result ServiceFingerprint) ServiceFingerprint {
	_, _ = conn.Write([]byte{0x10, 0x0e, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00})
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	result.Protocol = "mqtt"
	result.Product = "MQTT"
	result.Banner = fmt.Sprintf("%x", buf[:n])
	if n >= 4 && buf[0] == 0x20 {
		result.Confidence = 90
		result.Evidence = []string{"MQTT CONNACK response"}
	}
	return result
}

func cleanBanner(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return strings.TrimSpace(value)
}

func validPort(port int) bool {
	return port > 0 && port <= 65535
}
