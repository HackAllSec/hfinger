package logger

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"sync"
	"time"

	"github.com/fatih/color"
)

var logMu sync.Mutex

/* ---------- 错误分类 ---------- */
type ErrorClassifier struct{}

func (ErrorClassifier) Classify(err error) (category, friendlyMsg string) {
	if err == nil {
		return "", ""
	}
	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "actively refused"),
		strings.Contains(msg, "malformed"):
		return "CONNECTION", "Connection refused / malformed"
	case strings.Contains(msg, "reset by peer"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "eof"):
		return "CONNECTION", "Connection reset"
	case strings.Contains(msg, "timeout"):
		return "TIMEOUT", "Timeout"
	case strings.Contains(msg, "dns") || strings.Contains(msg, "no such host"):
		return "DNS", "DNS resolution failed"
	case strings.Contains(msg, "http2: stream closed"):
    	return "HTTP2", "HTTP/2 stream closed by peer"
	case strings.Contains(msg, "request method or response status code does not allow body"):
    	return "PROTOCOL", "Response body not allowed for this status/method"
	case strings.Contains(msg, "wsarecv") && strings.Contains(msg, "aborted"):
    	return "CONNECTION", "Local connection aborted"
	case strings.Contains(msg, "x509:"):
		return "CERTIFICATE", "Certificate error"
	case isSyscallError(err, syscall.ECONNREFUSED),
		isSyscallError(err, syscall.ECONNRESET),
		isSyscallError(err, syscall.ECONNABORTED):
		return "CONNECTION", "System network error"
	default:
		return "GENERIC", err.Error()
	}
}

/* ---------- 系统调用判断 ---------- */
func isSyscallError(err error, target syscall.Errno) bool {
	if opErr, ok := err.(*net.OpError); ok {
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
			if errno, ok := sysErr.Err.(syscall.Errno); ok {
				return errno == target
			}
		}
	}
	return false
}

func isDNSError(err error) bool {
	c, _ := ErrorClassifier{}.Classify(err)
	return c == "DNS" 
}

func isCertificateError(err error) bool {
	c, _ := ErrorClassifier{}.Classify(err)
	return c == "CERTIFICATE"
}

func ShouldTerminate(err error) bool {
	c, _ := ErrorClassifier{}.Classify(err)
	return c == "DNS" || c == "CERTIFICATE"
}

func isTemporaryError(err error) bool {
	classifier := ErrorClassifier{}
	category, _ := classifier.Classify(err)

	// 这些错误类型通常不需要终止整个处理流程
	return category == "TIMEOUT" || 
	       category == "CONNECTION" || 
		   category == "HTTP2" || 
	       category == "PROTOCOL"
}

/* ---------- 并发安全日志 ---------- */
func logf(c *color.Color, prefix string, a ...interface{}) {
    logMu.Lock()
    defer logMu.Unlock()
    c.Printf("[%s] "+prefix+"\n", append([]interface{}{time.Now().Format("01-02 15:04:05")}, a...)...)
}

var (
	cyan = color.New(color.FgCyan)
	red   = color.New(color.FgRed)
	white = color.New(color.FgWhite)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
)

func Info(format string, a ...interface{})  { logf(white, format, a...) }
func Warn(format string, a ...interface{})  { logf(yellow, "[-] "+format, a...) }
func Error(format string, a ...interface{}) { logf(red, "[!] "+format, a...) }
func Success(format string, a ...interface{}) { logf(green, "[+] "+format, a...) }
func Hint(format string, a ...interface{}) { logf(cyan, "[*] "+format, a...) }

/* ---------- 友好消息 ---------- */
func friendlyErrorMessage(err error, url string) string {
	if err == nil {
		return ""
	}
	_, msg := ErrorClassifier{}.Classify(err)
	return fmt.Sprintf("Request %s Error: %s", url, msg)
}

// PrintByLevel 根据错误自动选颜色并打印
func PrintByLevel(err error, url string) {
	if err == nil {
		return
	}
	msg := friendlyErrorMessage(err, url)
	switch {
	case isDNSError(err), isCertificateError(err):
		Error("%s", msg)
	case isTemporaryError(err):
		Warn("%s", msg)
	default:
		Error("%s", msg)
	}
}