package utils

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"encoding/pem"
	"math/big"
	"os"
	"time"
	"net"
	"fmt"
	"sync"

	"hfinger/config"
    "hfinger/logger"
	"github.com/tjfoc/gmsm/sm2"
	gmX509 "github.com/tjfoc/gmsm/x509"
)

// 统一CA结构
type UnifiedCA struct {
	RSACert    *x509.Certificate
	RSAKey     *rsa.PrivateKey
	GMRootPool *gmX509.CertPool
}

var (
	globalCA *UnifiedCA
	caMutex  sync.Mutex
)

func EnsureCerts() error {
	caMutex.Lock()
	defer caMutex.Unlock()
	
	if globalCA != nil {
		return nil
	}
	
	// 创建证书目录
	if err := os.MkdirAll(config.CertsDir, 0755); err != nil {
		return err
	}
	
	// 检查RSA根证书是否存在
	if _, err := os.Stat(config.CertsPath); os.IsNotExist(err) {
		logger.Warn("Generating new root CA certificates...")
		
		if err := generateSelfSignedCert(config.CertsPath, config.KeyPath); err != nil {
			return err
		}
		logger.Success("Root CA certificates generated successfully")
	}
	
	// 加载证书
	ca, err := loadUnifiedCA()
	if err != nil {
		return err
	}
	
	globalCA = ca
	return nil
}

func loadUnifiedCA() (*UnifiedCA, error) {
	// 加载RSA根证书
	rsaTLSCert, err := LoadCertificate(config.CertsPath, config.KeyPath)
	if err != nil {
		return nil, err
	}
	
	// 解析RSA根证书
	rsaCert, err := x509.ParseCertificate(rsaTLSCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	
	// 创建国密根证书池
	rootPool := gmX509.NewCertPool()
	
	// 将RSA根证书转换为国密格式并添加到证书池
	gmCert, err := gmX509.ParseCertificate(rsaCert.Raw)
	if err != nil {
		return nil, err
	}
	rootPool.AddCert(gmCert)
	
	return &UnifiedCA{
		RSACert:    rsaCert,
		RSAKey:     rsaTLSCert.PrivateKey.(*rsa.PrivateKey),
		GMRootPool: rootPool,
	}, nil
}

// 生成服务器证书
func GenerateServerCert(host string) (*tls.Certificate, *tls.Certificate, error) {
	if globalCA == nil {
		return nil, nil, fmt.Errorf("CA not initialized")
	}
	
	// 生成标准证书
	stdCert, err := generateStdServerCert(host, globalCA.RSACert, globalCA.RSAKey)
	if err != nil {
		return nil, nil, err
	}
	
	// 生成国密证书
	gmCert, err := generateGMServerCert(host, globalCA.RSACert, globalCA.RSAKey)
	if err != nil {
		return nil, nil, err
	}
	
	return stdCert, gmCert, nil
}

// 生成标准服务器证书
func generateStdServerCert(host string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)

	template := x509.Certificate{
		SerialNumber: big.NewInt(0).SetInt64(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}, nil
}

// 生成国密服务器证书
func generateGMServerCert(host string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	// 生成SM2密钥对
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)
	serial := big.NewInt(0).SetInt64(time.Now().UnixNano())

	// 创建国密证书模板
	template := gmX509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    gmX509.KeyUsageKeyEncipherment | gmX509.KeyUsageDigitalSignature,
		ExtKeyUsage: []gmX509.ExtKeyUsage{gmX509.ExtKeyUsageServerAuth},
	}

	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// 将标准CA证书转换为国密格式
	gmCACert, err := gmX509.ParseCertificate(caCert.Raw)
	if err != nil {
		return nil, err
	}
	
	// 创建国密证书
	derBytes, err := gmX509.CreateCertificate(&template, gmCACert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	// 转换为TLS证书格式
	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// 获取国密根证书池
func GetGMRootPool() *gmX509.CertPool {
	if globalCA == nil {
		return nil
	}
	return globalCA.GMRootPool
}

func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UTC().UnixNano()),
		Subject: pkix.Name{
			CommonName:         "HackAllSec CA",
			Organization:       []string{"HackAllSec"},
			OrganizationalUnit: []string{"HackAllSec CA"},
			Country:            []string{"CN"},
			Province:           []string{"HackAllSec"},
			Locality:           []string{"HackAllSec"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}

	return nil
}

func LoadCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEMBlock, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}