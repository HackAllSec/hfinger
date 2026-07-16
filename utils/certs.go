package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"hfinger/config"
	"hfinger/logger"

	"gitee.com/Trisia/gotlcp/tlcp"
	emSM2 "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// 统一CA结构
type UnifiedCA struct {
	RSACert *x509.Certificate
	RSAKey  *rsa.PrivateKey
	GMCert  *smx509.Certificate
	GMKey   *emSM2.PrivateKey
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
	if _, err := os.Stat(config.GMCertsPath); os.IsNotExist(err) {
		logger.Warn("Generating new GM root CA certificates...")
		if err := generateSelfSignedGMCert(config.GMCertsPath, config.GMKeyPath); err != nil {
			return err
		}
		logger.Success("GM root CA certificates generated successfully")
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

	gmCertPEM, err := os.ReadFile(config.GMCertsPath)
	if err != nil {
		return nil, err
	}
	gmKeyPEM, err := os.ReadFile(config.GMKeyPath)
	if err != nil {
		return nil, err
	}
	gmCACert, err := smx509.ParseCertificatePEM(gmCertPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(gmKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("parse GM CA private key: invalid PEM")
	}
	gmCAKey, err := parseTLCPPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &UnifiedCA{
		RSACert: rsaCert,
		RSAKey:  rsaTLSCert.PrivateKey.(*rsa.PrivateKey),
		GMCert:  gmCACert,
		GMKey:   gmCAKey,
	}, nil
}

func GenerateServerTLSCert(host string) (*tls.Certificate, error) {
	if globalCA == nil {
		return nil, fmt.Errorf("CA not initialized")
	}
	return generateStdServerCert(host, globalCA.RSACert, globalCA.RSAKey)
}

func GenerateServerTLCPCerts(host string) (*tlcp.Certificate, *tlcp.Certificate, error) {
	if globalCA == nil {
		return nil, nil, fmt.Errorf("CA not initialized")
	}

	signCert, err := generateTLCPServerCert(host, globalCA.GMCert, globalCA.GMKey)
	if err != nil {
		return nil, nil, err
	}
	encCert, err := generateTLCPServerCert(host, globalCA.GMCert, globalCA.GMKey)
	if err != nil {
		return nil, nil, err
	}
	return signCert, encCert, nil
}

func parseTLCPPrivateKey(der []byte) (*emSM2.PrivateKey, error) {
	if key, err := smx509.ParsePKCS8PrivateKey(der); err == nil {
		if sm2Key, ok := key.(*emSM2.PrivateKey); ok {
			return sm2Key, nil
		}
		return nil, fmt.Errorf("unexpected PKCS#8 key type %T", key)
	}
	if key, err := smx509.ParseSM2PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported SM2 private key format")
}

func generateTLCPServerCert(host string, caCert *smx509.Certificate, caKey *emSM2.PrivateKey) (*tlcp.Certificate, error) {
	priv, err := emSM2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)
	template := smx509.Certificate{
		SerialNumber: big.NewInt(0).SetInt64(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(1, 0, 0),
		SignatureAlgorithm: smx509.SM2WithSM3,
		KeyUsage:           smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
	}

	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := smx509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return &tlcp.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
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

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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

func generateSelfSignedGMCert(certPath, keyPath string) error {
	priv, err := emSM2.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * 24 * time.Hour)

	template := smx509.Certificate{
		SerialNumber: big.NewInt(time.Now().UTC().UnixNano()),
		Subject: pkix.Name{
			CommonName:         "HackAllSec GM CA",
			Organization:       []string{"HackAllSec"},
			OrganizationalUnit: []string{"HackAllSec GM CA"},
			Country:            []string{"CN"},
			Province:           []string{"HackAllSec"},
			Locality:           []string{"HackAllSec"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := smx509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
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

	keyBytes, err := smx509.MarshalSM2PrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return os.WriteFile(keyPath, keyPEM, 0600)
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
