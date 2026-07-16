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
	"github.com/tjfoc/gmsm/gmtls"
	tjSM2 "github.com/tjfoc/gmsm/sm2"
	gmX509 "github.com/tjfoc/gmsm/x509"
)

// 统一CA结构
type UnifiedCA struct {
	RSACert    *x509.Certificate
	RSAKey     *rsa.PrivateKey
	GMCert     *gmX509.Certificate
	GMKey      *tjSM2.PrivateKey
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
	gmCACert, err := gmX509.ReadCertificateFromPem(gmCertPEM)
	if err != nil {
		return nil, err
	}
	gmCAKey, err := gmX509.ReadPrivateKeyFromPem(gmKeyPEM, nil)
	if err != nil {
		return nil, err
	}

	rootPool := gmX509.NewCertPool()
	rootPool.AddCert(gmCACert)

	return &UnifiedCA{
		RSACert:    rsaCert,
		RSAKey:     rsaTLSCert.PrivateKey.(*rsa.PrivateKey),
		GMCert:     gmCACert,
		GMKey:      gmCAKey,
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
	gmCert, err := generateGMServerCert(host, globalCA.GMCert, globalCA.GMKey)
	if err != nil {
		return nil, nil, err
	}

	return stdCert, gmCert, nil
}

func GenerateServerGMTLSCerts(host string) (*tls.Certificate, *gmtls.Certificate, *gmtls.Certificate, *gmtls.Certificate, error) {
	if globalCA == nil {
		return nil, nil, nil, nil, fmt.Errorf("CA not initialized")
	}
	stdCert, err := generateStdServerCert(host, globalCA.RSACert, globalCA.RSAKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	gmSignCert, err := generateGMServerCert(host, globalCA.GMCert, globalCA.GMKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	gmEncCert, err := generateGMServerCert(host, globalCA.GMCert, globalCA.GMKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return stdCert, toGMTLSCertificate(stdCert), toGMTLSCertificate(gmSignCert), toGMTLSCertificate(gmEncCert), nil
}

func GenerateServerTLCPCerts(host string) (*tlcp.Certificate, *tlcp.Certificate, error) {
	if globalCA == nil {
		return nil, nil, fmt.Errorf("CA not initialized")
	}
	caCert, caKey, err := loadTLCPCA()
	if err != nil {
		return nil, nil, err
	}

	signCert, err := generateTLCPServerCert(host, caCert, caKey)
	if err != nil {
		return nil, nil, err
	}
	encCert, err := generateTLCPServerCert(host, caCert, caKey)
	if err != nil {
		return nil, nil, err
	}
	return signCert, encCert, nil
}

func toGMTLSCertificate(cert *tls.Certificate) *gmtls.Certificate {
	if cert == nil {
		return nil
	}
	return &gmtls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
	}
}

func loadTLCPCA() (*smx509.Certificate, *emSM2.PrivateKey, error) {
	certPEM, err := os.ReadFile(config.GMCertsPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(config.GMKeyPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := smx509.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse TLCP CA certificate: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("parse TLCP CA private key: invalid PEM")
	}
	key, err := parseTLCPPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse TLCP CA private key: %w", err)
	}
	return cert, key, nil
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

// 生成国密服务器证书
func generateGMServerCert(host string, caCert *gmX509.Certificate, caKey *tjSM2.PrivateKey) (*tls.Certificate, error) {
	// 生成SM2密钥对
	priv, err := tjSM2.GenerateKey(rand.Reader)
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
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(1, 0, 0),
		SignatureAlgorithm: gmX509.SM2WithSM3,
		KeyUsage:           gmX509.KeyUsageKeyEncipherment | gmX509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []gmX509.ExtKeyUsage{gmX509.ExtKeyUsageServerAuth},
	}

	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// 创建国密证书
	derBytes, err := gmX509.CreateCertificate(&template, caCert, &priv.PublicKey, caKey)
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
	priv, err := tjSM2.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * 24 * time.Hour)

	template := gmX509.Certificate{
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
		SignatureAlgorithm:    gmX509.SM2WithSM3,
		KeyUsage:              gmX509.KeyUsageKeyEncipherment | gmX509.KeyUsageDigitalSignature | gmX509.KeyUsageCertSign,
		ExtKeyUsage:           []gmX509.ExtKeyUsage{gmX509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := gmX509.CreateCertificate(&template, &template, &priv.PublicKey, priv)
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

	keyPEM, err := gmX509.WritePrivateKeyToPem(priv, nil)
	if err != nil {
		return err
	}
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
