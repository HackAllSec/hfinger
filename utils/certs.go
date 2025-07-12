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

    "hfinger/config"
    "github.com/fatih/color"
)

func EnsureCerts() error {
    if err := os.MkdirAll(config.CertsDir, 0755); err != nil {
        return err
    }

    if _, err := os.Stat(config.CertsPath); os.IsNotExist(err) {
        color.Yellow("[%s] [-] Warning: Certificates not found, generating new ones...", time.Now().Format("01-02 15:04:05"))
        if err := generateSelfSignedCert(config.CertsPath, config.KeyPath); err != nil {
            return err
        } else {
            color.Green("[%s] [+] The certificate has been successfully generated", time.Now().Format("01-02 15:04:05"))
        }
    }

    return nil
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

func GenerateServerCert(host string) (*tls.Certificate, error) {
    caTLSCert, err := LoadCertificate(config.CertsPath, config.KeyPath)
    if err != nil {
        return nil, err
    }

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

    caCert, err := x509.ParseCertificate(caTLSCert.Certificate[0])
    if err != nil {
        return nil, err
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caTLSCert.PrivateKey)
    if err != nil {
        return nil, err
    }

    return &tls.Certificate{
        Certificate: [][]byte{derBytes},
        PrivateKey:  privateKey,
    }, nil
}
