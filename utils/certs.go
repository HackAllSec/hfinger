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
    notAfter := notBefore.Add(365 * 24 * time.Hour)

    template := x509.Certificate{
        SerialNumber: big.NewInt(time.Now().UTC().UnixNano()),
        Subject: pkix.Name{
            Organization: []string{"HackAllSec CA"},
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

func LoadCertificate() (*tls.Config, error) {
    caCert, err := os.ReadFile(config.CertsPath)
    if err != nil {
        return nil, err
    }

    caKey, err := os.ReadFile(config.KeyPath)
    if err != nil {
        return nil, err
    }

    cert, err := tls.X509KeyPair(caCert, caKey)
    if err != nil {
        return nil, err
    }

    return &tls.Config{
        Certificates: []tls.Certificate{cert},
    }, nil
}
