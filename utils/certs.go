package utils

import (
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "crypto/rand"
    "encoding/pem"
    "log"
    "math/big"
    "os"
    "path/filepath"
    "time"
)

const (
    certsDir   = "certs"
    caCertFile = "ca.crt"
    caKeyFile  = "ca.key"
)

func EnsureCerts() error {
    if err := os.MkdirAll(certsDir, 0755); err != nil {
        return err
    }

    certsPath := filepath.Join(certsDir, caCertFile)
    keyPath := filepath.Join(certsDir, caKeyFile)

    if _, err := os.Stat(certsPath); os.IsNotExist(err) {
        log.Println("Certificates not found, generating new ones...")
        if err := generateSelfSignedCert(certsPath, keyPath); err != nil {
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
    caCertPath := filepath.Join(certsDir, caCertFile)
    caKeyPath := filepath.Join(certsDir, caKeyFile)

    caCert, err := os.ReadFile(caCertPath)
    if err != nil {
        return nil, err
    }

    caKey, err := os.ReadFile(caKeyPath)
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
