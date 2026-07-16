package utils

import (
	"path/filepath"
	"testing"

	"hfinger/config"
)

func TestEnsureCertsGeneratesSeparateGMCA(t *testing.T) {
	certDir := t.TempDir()
	oldCertsDir := config.CertsDir
	oldCertsPath := config.CertsPath
	oldKeyPath := config.KeyPath
	oldGMCertsPath := config.GMCertsPath
	oldGMKeyPath := config.GMKeyPath
	oldGlobalCA := globalCA
	config.CertsDir = certDir
	config.CertsPath = filepath.Join(certDir, config.CaCertFile)
	config.KeyPath = filepath.Join(certDir, config.CaKeyFile)
	config.GMCertsPath = filepath.Join(certDir, config.GMCaCertFile)
	config.GMKeyPath = filepath.Join(certDir, config.GMCaKeyFile)
	globalCA = nil
	t.Cleanup(func() {
		config.CertsDir = oldCertsDir
		config.CertsPath = oldCertsPath
		config.KeyPath = oldKeyPath
		config.GMCertsPath = oldGMCertsPath
		config.GMKeyPath = oldGMKeyPath
		globalCA = oldGlobalCA
	})

	if err := EnsureCerts(); err != nil {
		t.Fatalf("EnsureCerts() unexpected error: %v", err)
	}
	if globalCA == nil || globalCA.RSACert == nil || globalCA.GMCert == nil || globalCA.GMKey == nil {
		t.Fatalf("EnsureCerts() did not initialize both RSA and GM CAs")
	}
	if globalCA.RSACert.RawSubject == nil || globalCA.GMCert.RawSubject == nil {
		t.Fatalf("CA subjects should not be empty")
	}
	if globalCA.RSACert.Subject.CommonName == globalCA.GMCert.Subject.CommonName {
		t.Fatalf("RSA CA and GM CA should be separate certificates")
	}
}

func TestGenerateServerGMTLSCertsUsesGMCA(t *testing.T) {
	certDir := t.TempDir()
	oldCertsDir := config.CertsDir
	oldCertsPath := config.CertsPath
	oldKeyPath := config.KeyPath
	oldGMCertsPath := config.GMCertsPath
	oldGMKeyPath := config.GMKeyPath
	oldGlobalCA := globalCA
	config.CertsDir = certDir
	config.CertsPath = filepath.Join(certDir, config.CaCertFile)
	config.KeyPath = filepath.Join(certDir, config.CaKeyFile)
	config.GMCertsPath = filepath.Join(certDir, config.GMCaCertFile)
	config.GMKeyPath = filepath.Join(certDir, config.GMCaKeyFile)
	globalCA = nil
	t.Cleanup(func() {
		config.CertsDir = oldCertsDir
		config.CertsPath = oldCertsPath
		config.KeyPath = oldKeyPath
		config.GMCertsPath = oldGMCertsPath
		config.GMKeyPath = oldGMKeyPath
		globalCA = oldGlobalCA
	})

	if err := EnsureCerts(); err != nil {
		t.Fatalf("EnsureCerts() unexpected error: %v", err)
	}
	_, _, gmSignCert, gmEncCert, err := GenerateServerGMTLSCerts("example.com")
	if err != nil {
		t.Fatalf("GenerateServerGMTLSCerts() unexpected error: %v", err)
	}
	if gmSignCert == nil || gmEncCert == nil {
		t.Fatalf("GenerateServerGMTLSCerts() did not return GM sign/encryption certificates")
	}
	if len(gmSignCert.Certificate) == 0 || len(gmEncCert.Certificate) == 0 {
		t.Fatalf("GM sign/encryption certificates should contain DER data")
	}
}
