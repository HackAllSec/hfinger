package config

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
)

// FingerprintConfig 定义了指纹配置的结构
type FingerprintConfig struct {
    Finger []Fingerprint `json:"finger"`
}

type Fingerprint struct {
    CMS      string   `json:"cms"`
    Method   string   `json:"method"`
    Location string   `json:"location"`
    Logic    string   `json:"logic"`
    Rule     []string `json:"rule"`
}

// Result 存储指纹识别的结果
type Result struct {
    URL        string
    CMS        string
    Server     string
    StatusCode int
    Title      string
}

type LastResponse struct {
    StatusCode int
    Server     string
    Title      string
}

var (
    Config *FingerprintConfig
    once   sync.Once
    Version = "v1.0.8"
    CertsDir   = "certs"
    CaCertFile = "ca.crt"
    CaKeyFile  = "ca.key"
    CertsPath = filepath.Join(CertsDir, CaCertFile)
    KeyPath = filepath.Join(CertsDir, CaKeyFile)
    Datapath = "data"
    FingerUrl = "https://raw.githubusercontent.com/HackAllSec/hfinger/main/data/finger.json"
    ReleaseUrl = "https://api.github.com/repos/HackAllSec/hfinger/releases/latest"
    Fingerfile = "finger.json"
    Fingerfullpath = filepath.Join(Datapath, Fingerfile)
    Isconfig = false
)

func init() {
    once.Do(func() {
        absPath, pathErr := filepath.Abs(Fingerfullpath)
        if pathErr != nil {
            return
        }

        data, readErr := os.ReadFile(absPath)
        if readErr != nil {
            return
        }

        var loadedConfig FingerprintConfig
        if unmarshalErr := json.Unmarshal(data, &loadedConfig); unmarshalErr != nil {
            return
        }

        Config = &loadedConfig
        Isconfig = true
    })
}
