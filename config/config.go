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
    Version = "v1.0.9"
    CertsDir   = "certs"
    CaCertFile = "ca.crt"
    CaKeyFile  = "ca.key"
    CertsPath = filepath.Join(CertsDir, CaCertFile)
    KeyPath = filepath.Join(CertsDir, CaKeyFile)
    Datapath = "data"
    FingerUrl = "https://raw.githubusercontent.com/HackAllSec/hfinger/main/data/finger.json"
    ReleaseUrl = "https://api.github.com/repos/HackAllSec/hfinger/releases/latest"
    Fingerfile = "finger.json"
    ExecutableDir = "."
    Fingerfullpath = filepath.Join(Datapath, Fingerfile)
    Isconfig = false
)

func resolveExecutableDir() string {
    exePath, err := os.Executable()
    if err != nil {
        return "."
    }

    realPath, err := filepath.EvalSymlinks(exePath)
    if err == nil {
        exePath = realPath
    }

    return filepath.Dir(exePath)
}

func initRuntimePaths() {
    ExecutableDir = resolveExecutableDir()
    Datapath = filepath.Join(ExecutableDir, "data")
    Fingerfullpath = filepath.Join(Datapath, Fingerfile)
}

func LoadFingerprintConfig() error {
    initRuntimePaths()

    data, readErr := os.ReadFile(Fingerfullpath)
    if readErr != nil {
        Config = nil
        Isconfig = false
        return readErr
    }

    var loadedConfig FingerprintConfig
    if unmarshalErr := json.Unmarshal(data, &loadedConfig); unmarshalErr != nil {
        Config = nil
        Isconfig = false
        return unmarshalErr
    }

    Config = &loadedConfig
    Isconfig = true
    return nil
}

func init() {
    once.Do(func() {
        _ = LoadFingerprintConfig()
    })
}
