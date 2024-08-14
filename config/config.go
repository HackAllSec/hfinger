package config

import (
    "encoding/json"
    "io/ioutil"
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

var (
    config *FingerprintConfig
    once   sync.Once
    Version = "v1.0.3"
    CertsDir   = "certs"
    CaCertFile = "ca.crt"
    CaKeyFile  = "ca.key"
    CertsPath = filepath.Join(CertsDir, CaCertFile)
    KeyPath = filepath.Join(CertsDir, CaKeyFile)
    Datapath = "data"
    Fingerfile = "finger.json"
    Fingerfullpath = filepath.Join(Datapath, Fingerfile)
)

// LoadConfig 加载并缓存指纹配置
func LoadConfig(filePath string) error {
    var err error
    once.Do(func() {
        absPath, pathErr := filepath.Abs(filePath)
        if pathErr != nil {
            err = pathErr
            return
        }

        data, readErr := ioutil.ReadFile(absPath)
        if readErr != nil {
            err = readErr
            return
        }

        var loadedConfig FingerprintConfig
        if unmarshalErr := json.Unmarshal(data, &loadedConfig); unmarshalErr != nil {
            err = unmarshalErr
            return
        }

        config = &loadedConfig
    })

    return err
}

// GetConfig 获取缓存的指纹配置
func GetConfig() *FingerprintConfig {
    return config
}
