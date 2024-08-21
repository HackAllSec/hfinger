package utils

import (
    "archive/zip"
    "encoding/json"
    "io"
    "os"
    "runtime"
    "strings"
    "path/filepath"
    "time"
    "crypto/sha256"
    "encoding/hex"

    "hfinger/config"
    "github.com/fatih/color"
)

var finger_url = "https://raw.githubusercontent.com/HackAllSec/hfinger/main/data/finger.json"

type GitHubReleaseAsset struct {
    Name               string `json:"name"`
    BrowserDownloadURL string `json:"browser_download_url"`
}

type GitHubReleaseResponse struct {
    TagName string               `json:"tag_name"`
    Assets  []GitHubReleaseAsset `json:"assets"`
}

func calculateHash(data []byte) string {
    sha := sha256.New()
    sha.Write(data)
    return hex.EncodeToString(sha.Sum(nil))
}

func getRemoteFileHash() string {
    resp, err := Get(finger_url, nil)
    if err != nil {
        return ""
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return ""
    }
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return ""
    }

    return calculateHash(body)
}

func getLocalFileHash() string {
    file, err := os.Open(config.Fingerfullpath)
    if err != nil {
        return ""
    }
    defer file.Close()

    body, err := io.ReadAll(file)
    if err != nil {
        return ""
    }

    return calculateHash(body)
}

func getLatestRelease() (*GitHubReleaseResponse, error) {
    url := "https://api.github.com/repos/HackAllSec/hfinger/releases/latest"
    resp, err := Get(url, nil)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var release GitHubReleaseResponse
    if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
        return nil, err
    }

    return &release, nil
}

func downloadFile(url, filepath string) error {
    resp, err := Get(url, nil)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    out, err := os.Create(filepath)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, resp.Body)
    return err
}

func extractZip(filePath, destDir string) error {
    zipReader, err := zip.OpenReader(filePath)
    if err != nil {
        return err
    }
    defer zipReader.Close()

    for _, file := range zipReader.File {
        cleanedName := filepath.Clean(file.Name)
        if filepath.IsAbs(cleanedName) || strings.Contains(cleanedName, "../") {
            continue
        }
        fullPath := filepath.Join(destDir, cleanedName)

        if file.FileInfo().IsDir() {
            if err := os.MkdirAll(fullPath, file.Mode()); err != nil {
                return err
            }
            continue
        }

        if err := os.MkdirAll(filepath.Dir(fullPath), os.ModePerm); err != nil {
            return err
        }

        outFile, err := os.Create(fullPath)
        if err != nil {
            return err
        }
        defer outFile.Close()

        rc, err := file.Open()
        if err != nil {
            return err
        }
        defer rc.Close()
        
        if _, err := io.Copy(outFile, rc); err != nil {
            return err
        }
    }
    return nil
}

func CheckForUpdates() {
    release, err := getLatestRelease()
    if err != nil {
        return
    }

    latestVersion := release.TagName
    if latestVersion != config.Version {
        color.Yellow("[*] Your current hfinger %s are outdated. Latest is %s.You can use the --upgrade option to upgrade.", config.Version, latestVersion)
    }
    remotehash := getRemoteFileHash()
    localhash := getLocalFileHash()
    if remotehash != "" && localhash != "" {
        if remotehash != localhash {
            color.Yellow("[*] There is a new update to the hfinger fingerprint database, you can use the --update option to update it.")
        }
    }

}

func Update() {
    err := os.MkdirAll("data", os.ModePerm)
    if err != nil {
        return
    }
    _ = os.Rename(config.Fingerfullpath, config.Fingerfullpath + ".bak")
    err = downloadFile(finger_url, config.Fingerfullpath)
    if err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
        return
    }
    color.Green("[%s] [+] Update finger.json successfully.", time.Now().Format("01-02 15:04:05"))
}

func Upgrade() {
    release, err := getLatestRelease()
    if err != nil {
        return
    }

    latestVersion := release.TagName
    if latestVersion != config.Version {
        var assetName string
        switch runtime.GOOS {
        case "windows":
            assetName = "windows"
        case "linux":
            assetName = "linux"
        case "darwin":
            assetName = "darwin"
        default:
            color.Red("[%s] [!] Error: Unsupported OS: %s", time.Now().Format("01-02 15:04:05"), runtime.GOOS)
            return
        }

        var downloadURL string
        for _, asset := range release.Assets {
            if strings.Contains(asset.Name, assetName) {
                assetName = asset.Name
                downloadURL = asset.BrowserDownloadURL
                break
            }
        }

        if downloadURL == "" {
            color.Red("[%s] [!] Error: No download URL found for %s", time.Now().Format("01-02 15:04:05"), assetName)
            return
        }

        tempFile := "./" + assetName
        err := downloadFile(downloadURL, tempFile)
        if err != nil {
            color.Red("[%s] [!] Error downloading the new version: %v", time.Now().Format("01-02 15:04:05"), err)
            return
        }

        color.Green("[%s] [+] Downloaded new version: %s", time.Now().Format("01-02 15:04:05"), latestVersion)

        exePath, err := os.Executable()
        if err != nil {
            color.Red("[%s] [!] Error getting executable path: %v", time.Now().Format("01-02 15:04:05"), err)
            return
        }

        if err := os.Rename(exePath, exePath + ".old"); err != nil {
            color.Red("[%s] [!] Error renaming executable: %v", time.Now().Format("01-02 15:04:05"), err)
            return
        }
        err = extractZip(tempFile, "./")
        if err != nil {
            color.Red("[%s] [!] Error extracting the new version: %v", time.Now().Format("01-02 15:04:05"), err)
            return
        }

        os.Remove(tempFile)

        color.Green("[%s] [+] Upgrade complete. New version installed.", time.Now().Format("01-02 15:04:05"))
    }
}
