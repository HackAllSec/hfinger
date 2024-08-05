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

    "hfinger/config"
    "github.com/fatih/color"
)

type GitHubReleaseAsset struct {
    Name               string `json:"name"`
    BrowserDownloadURL string `json:"browser_download_url"`
}

type GitHubReleaseResponse struct {
    TagName string               `json:"tag_name"`
    Assets  []GitHubReleaseAsset `json:"assets"`
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
        fullPath := filepath.Join(destDir, file.Name)

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
        color.Blue("[*] Your current hfinger %s are outdated. Latest is %s.You can use the --upgrade option to upgrade.", config.Version, latestVersion)
    }
}

func Update() {
    url := "https://raw.githubusercontent.com/HackAllSec/hfinger/main/data/finger.json"
    err := os.MkdirAll("data", os.ModePerm)
    if err != nil {
        return
    }
    destPath := "data/finger.json"
    err = downloadFile(url, destPath)
    if err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
        return
    }
    color.Green("[%s] [+] Update finger.json success.", time.Now().Format("01-02 15:04:05"))
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
