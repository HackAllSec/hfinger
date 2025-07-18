package utils

import (
    "archive/zip"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io"
    "os"
    "path/filepath"
    "runtime"
    "strings"

    "hfinger/config"
    "hfinger/logger"
)

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
    resp, err := Get(config.FingerUrl, nil)
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
    resp, err := Get(config.ReleaseUrl, nil)
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

func verifyZip(filePath string) error {
    r, err := zip.OpenReader(filePath)
    if err != nil {
        return err
    }
    defer r.Close()

    for _, f := range r.File {
        rc, err := f.Open()
        if err != nil {
            return err
        }
        _, _ = io.Copy(io.Discard, rc)
        rc.Close()
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
        logger.Warn("Your current hfinger %s is outdated. Latest is %s. You can use the --upgrade option to upgrade.", config.Version, latestVersion)
    }
    remotehash := getRemoteFileHash()
    localhash := getLocalFileHash()
    if remotehash != "" && localhash != "" {
        if remotehash != localhash {
            logger.Warn("There is a new update to the hfinger fingerprint database, you can use the --update option to update it.")
        }
    }
}

func Update() {
    backupPath := config.Fingerfullpath + ".bak"

    err := os.MkdirAll("data", os.ModePerm)
    if err != nil {
        return
    }

    // 备份旧文件
    if _, err := os.Stat(config.Fingerfullpath); err == nil {
        _ = os.Rename(config.Fingerfullpath, backupPath)
    }

    // 下载新文件
    err = downloadFile(config.FingerUrl, config.Fingerfullpath)
    if err != nil {
        logger.Error("Error downloading file: %v", err)
        _ = os.Remove(config.Fingerfullpath)
        if _, err := os.Stat(backupPath); err == nil {
            _ = os.Rename(backupPath, config.Fingerfullpath)
            logger.Success("Rollback to previous version.")
        }
        return
    }

    // 哈希验证
    remoteHash := getRemoteFileHash()
    localHash := getLocalFileHash()
    if remoteHash != "" && localHash != "" && remoteHash != localHash {
        logger.Error("Hash mismatch. Update failed.")
        _ = os.Remove(config.Fingerfullpath)
        if _, err := os.Stat(backupPath); err == nil {
            _ = os.Rename(backupPath, config.Fingerfullpath)
            logger.Success("Rollback to previous version.")
        }
        return
    }

    logger.Success("Update successful.")
}

func Upgrade() {
    release, err := getLatestRelease()
    if err != nil {
        logger.Error("Error fetching release info: %v", err)
        return
    }

    latestVersion := release.TagName
    if latestVersion == config.Version {
        logger.Success("Already on the latest version: %s", latestVersion)
        return
    }

    var assetName string
    switch runtime.GOOS {
    case "windows":
        assetName = "windows"
    case "linux":
        assetName = "linux"
    case "darwin":
        assetName = "darwin"
    default:
        logger.Error("Unsupported OS: %s", runtime.GOOS)
        return
    }

    var downloadURL string
    for _, asset := range release.Assets {
        if strings.Contains(asset.Name, assetName) {
            downloadURL = asset.BrowserDownloadURL
            assetName = asset.Name
            break
        }
    }

    if downloadURL == "" {
        logger.Error("No matching asset found for %s", assetName)
        return
    }

    tempFile := "./" + assetName

    exePath, _ := os.Executable()
    backupExe := exePath + ".old"

    // 备份当前程序
    if err := os.Rename(exePath, backupExe); err != nil {
        logger.Error("Error backing up executable: %v", err)
        return
    }

    // 下载新版本
    if err := downloadFile(downloadURL, tempFile); err != nil {
        logger.Error("Error downloading new version: %v", err)
        _ = os.Remove(tempFile)
        _ = os.Rename(backupExe, exePath)
        return
    }

    // 解压前校验 ZIP
    if err := verifyZip(tempFile); err != nil {
        logger.Error("ZIP verification failed: %v", err)
        _ = os.Remove(tempFile)
        _ = os.Rename(backupExe, exePath)
        return
    }

    // 解压 ZIP 到当前目录
    if err := extractZip(tempFile, "./"); err != nil {
        logger.Error("Error extracting ZIP: %v", err)
        _ = os.Remove(tempFile)
        _ = os.Rename(backupExe, exePath)
        return
    }

    // 清理临时文件
    _ = os.Remove(tempFile)
    _ = os.Remove(backupExe)

    logger.Success("Upgrade complete. New version: %s", latestVersion)
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

        outFile, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
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