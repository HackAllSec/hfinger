package utils

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	Digest             string `json:"digest"`
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func verifyAssetChecksum(release *GitHubReleaseResponse, assetName, filePath string) error {
	assetData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	expectedHash, err := releaseAssetDigest(release.Assets, assetName)
	if err != nil {
		checksumAsset, ok := findChecksumAsset(release.Assets, assetName)
		if !ok {
			return err
		}

		checksumPath := filePath + ".sha256"
		defer os.Remove(checksumPath)
		if err := downloadFile(checksumAsset.BrowserDownloadURL, checksumPath); err != nil {
			return fmt.Errorf("download checksum: %w", err)
		}

		checksumData, err := os.ReadFile(checksumPath)
		if err != nil {
			return err
		}

		expectedHash, err = parseChecksum(string(checksumData), assetName)
		if err != nil {
			return err
		}
	}

	actualHash := calculateHash(assetData)
	if !strings.EqualFold(expectedHash, actualHash) {
		return fmt.Errorf("checksum mismatch for %s", assetName)
	}
	return nil
}

func releaseAssetDigest(assets []GitHubReleaseAsset, assetName string) (string, error) {
	for _, asset := range assets {
		if asset.Name != assetName {
			continue
		}
		hash, err := parseGitHubAssetDigest(asset.Digest)
		if err != nil {
			return "", err
		}
		return hash, nil
	}
	return "", fmt.Errorf("missing GitHub asset digest for %s", assetName)
}

func parseGitHubAssetDigest(digest string) (string, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(strings.ToLower(digest), prefix) {
		return "", fmt.Errorf("unsupported GitHub asset digest %q", digest)
	}
	hash := digest[len(prefix):]
	if !isSHA256Hex(hash) {
		return "", fmt.Errorf("invalid GitHub asset digest %q", digest)
	}
	return hash, nil
}

func findChecksumAsset(assets []GitHubReleaseAsset, assetName string) (GitHubReleaseAsset, bool) {
	lowerAssetName := strings.ToLower(assetName)
	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		if !strings.Contains(name, "sha256") && !strings.Contains(name, "checksum") {
			continue
		}
		if strings.Contains(name, lowerAssetName) || strings.Contains(name, runtime.GOOS) || name == "checksums.txt" || name == "sha256sums.txt" {
			return asset, true
		}
	}
	return GitHubReleaseAsset{}, false
}

func parseChecksum(content, assetName string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 1 && isSHA256Hex(fields[0]) {
			return fields[0], nil
		}
		if len(fields) < 2 || !isSHA256Hex(fields[0]) {
			continue
		}

		filename := strings.TrimPrefix(fields[len(fields)-1], "*")
		if filepath.Base(filename) == assetName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found", assetName)
}

func isSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
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
}

func Update() {
	logger.Warn("Built-in fingerprint rules are shipped with the hfinger binary now. Use --upgrade to update built-in rules, or --rules to load external YAML rules.")
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

	asset, err := selectUpgradeAsset(release.Assets, runtime.GOOS)
	if err != nil {
		logger.Error("%v", err)
		return
	}
	assetName := asset.Name

	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	tempFile := filepath.Join(exeDir, assetName)
	backupExe := exePath + ".old"

	// 下载新版本
	if err := downloadFile(asset.BrowserDownloadURL, tempFile); err != nil {
		logger.Error("Error downloading new version: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	// 校验发布包哈希，避免下载内容被替换。
	if err := verifyAssetChecksum(release, assetName, tempFile); err != nil {
		logger.Error("Checksum verification failed: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	// 解压前校验 ZIP
	if err := verifyZip(tempFile); err != nil {
		logger.Error("ZIP verification failed: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	// 备份当前程序
	if err := os.Rename(exePath, backupExe); err != nil {
		logger.Error("Error backing up executable: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	// 解压 ZIP 到可执行文件目录
	if err := extractZip(tempFile, exeDir); err != nil {
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

func selectUpgradeAsset(assets []GitHubReleaseAsset, goos string) (GitHubReleaseAsset, error) {
	var osName string
	switch goos {
	case "windows":
		osName = "windows"
	case "linux":
		osName = "linux"
	case "darwin":
		osName = "darwin"
	default:
		return GitHubReleaseAsset{}, fmt.Errorf("unsupported OS: %s", goos)
	}

	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		if !strings.Contains(name, osName) {
			continue
		}
		if strings.Contains(name, "sha256") || strings.Contains(name, "checksum") {
			continue
		}
		if !strings.HasSuffix(name, ".zip") {
			continue
		}
		return asset, nil
	}
	return GitHubReleaseAsset{}, fmt.Errorf("no matching asset found for %s", osName)
}

func extractZip(filePath, destDir string) error {
	zipReader, err := zip.OpenReader(filePath)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		fullPath, ok, err := safeZipPath(destDir, file.Name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if file.FileInfo().Mode()&os.ModeSymlink != 0 {
			continue
		}

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

		rc, err := file.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			rc.Close()
			outFile.Close()
			return err
		}
		rc.Close()
		outFile.Close()
	}
	return nil
}

func safeZipPath(destDir, name string) (string, bool, error) {
	cleanedName := filepath.Clean(filepath.FromSlash(name))
	if cleanedName == "." || filepath.IsAbs(cleanedName) {
		return "", false, nil
	}
	for _, part := range strings.Split(cleanedName, string(os.PathSeparator)) {
		if part == ".." {
			return "", false, nil
		}
	}

	fullPath := filepath.Join(destDir, cleanedName)
	rel, err := filepath.Rel(destDir, fullPath)
	if err != nil {
		return "", false, err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", false, nil
	}
	return fullPath, true, nil
}
