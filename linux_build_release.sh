#!/bin/bash

build_and_package() {
    local goos=$1
    local goarch=$2
    local filename=$3

    echo "Building for ${goos}/${goarch}..."
    CGO_ENABLED=0 GOOS=${goos} GOARCH=${goarch} go build -ldflags "-w -s"
    
    if [ $? -ne 0 ]; then
        echo "Build failed for ${goos}/${goarch}"
        return 1
    fi

    echo "Creating zip package for ${goos}/${goarch}..."
    zip -r "${filename}.zip" "${APP_NAME}" data/*
    
    if [ $? -ne 0 ]; then
        echo "Zip failed for ${goos}/${goarch}"
        return 1
    fi

    rm -rf "${APP_NAME}"
    echo "Clean up temporary files for ${goos}/${goarch}."
}

if ! command -v go > /dev/null; then
    echo "Error: go command not found"
    exit 1
fi

if ! command -v zip > /dev/null; then
    echo "Error: zip command not found"
    exit 1
fi

APP_NAME="hfinger"
DATA_DIR="data"

build_and_package "linux" "amd64" "${APP_NAME}_linux_amd64"
build_and_package "linux" "arm64" "${APP_NAME}_linux_arm64"
build_and_package "linux" "arm" "${APP_NAME}_linux_arm"
build_and_package "darwin" "amd64" "${APP_NAME}_darwin_amd64"
build_and_package "darwin" "arm64" "${APP_NAME}_darwin_arm64"

echo "All builds and packages are completed."
