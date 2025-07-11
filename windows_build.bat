@echo off
go-winres make
go build -ldflags "-w -s" -trimpath