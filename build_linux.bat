@echo off
setLocal

set GOARCH=amd64
set GOOS=linux
go build --ldflags="-s -w" -v -x -a -o bin\\simpleProxy main.go

endLocal
@echo on