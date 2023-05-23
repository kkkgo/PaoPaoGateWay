#!/bin/sh
cd /go/build || exit
go mod init ppgw
go get -u
if [ -f /go/ppgw/ppgw ]; then
    rm -f /go/ppgw/ppgw
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" -trimpath -o /go/ppgw/ppgw
