#!/bin/sh
cp /go/main.go /go/build/main.go
cd /go/build || exit
go mod init ppgw
go get -u
if [ -f /go/ppgw/ppgw ]; then
    rm -f /go/ppgw/ppgw
fi
apk update
apk upgrade
apk add curl
version=$(curl -s https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/main/package.json|grep version|grep -Eo "[0-9.]+"|head -n 1)
if [ -z "$version" ]; then
    version="1.9.9"
fi
echo "clash-verge version: $version"
sed -i "s/1.6.6/$version/g" /go/build/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static" -trimpath -o /go/ppgw/ppgw
