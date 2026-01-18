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
version=$(curl -s https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/autobuild|grep -Eo "releases/download/autobuild/Clash.Verge_[^_]+"|cut -d"_" -f2|head -n 1)
if ! echo "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+.+'; then
    version="2.4.5+autobuild.0117.20ed7a3"
fi
echo "clash-verge version: $version"
sed -i "s/1.6.6/$version/g" /go/build/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static" -trimpath -o /go/ppgw/ppgw