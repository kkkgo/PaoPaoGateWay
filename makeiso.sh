#!/bin/sh
ppgwver=$(date +%Y%m%d)
if [ -f ./sha.txt ]; then
    ppgwver="$ppgwver""-"$(cat ./sha.txt)
    sed -i "s/PPGW_version/$ppgwver/g"custom.config.sh
fi
# build ppgw
docker pull golang:alpine
docker run --rm --name gobuilder \
    -v $(pwd)/ppgw.go:/go/build/main.go \
    -v $(pwd)/FILES/usr/bin/:/go/ppgw/ \
    -v $(pwd)/buildppgw.sh:/go/build/buildppgw.sh \
    golang:alpine sh /go/build/buildppgw.sh

docker pull sliamb/opbuilder
mkdir -p ./iso
mkdir -p ./FILES/
rm -rf ./iso/*
ls -lah ./iso/
docker run --rm --name opbuilder \
    -e ppgwver="$ppgwver" \
    -v $(pwd)/custom.config.sh:/src/custom.config.sh \
    -v $(pwd)/iso/:/src/iso/ \
    -v $(pwd)/FILES:/src/cpfiles/ \
    -v $(pwd)/pkg.conf:/src/pkg.conf \
    sliamb/opbuilder
# ls -lah ./iso/

cd ./iso || exit
isofilename=paopao-gateway-x86-64"$sha".iso
mv *.iso "$isofilename"
beijing_time=$(TZ='Asia/Shanghai' date +'%Y-%m-%d %H:%M:%S')
echo "$beijing_time" >sha256hashsum.txt
ls -lah | grep iso >>sha256hashsum.txt
echo "   " >>sha256hashsum.txt
echo "Linux shell:" >>sha256hashsum.txt
echo "   sha256sum ""$isofilename" >>sha256hashsum.txt
echo "Windows Powershell: " >>sha256hashsum.txt
echo "  Get-FileHash ""$isofilename" >>sha256hashsum.txt
echo "SHA256SUM:   " >>sha256hashsum.txt

for file in *.iso; do
    hash=$(sha256sum "$file" | awk '{print $1}')
    echo "$hash  $file" >>sha256hashsum.txt
done

if [ -f ../sha.txt ]; then
    tail -1 sha256hashsum.txt | cut -d" " -f1 >../renote.txt
    docker run --rm --name opbuilder \
        -v $(pwd):/src/iso/ \
        -e sha=$sha \
        sliamb/opbuilder bash 7z.sh
else
    ls -lah .
fi
