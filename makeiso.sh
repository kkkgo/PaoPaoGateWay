#!/bin/sh
ppgwver=$(date +%Y%m%d)
builddir=$(pwd)
if [ -f "$builddir""/sha.txt" ]; then
    sha="-"$(cat ./sha.txt)
    ppgwver="$ppgwver""$sha"
    sed -i "s/PPGW_version/$ppgwver/g" "$builddir"/custom.config.sh
    sed -i '/.*dropbear.*/s/.*/-dropbear/' "$builddir"/pkg.conf
fi

# build ppgw
if [ -f "$builddir"/FILES/usr/bin/ppgw ]; then
    rm "$builddir"/FILES/usr/bin/ppgw
fi
docker pull golang:alpine
docker run --rm --name gobuilder \
    -v "$builddir"/ppgw.go:/go/build/main.go \
    -v "$builddir"/FILES/usr/bin/:/go/ppgw/ \
    -v "$builddir"/buildppgw.sh:/go/build/buildppgw.sh \
    golang:alpine sh /go/build/buildppgw.sh

if [ -f "$builddir""/FILES/usr/bin/ppgw" ]; then
    echo "ppgw compilation OK."
else
    echo "ppgw compilation failed."
    exit
fi

echo "make iso files..."
docker pull sliamb/opbuilder
mkdir -p "$builddir"/iso
mkdir -p "$builddir"/FILES/
rm -rf "$builddir"/iso/*
ls -lah "$builddir"/iso/
docker run --rm --name opbuilder \
    -e ppgwver="$ppgwver" \
    -v "$builddir"/custom.config.sh:/src/custom.config.sh \
    -v "$builddir"/iso/:/src/iso/ \
    -v "$builddir"/FILES:/src/cpfiles/ \
    -v "$builddir"/pkg.conf:/src/pkg.conf \
    -v "$builddir"/patch.sh:/src/patch.sh \
    sliamb/opbuilder

echo "make docker files..."
rootsha=$(head -1 "$builddir""/iso/rootsha.txt")
echo "docker rootsha: ""$rootsha"
sed "s/rootsha/$rootsha/g" "$builddir"/Dockerfile >"$builddir"/iso/Dockerfile
cp "$builddir"/remakeiso.sh "$builddir"/iso/
if [ -f "$builddir""/sha.txt" ]; then
    ls -lah "$builddir"/iso/
else
    cd "$builddir"/iso || exit
    docker build -t ppgwiso .
fi

echo "make sha256hashsum.txt ..."
isofilename=paopao-gateway-x86-64"$sha".iso
mv "$builddir"/iso/*.iso "$builddir"/iso/"$isofilename"
beijing_time=$(TZ='Asia/Shanghai' date +'%Y-%m-%d %H:%M:%S')
sha256hashsumfile="$builddir"/iso/sha256hashsum.txt
echo "$beijing_time" >"$sha256hashsumfile"
ls -lah "$builddir"/iso/paopao-gateway*.iso | grep iso >>"$sha256hashsumfile"
echo "   " >>"$sha256hashsumfile"
echo "Linux shell:" >>"$sha256hashsumfile"
echo "   sha256sum ""$isofilename" >>"$sha256hashsumfile"
echo "Windows Powershell: " >>"$sha256hashsumfile"
echo "  Get-FileHash ""$isofilename" >>"$sha256hashsumfile"
echo "SHA256SUM:   " >>"$sha256hashsumfile"
cd "$builddir"/iso || exit
sha256sum paopao-gateway*.iso >>"$sha256hashsumfile"
ls -lah "$sha256hashsumfile"

if [ -f "$builddir""/sha.txt" ]; then
    echo "make 7z files..."
    tail -1 "$builddir"/iso/sha256hashsum.txt | cut -d" " -f1 >"$builddir"/iso/renote.txt
    mkdir -p "$builddir"/iso/pack
    mv "$builddir"/iso/"$isofilename" "$builddir"/iso/pack/
    mv "$sha256hashsumfile" "$builddir"/iso/pack/
    ls -lah "$builddir"/iso/pack
    docker run --rm --name opbuilder \
        -v "$builddir"/iso/pack:/src/iso/ \
        -e sha=$sha \
        sliamb/opbuilder bash 7z.sh
    mv "$builddir"/iso/pack/*.7z "$builddir"/iso/
fi
ls -lah "$builddir"/iso
