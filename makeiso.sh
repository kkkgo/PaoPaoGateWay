#!/bin/sh
ppgwver=$(date +%Y%m%d)
builddir=$(pwd)
if [ -f "$builddir""/sha.txt" ]; then
    sha="-"$(cat ./sha.txt)
    ppgwver="$ppgwver""$sha"
    sed -i "s/PPGW_version/$ppgwver/g" "$builddir"/custom.config.sh
    sed -i '/.*dropbear.*/s/.*/-dropbear/' "$builddir"/pkg.conf
    sed -i '/.*psmisc.*/s/.*/-psmisc/' "$builddir"/pkg.conf
fi

rm -f "$builddir"/FILES/usr/bin/sniffbox
docker pull rust:alpine
docker run --rm --name rustbuilder \
    -v "$builddir"/FILES/usr/bin/:/app/ \
    -v "$builddir"/buildbox.sh:/sh/buildbox.sh \
    -v "$builddir"/sniffbox:/box \
    rust:alpine sh /sh/buildbox.sh
if [ -f "$builddir""/FILES/usr/bin/sniffbox" ]; then
    echo "sniffbox compilation OK."
else
    echo "sniffbox compilation failed."
    exit
fi
cat >"$builddir"/FILES/usr/bin/ppgw <<'PPGWEOF'
#!/bin/sh
exec /usr/bin/sniffbox ppgw "$@"
PPGWEOF
chmod +x "$builddir"/FILES/usr/bin/ppgw
echo "ppgw -> sniffbox wrapper created."

echo "make iso files..."
docker pull sliamb/opbuilder
mkdir -p "$builddir"/iso
mkdir -p "$builddir"/FILES/
rm -rf "$builddir"/iso/*
ls -lah "$builddir"/iso/
export FULLMOD="no"
#usefullmod export FULLMOD="yes"
docker run --rm --name opbuilder \
    -e ppgwver="$ppgwver" \
    -e FULLMOD="$FULLMOD" \
    -v "$builddir"/custom.config.sh:/src/custom.config.sh \
    -v "$builddir"/iso/:/src/iso/ \
    -v "$builddir"/FILES:/src/cpfiles/ \
    -v "$builddir"/pkg.conf:/src/pkg.conf \
    -v "$builddir"/patch.sh:/src/patch.sh \
    sliamb/opbuilder

echo "make docker files..."
rootsha=$(head -1 "$builddir""/iso/rootsha.txt")
echo "docker rootsha: ""$rootsha"
rm -f "$builddir"/iso/paopao-gateway-x86-64.iso
sed "s/rootsha/$rootsha/g" "$builddir"/Dockerfile >"$builddir"/iso/Dockerfile
cp "$builddir"/remakeiso.sh "$builddir"/iso/
sed -i "s/PPGW_version/$ppgwver/g" "$builddir"/iso/remakeiso.sh
cd "$builddir"/iso || exit
docker build -t ppgwiso .

echo "generate final iso via docker..."
docker run --rm --name ppgwiso_final \
    -e MI=y \
    -e GEO=yes \
    -v "$builddir"/iso:/data \
    ppgwiso

echo "make sha256hashsum.txt ..."
isofile=$(ls "$builddir"/iso/ppgw-r*.iso 2>/dev/null | head -1)
if [ -z "$isofile" ]; then
    echo "Final ISO not found."
    exit 1
fi
isofilename=$(basename "$isofile")
beijing_time=$(TZ='Asia/Shanghai' date +'%Y-%m-%d %H:%M:%S')
sha256hashsumfile="$builddir"/iso/sha256hashsum.txt
echo "$beijing_time" >"$sha256hashsumfile"
ls -lah "$builddir"/iso/ppgw-r*.iso | grep iso >>"$sha256hashsumfile"
echo "   " >>"$sha256hashsumfile"
echo "Linux shell:" >>"$sha256hashsumfile"
echo "   sha256sum ""$isofilename" >>"$sha256hashsumfile"
echo "Windows Powershell: " >>"$sha256hashsumfile"
echo "  Get-FileHash ""$isofilename" >>"$sha256hashsumfile"
echo "SHA256SUM:   " >>"$sha256hashsumfile"
cd "$builddir"/iso || exit
sha256sum "$isofilename" >>"$sha256hashsumfile"
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
        -e sha="$sha" \
        sliamb/opbuilder bash 7z.sh
    mv "$builddir"/iso/pack/*.7z "$builddir"/iso/
fi
ls -lah "$builddir"/iso
