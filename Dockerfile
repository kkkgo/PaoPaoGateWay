FROM alpine:edge AS downloader
RUN apk add go git curl gzip && apk upgrade
WORKDIR /geodata
RUN curl -L -o geoip.metadb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb && \
    curl -L -o ASN.mmdb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb && \
    curl -L -o GeoIP.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat && \
    curl -L -o GeoSite.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat
RUN ver=$(curl -s https://github.com/MetaCubeX/mihomo/releases | \
          grep mihomo-android- | \
          grep MetaCubeX/mihomo/releases | \
          grep -Eo "download/[^/]+" | \
          cut -d"/" -f2 | \
          head -1) && \
    echo "Version: $ver" && \
    downlink_compatible="https://github.com/MetaCubeX/mihomo/releases/download/${ver}/mihomo-linux-amd64-compatible-${ver}.gz" && \
    downlink_v3="https://github.com/MetaCubeX/mihomo/releases/download/${ver}/mihomo-linux-amd64-v3-${ver}.gz" && \
    curl -L "$downlink_compatible" -o /tmp/mihomo_compatible.gz && \
    gunzip /tmp/mihomo_compatible.gz && \
    ls /tmp/ && \
    mv /tmp/mihomo_compatible /usr/bin/mihomo_compatible && \
    chmod +x /usr/bin/mihomo_compatible && \
    curl -L "$downlink_v3" -o /tmp/mihomo_v3.gz && \
    gunzip /tmp/mihomo_v3.gz && \
    ls /tmp/ && \
    mv /tmp/mihomo_v3 /usr/bin/mihomo_v3 && \
    chmod +x /usr/bin/mihomo_v3 && \
    rm -rf /tmp/*
FROM downloader AS singbuilder
WORKDIR /data
RUN git clone https://github.com/kkkgo/box.git box --depth 1
WORKDIR /data/box
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$(git describe --tags --always)' -s -w" -trimpath -tags "with_clash_api" -buildvcs=false -o /data/sing-box ./cmd/sing-box 

FROM alpine:edge
RUN apk add --no-cache xorriso 7zip
COPY --from=singbuilder /data/sing-box /sing-box
COPY --from=singbuilder /usr/bin/mihomo_compatible /clash/
COPY --from=singbuilder /usr/bin/mihomo_v3 /clash/
COPY --from=singbuilder /geodata/geoip.metadb /geodata/geoip.metadb
COPY --from=singbuilder /geodata/ASN.mmdb /geodata/ASN.mmdb
COPY --from=singbuilder /geodata/GeoSite.dat /geodata/GeoSite.dat
COPY --from=singbuilder /geodata/GeoIP.dat /geodata/GeoIP.dat
COPY --from=sliamb/opbuilder /src/isolinux /isolinux
WORKDIR /data
COPY ./remakeiso.sh /
COPY ./root.7z /
RUN chmod +x /sing-box && chmod +x /remakeiso.sh
ENV sha="rootsha"
ENV SNIFF=yes
ENV GEO=yes
ENTRYPOINT ["/remakeiso.sh"]