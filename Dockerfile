FROM alpine:edge AS downloader
RUN apk add go git curl && apk upgrade
WORKDIR /geodata
RUN curl -L -o geoip.metadb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb && \
    curl -L -o ASN.mmdb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb && \
    curl -L -o GeoIP.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat && \
    curl -L -o GeoSite.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat

FROM downloader AS singbuilder
WORKDIR /data
RUN git clone https://github.com/kkkgo/box.git box --depth 1
WORKDIR /data/box
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static" -trimpath -tags "with_clash_api" -buildvcs=false -o /data/sing-box ./cmd/sing-box

FROM alpine:edge
RUN apk add --no-cache xorriso 7zip
COPY --from=singbuilder /data/sing-box /sing-box
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