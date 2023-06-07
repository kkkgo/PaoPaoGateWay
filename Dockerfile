FROM alpine:edge
WORKDIR /data
COPY ./remakeiso.sh /
COPY ./root.7z /
COPY --from=v2fly/v2fly-core /usr/bin/v2ray /v2ray
RUN apk add --no-cache xorriso 7zip && chmod +x /v2ray && chmod +x /remakeiso.sh
ENV sha="rootsha"
ENV GEOIP=lite
ENV SNIFF=no
ENTRYPOINT ["/remakeiso.sh"]