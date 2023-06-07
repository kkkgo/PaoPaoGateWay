FROM alpine:edge
RUN apk add --no-cache xorriso 7zip && mkdir -p /data
WORKDIR /data
COPY ./remakeiso.sh /
COPY ./root.7z /
ENV sha="rootsha"
ENV GEOIP=lite
CMD sh /remakeiso.sh