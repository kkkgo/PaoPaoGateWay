FROM alpine:edge AS singbuilder
RUN apk add go git
WORKDIR /data
RUN git clone https://github.com/kkkgo/box.git box
WORKDIR /data/box
RUN go get -u && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static" -trimpath -tags "" -o /data/sing-box ./cmd/sing-box
FROM alpine:edge
WORKDIR /data
COPY ./remakeiso.sh /
COPY ./root.7z /
COPY --from=singbuilder /data/sing-box /sing-box
RUN apk add --no-cache xorriso 7zip && chmod +x /sing-box && chmod +x /remakeiso.sh
ENV sha="rootsha"
ENV SNIFF=no
ENTRYPOINT ["/remakeiso.sh"]