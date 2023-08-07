FROM alpine:edge AS singbuilder
RUN apk add go
WORKDIR /data
RUN go mod init sing-box && go get -v github.com/sagernet/sing-box/cmd/sing-box@latest
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static" -trimpath -o /data/sing-box github.com/sagernet/sing-box/cmd/sing-box
FROM alpine:edge
WORKDIR /data
COPY ./remakeiso.sh /
COPY ./root.7z /
COPY --from=singbuilder /data/sing-box /sing-box
RUN apk add --no-cache xorriso 7zip && chmod +x /sing-box && chmod +x /remakeiso.sh
ENV sha="rootsha"
ENV SNIFF=no
ENTRYPOINT ["/remakeiso.sh"]