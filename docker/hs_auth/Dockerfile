FROM golang:1-alpine3.9

WORKDIR /go/src/github.com/unicsmcr/hs_auth

ENV GO111MODULE on

COPY . .

RUN apk add git
RUN go mod download
RUN apk del git

ENV GOPATH /go

EXPOSE 80

ENTRYPOINT go run main.go wire_gen.go server.go
