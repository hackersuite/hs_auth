FROM golang:1-alpine3.9

WORKDIR /go/src/github.com/unicsmcr/hs_auth

COPY . .

RUN apk add git
RUN go get -d -v ./...
RUN go install -v ./...
RUN go build main.go

ENV GOPATH /go

EXPOSE 80

ENTRYPOINT ./hs_auth
