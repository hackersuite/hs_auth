FROM golang:1-alpine3.9

WORKDIR /go/src/github.com/unicsmcr/hs_auth

COPY . .

RUN apk add git
RUN go get -d -v ./...
RUN go install -v ./...

ENV GOPATH /go

RUN go get github.com/githubnemo/CompileDaemon

EXPOSE 80

ENTRYPOINT \
  # Starting daemon for live reloading
  CompileDaemon -log-prefix=false -build="go build" -command="./hs_auth"
