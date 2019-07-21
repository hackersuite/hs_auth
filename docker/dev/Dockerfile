FROM golang:1-alpine3.9

WORKDIR /go/src/github.com/unicsmcr/hs_auth

COPY . .

RUN apk add iptables
RUN apk add git
RUN go get -d -v ./...
RUN go install -v ./...

ENV GOPATH /go

RUN go get github.com/githubnemo/CompileDaemon

EXPOSE 8080

ENTRYPOINT \
  # Redirecting HTTP requests to 8080 for communication between HS services
  iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080 && \
  # Starting daemon for live reloading
  CompileDaemon -log-prefix=false -build="go build" -command="./hs_auth"
