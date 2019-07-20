FROM golang:1.10

WORKDIR /go/src/github.com/unicsmcr/hs_auth

COPY . .

RUN go get -d -v ./...
RUN go install -v ./...


RUN ["go", "get", "github.com/githubnemo/CompileDaemon"]

EXPOSE 8080

ENTRYPOINT CompileDaemon -log-prefix=false -build="go build" -command="./hs_auth"
