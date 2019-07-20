FROM golang:1.8

WORKDIR /go/src/github.com/unicsmcr/hs_auth
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

EXPOSE 8080
CMD ["go", "run", "main.go"]
