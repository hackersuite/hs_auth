module github.com/unicsmcr/hs_auth

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.4.0
	github.com/go-redis/redis/v7 v7.0.0-beta.4 // indirect
	github.com/golang/mock v1.4.3
	github.com/golang/snappy v0.0.1 // indirect
	github.com/google/wire v0.4.0
	github.com/markbates/refresh v1.11.1 // indirect
	github.com/pkg/errors v0.8.1
	github.com/sendgrid/rest v2.4.1+incompatible // indirect
	github.com/sendgrid/sendgrid-go v3.5.0+incompatible
	github.com/stretchr/testify v1.6.1
	github.com/tidwall/pretty v1.0.0 // indirect
	github.com/ugorji/go/codec v0.0.0-20181204163529-d75b2dcb6bc8 // indirect
	github.com/vektra/mockery v1.1.2 // indirect
	github.com/xdg/scram v0.0.0-20180814205039-7eeb5667e42c // indirect
	github.com/xdg/stringprep v1.0.0 // indirect
	go.mongodb.org/mongo-driver v1.1.1
	go.uber.org/config v1.3.1
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/text v0.3.2 // indirect
	golang.org/x/tools v0.0.0-20201014170642-d1624618ad65
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
)

replace github.com/ugorji/go v1.1.4 => github.com/ugorji/go/codec v0.0.0-20190204201341-e444a5086c43
