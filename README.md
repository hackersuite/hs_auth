
# Hacker Suite - Auth (WIP)
[![Build Status](https://travis-ci.org/unicsmcr/hs_auth.svg?branch=master)](https://travis-ci.org/unicsmcr/hs_auth)
[![codecov](https://codecov.io/gh/unicsmcr/hs_auth/branch/master/graph/badge.svg)](https://codecov.io/gh/unicsmcr/hs_auth)
![GitHub](https://img.shields.io/github/license/unicsmcr/hs_auth.svg)

## Dependencies
- Go
- GNU make
- [mockgen](https://github.com/golang/mock)
- [wire](https://github.com/google/wire/) (optional - only needed to update DI containers)

## Getting started

### Project set up

Run the following commands in a terminal:

```
go get github.com/unicsmcr/hs_auth
cd $GOROOT/src/github.com/unicsmcr/hs_auth
cp app.env.example app.env
cp mongo.env.example mongo.env
cp mongo_express.env.example mongo_express.env
```



Then replace the placeholder values in the .env files



## Deployment with Docker

### Starting the app
First, complete the initial set up (above). Then run one of the 2 commands in a terminal:

```
make up
```
or
```
make up-dev // this will start the app with live reloading
// NOTE: you will need to restart the containers whenever you install a new package
// or change the environment variables in any of the .env files
```
This will create three containers: the go app, the MongoDB database, a database managent tool Mongo Express and two Docker networks: `hs_auth_internal` and `hacker_suite` (if it doesn't exist already). The first time you run the command, it will take a while since it will install the required services. Next time you run the command, it will be much faster since dependecies are cached.

The go app will be available at `localhost:8080` or as `hs_auth` on the `hacker_suite` network. Mongo Express will be available at `localhost:8081`

`hs_auth_internal` is a network used by the hs_auth services internally to communicate with each other, while `hacker_suite` is used to connect all consumer-facing Hacker Suite services.

### Logging
The output from the apps can be attached to the terminal with one of the following commands:
```
make logs // will attach the logs from all 3 containers
make logs-app // will attach the logs from the go app
make logs-db // will attach the logs from the database
```

### Stopping the app
The app can be stopped with:
```
make down
```

## Manual deployment
Complete the setup above and make sure that DB_URL in hs_auth.env is pointing to a running MongoDB database, then run:
```
make run
```

## Tests
Tests can be run with:
````
make test
````

## License

Hacker Suite - Auth is licensed under the MIT License.
