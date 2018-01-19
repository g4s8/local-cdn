# local-cdn
HTTP proxy which cache all responses from server

## Usage
### Environment
Required go-lang build tool
### Clone
Get it from Github: `git clone https://github.com/g4s8/local-cdn.git`
### Build
```
cd local-cdn
go build local-cdn.go
```
### Start proxy
```
./local-cdn -host=your.host.com -port=8010 -verbose
```
where `-host` is a target host
`-port` is a proxy port
### Configure your tools
E.g. for java add this arguments: `-Dhttp.proxyHost=localhost -Dhttp.proxyPort=8010`
