package main

import (
	"bytes"
	"fmt"
	"github.com/bclicn/color"
	"github.com/elazarl/goproxy"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const (
	HOST = "datum.zerocracy.com"
	FLAG = "X-LocalCDN"
)

var (
	cache     = make(map[string]string)
	responses = make(map[string]*http.Response)
)

func main() {
	proxy := goproxy.NewProxyHttpServer()
	//proxy.Verbose = true

	tmpDir, err := ioutil.TempDir("/tmp", "local-cdn")
	if err != nil {
		panic(err)
	}

	proxy.OnRequest(goproxy.DstHostIs(HOST)).DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			name := CacheName(r)
			if responses[name] != nil {
				fmt.Println(color.Green(fmt.Sprintf("HIT:   %s", name)))
				r.Header.Set(FLAG, "1")
				proto := responses[name]
				return r, CopyResponse(proto, r, cache[name])
			}
			return r, nil
		})
	proxy.OnResponse(goproxy.DstHostIs(HOST)).DoFunc(
		func(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if rsp.StatusCode == 200 && ctx.Req.Method == "GET" {
				if ctx.Req.Header.Get(FLAG) == "1" {
					return rsp
				}
				tmp, err := ioutil.TempFile(tmpDir, "rsp_")
				if err != nil {
					panic(err)
				}
				defer tmp.Close()
				if _, err := io.Copy(tmp, rsp.Body); err != nil {
					panic(err)
				}
				name := CacheName(ctx.Req)
				fmt.Println(color.Yellow(fmt.Sprintf("CACHE: %s", name)))
				cache[name] = tmp.Name()
				responses[name] = rsp
				return CopyResponse(rsp, ctx.Req, tmp.Name())
			}
			return rsp
		})
	log.Fatal(http.ListenAndServe(":8010", proxy))
	fmt.Println("cleanup...")
	if err := os.Remove(tmpDir); err != nil {
		panic(err)
	}
	fmt.Println("Done!")
}

func CacheName(req *http.Request) string {
	return fmt.Sprintf("[%s][%s][%s]", req.Method, req.URL.Host, req.URL.Path)
}

func CopyResponse(proto *http.Response, req *http.Request, body string) *http.Response {
	file, err := os.Open(body)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	var buf bytes.Buffer
	len, err := io.Copy(&buf, file)
	if err != nil {
		panic(err)
	}
	resp := &http.Response{
		Status:        proto.Status,
		StatusCode:    proto.StatusCode,
		Proto:         proto.Proto,
		ProtoMajor:    proto.ProtoMajor,
		ProtoMinor:    proto.ProtoMinor,
		Request:       req,
		Header:        proto.Header,
		Body:          ioutil.NopCloser(&buf),
		ContentLength: len,
	}
	return resp
}
