package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/bclicn/color"
	"github.com/elazarl/goproxy"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
)

const (
	FLAG = "X-LocalCDN"
)

var (
	cache           = make(map[string]*Entry)
	tmpDir          string
	dryRun, verbose bool
	host            string
	port            int
)

type Entry struct {
	File   string
	Source *http.Response
	Hits   int
}

func main() {
	flag.StringVar(&host, "host", "", "host to cache")
	flag.IntVar(&port, "port", 8010, "proxy port")
	flag.BoolVar(&dryRun, "dry", false, "skip cache")
	flag.BoolVar(&verbose, "verbose", false, "print cached responses and hits")
	flag.Parse()

	if host == "" {
		flag.Usage()
		panic("host required")
	}

	tmp, err := ioutil.TempDir("/tmp", "local-cdn")
	if err != nil {
		panic(err)
	}
	tmpDir = tmp

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		Cleanup()
		os.Exit(0)
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest(goproxy.DstHostIs(host)).Do(goproxy.FuncReqHandler(OnRequest))
	proxy.OnResponse(goproxy.DstHostIs(host)).Do(goproxy.FuncRespHandler(OnResponse))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
}

func Cleanup() {
	fmt.Print("cleaning up...")
	if err := os.Remove(tmpDir); err != nil {
		panic(err)
	}
	fmt.Printf("\t[done]\n")
}

func OnRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	name := CacheName(r)
	entry := cache[name]
	if entry != nil {
		entry.Hits++
		if verbose {
			fmt.Println(color.Green(fmt.Sprintf("HIT %d: %s", entry.Hits, name)))
		}
		r.Header.Set(FLAG, "1")
		return r, entry.Response(r)
	}
	return r, nil
}

func OnResponse(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
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
		if verbose {
			fmt.Println(color.Yellow(fmt.Sprintf("CACHE: %s", name)))
		}
		entry := &Entry{
			File:   tmp.Name(),
			Source: rsp,
			Hits:   0,
		}
		if !dryRun {
			cache[name] = entry
		}
		return CopyResponse(rsp, ctx.Req, tmp.Name())
	}
	return rsp
}

func CacheName(req *http.Request) string {
	return fmt.Sprintf("[%s][%s][%s]", req.Method, req.URL.Host, req.URL.Path)
}

func (entry *Entry) Response(req *http.Request) *http.Response {
	return CopyResponse(entry.Source, req, entry.File)
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
