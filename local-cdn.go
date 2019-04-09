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
	"strconv"
	"syscall"
)

const (
	flagHeader = "X-LocalCDN"
)

var (
	cache           = make(map[string]*entry)
	tmpDir          string
	dryRun, verbose bool
	host            string
	port            int
)

type entry struct {
	File   string
	Source *http.Response
	Hits   int
}

func main() {
	var pid string
	flag.StringVar(&host, "host", "", "host to cache")
	flag.IntVar(&port, "port", 8010, "proxy port")
	flag.BoolVar(&dryRun, "dry", false, "skip cache")
	flag.BoolVar(&verbose, "verbose", false, "print cached responses and hits")
	flag.StringVar(&pid, "pid", "", "pidfile path")
	flag.Parse()

	if host == "" {
		flag.Usage()
		panic("host required")
	}

	if pid == "" {
		writePidFile(pid)
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
		defer os.Exit(0)
		cleanup()
		if pid != "" {
			os.Remove(pid)
		}
	}()

	fmt.Printf("starting on port %d to cache requests to %s\n", port, host)
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest(goproxy.DstHostIs(host)).Do(goproxy.FuncReqHandler(onRequest))
	proxy.OnResponse(goproxy.DstHostIs(host)).Do(goproxy.FuncRespHandler(onResponse))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
}

func cleanup() {
	fmt.Print("cleaning up...")
	if err := os.RemoveAll(tmpDir); err != nil {
		panic(err)
	}
	fmt.Printf("\t[done]\n")
}

func onRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	name := cacheName(r)
	entry := cache[name]
	if entry != nil {
		entry.Hits++
		if verbose {
			fmt.Println(color.Green(fmt.Sprintf("HIT %d: %s", entry.Hits, name)))
		}
		r.Header.Set(flagHeader, "1")
		return r, entry.response(r)
	}
	return r, nil
}

func onResponse(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if rsp.StatusCode == 200 && ctx.Req.Method == "GET" {
		if ctx.Req.Header.Get(flagHeader) == "1" {
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
		name := cacheName(ctx.Req)
		if verbose {
			fmt.Println(color.Yellow(fmt.Sprintf("CACHE: %s", name)))
		}
		entry := &entry{
			File:   tmp.Name(),
			Source: rsp,
			Hits:   0,
		}
		if !dryRun {
			cache[name] = entry
		}
		return copyResponse(rsp, ctx.Req, tmp.Name())
	}
	return rsp
}

func cacheName(req *http.Request) string {
	return fmt.Sprintf("[%s][%s][%s]", req.Method, req.URL.Host, req.URL.Path)
}

func (entry *entry) response(req *http.Request) *http.Response {
	return copyResponse(entry.Source, req, entry.File)
}

func copyResponse(proto *http.Response, req *http.Request, body string) *http.Response {
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

// Got it from https://gist.github.com/davidnewhall/3627895a9fc8fa0affbd747183abca39
// Write a pid file, but first make sure it doesn't exist with a running pid.
func writePidFile(pidFile string) error {
	// Read in the pid file as a slice of bytes.
	if piddata, err := ioutil.ReadFile(pidFile); err == nil {
		// Convert the file contents to an integer.
		if pid, err := strconv.Atoi(string(piddata)); err == nil {
			// Look for the pid in the process list.
			if process, err := os.FindProcess(pid); err == nil {
				// Send the process a signal zero kill.
				if err := process.Signal(syscall.Signal(0)); err == nil {
					// We only get an error if the pid isn't running, or it's not ours.
					return fmt.Errorf("pid already running: %d", pid)
				}
			}
		}
	}
	// If we get here, then the pidfile didn't exist,
	// or the pid in it doesn't belong to the user running this app.
	return ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0664)
}
