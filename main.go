package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/caarlos0/env"
	"github.com/michalnicp/mole/ssh"
)

type config struct {
	// ServerName is the server's fully qualified domain name (hostname).
	ServerName        string `env:"SERVER_NAME"`
	HTTPAddr          string `env:"HTTP_ADDR" envDefault:":8080"`
	SSHAddr           string `env:"SSH_ADDR" envDefault:":2022"`
	SSHHostKey        string `env:"SSH_HOST_KEY" envDefault:"ssh_host_key"`
	SSHAuthorizedKeys string `env:"SSH_AUTHORIZED_KEYS" envDefault:"authorized_keys"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// read config from env
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("parse environment: %v", err)
	}

	// create ssh server
	sshServer, err := ssh.NewServer(cfg.SSHAddr)
	if err != nil {
		log.Fatalf("create ssh server: %v", err)
	}

	if err := sshServer.Start(); err != nil {
		log.Fatalf("start ssh server: %v", err)
	}

	// create reverse proxy
	domain := cfg.ServerName
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			subdomain := strings.TrimSuffix(req.Host, "."+domain)
			id64, err := strconv.ParseUint(subdomain, 10, 64)
			if err != nil {
				log.Printf("parse host: %s: %v", req.Host, err)
				return
			}
			id := uint(id64)

			addr, ok := sshServer.GetForwardAddr(id)
			if !ok {
				log.Printf("forward address not found: %d", id)
				return
			}

			// If there was an error above this line, the scheme will not be set.
			// This results in the request failing with a 502 Bad Gateway, which
			// is what we want. See proxy.ErrorHandler.

			req.URL.Scheme = "http"
			req.URL.Host = addr

			// TODO: Should we modify req.Host as well?
			// req.Host = req.URL.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if err.Error() != "unsupported protocol scheme \"\"" {
				log.Printf("http: proxy error: %v", err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	httpServer := http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: proxy,
	}

	go func() {
		log.Printf("starting http server; http_addr=%s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("start http server: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	s := <-sigs
	log.Printf("caught %s, shutting down", s)

	if err := httpServer.Close(); err != nil {
		log.Printf("close http server: %v", err)
	}

	if err := sshServer.Close(); err != nil {
		log.Printf("close ssh server: %v", err)
	}

	// FIXME: get this down to 2
	// time.Sleep(300 * time.Millisecond)
	// pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
}
