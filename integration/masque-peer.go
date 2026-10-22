// A CONNECT-UDP proxy (RFC 9298) and an HTTP/3 origin, for the integration
// tests of twist.  Both are quic-go's.
//
//   masque-peer proxy  -b ADDR -c CERT -k KEY -t TEMPLATE [-u USER:PASS] [-r REFUSED_PORT]
//   masque-peer origin -b ADDR -c CERT -k KEY
package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("proxy or origin")
	}
	role := os.Args[1]
	fs := flag.NewFlagSet(role, flag.ExitOnError)
	var templateStr, bind, keyFile, certFile, creds, refused string
	fs.StringVar(&templateStr, "t", "", "URI template")
	fs.StringVar(&bind, "b", "", "bind to (ip:port)")
	fs.StringVar(&keyFile, "k", "", "key file")
	fs.StringVar(&certFile, "c", "", "cert file")
	fs.StringVar(&creds, "u", "", "user:password")
	fs.StringVar(&refused, "r", "", "refused target port")
	fs.Parse(os.Args[2:])
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})
	server := http3.Server{Addr: bind, TLSConfig: tlsConf, EnableDatagrams: true}
	if role == "origin" {
		/* Its first packets are 1200 bytes, not quic-go's 1252: the proxy
		   carries them in datagrams of its own, which hold no more until its
		   path MTU discovery has grown them, and masque-go ends the flow on
		   the first that does not fit.  */
		server.QUICConfig = &quic.Config{InitialPacketSize: 1200, EnableDatagrams: true}
	}
	mux := http.NewServeMux()
	if role == "origin" {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/big" {
				w.Header().Set("Content-Length", "3000000")
				buf := make([]byte, 3000000)
				for i := range buf {
					buf[i] = 'h'
				}
				w.Write(buf)
				return
			}
			fmt.Fprint(w, "h3-direct")
		})
	} else {
		template, err := uritemplate.New(templateStr)
		if err != nil {
			log.Fatalf("template: %v", err)
		}
		u, _ := url.Parse(templateStr)
		proxy := masque.Proxy{}
		mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
			if creds != "" && r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)) {
				w.WriteHeader(407)
				return
			}
			req, err := masque.ParseProxyRequest(r, template)
			if err != nil {
				var perr *masque.ProxyRequestParseError
				if errors.As(err, &perr) {
					w.WriteHeader(perr.HTTPStatus)
					return
				}
				w.WriteHeader(400)
				return
			}
			if refused != "" && strings.HasSuffix(req.Target, ":"+refused) {
				w.WriteHeader(403)
				return
			}
			proxy.Proxy(w, req)
		})
	}
	server.Handler = mux
	fmt.Println("ready")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
