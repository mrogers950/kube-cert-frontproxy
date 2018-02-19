package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/http2"

	"bytes"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"strings"
)

// handler reads the TLS peer cert and passes it to a validator script
// on return expects a json formatted DefaultInfo, and adds it to the headers
// X-Remote-User, X-Remote-Group, X-Remote-Extra-
type proxyHandler struct {
	handler   http.Handler
	validator string
}

// DefaultInfo provides a simple user information exchange object
// for components that implement the UserInfo interface.
type DefaultInfo struct {
	Name   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	func() {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return
		}
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: r.TLS.PeerCertificates[0].Raw,
		}
		buf := bytes.Buffer{}
		if err := pem.Encode(&buf, b); err != nil {
			return
		}
		cmd := exec.Command(p.validator, buf.String())
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			return
		}
		// out should be a json of user,group,extra
		var info DefaultInfo
		err = json.Unmarshal(out.Bytes(), &info)
		if err != nil {
			return
		}
		r.Header.Set("X-Remote-User", info.Name)
		for _, group := range info.Groups {
			r.Header.Add("X-Remote-Group", group)
		}
	}()
	p.handler.ServeHTTP(w, r)
}

func main() {
	// parse flags
	// --listen-addr=
	// * --backend-addr=
	// * --backend-ca=
	// * --server-cert=
	// * --server-key=
	// * --server-CA=
	// * --validator-script=
	//
	listenAddr := flag.String("listen-addr", ":4181", "<addr>:<port> to listen on for HTTPS clients")
	backendAddr := flag.String("backend-addr", "", "the https url of the backend")
	backendCA := flag.String("backend-ca", "", "the file path to the backend CA bundle")
	serverCert := flag.String("server-cert", "", "the file path to the server certificate")
	serverKey := flag.String("server-key", "", "the file path to the server key")
	serverCA := flag.String("server-ca", "", "the file path to the server CA")
	validatorScript := flag.String("validator-script", "", "the file path to the certificate validation script")
	flag.Parse()

	if *listenAddr == "" || *backendAddr == "" || *backendCA == "" || *serverCert == "" || *serverKey == "" || *validatorScript == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	backendUrl, err := url.Parse(*backendAddr)
	if err != nil {
		log.Fatalf("error parsing backend URL %s", err)
	}

	backendUrl.Scheme = "https"
	proxy := httputil.NewSingleHostReverseProxy(backendUrl)
	// proxy.FlushInterval needed?
	transport := &http.Transport{
		MaxIdleConnsPerHost: 500,
		IdleConnTimeout:     1 * time.Minute,
	}

	caFile, err := ioutil.ReadFile(*backendCA)
	if err != nil {
		log.Fatalf("error reading CA file %s", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caFile) {
		log.Fatalf("error loading CA %s", err)
	}

	transport.TLSClientConfig = &tls.Config{
		RootCAs: pool,
	}

	// is this needed?
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Fatalf("error configuring transport %s", err)
	}

	proxy.Transport = transport
	proxyHandler := &proxyHandler{proxy, *validatorScript}

	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		log.Fatalf("FATAL: loading tls config (%s, %s) failed - %s", *serverCert, *serverKey, err)
	}

	if len(*serverCA) > 0 {
		config.ClientAuth = tls.RequestClientCert
		p := x509.NewCertPool()
		serverCAFile, err := ioutil.ReadFile(*serverCA)
		if err != nil {
			log.Fatalf("error reading CA file %s", err)
		}
		if !p.AppendCertsFromPEM(serverCAFile) {
			log.Fatalf("error loading CA file %s", err)
		}
		config.ClientCAs = p
		if err != nil {
			log.Fatalf("FATAL: %s", err)
		}
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s) failed - %s", *listenAddr, err)
	}
	log.Printf("HTTPS: listening on %s", ln.Addr())

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	srv := &http.Server{Handler: proxyHandler}
	err = srv.Serve(tlsListener)

	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: https.Serve() - %s", err)
	}
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
