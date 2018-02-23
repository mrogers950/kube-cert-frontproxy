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
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"strings"
)

// handler reads the TLS peer cert and passes it to a validator script
// on return expects a json formatted UserInfo, and adds it to the headers
// X-Remote-User, X-Remote-Group, X-Remote-Extra-
type proxyHandler struct {
	userHeader  string
	groupHeader string
	extraHeader string
	handler     http.Handler
	validator   string
}

type UserInfo struct {
	Name   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

func ValidateCert(cert []byte, validator string) (*UserInfo, error) {
	b := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	buf := bytes.Buffer{}
	if err := pem.Encode(&buf, b); err != nil {
		return nil, err
	}

	// use stdin instead?
	cmd := exec.Command(validator, buf.String()+"\n")

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	info := &UserInfo{}
	err = json.Unmarshal(out.Bytes(), &info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
		info, err := ValidateCert(r.TLS.PeerCertificates[0].Raw, p.validator)
		if err == nil {
			r.Header.Set(p.userHeader, info.Name)
			for _, group := range info.Groups {
				r.Header.Add(p.groupHeader, group)
			}
		}
	}
	p.handler.ServeHTTP(w, r)
}

type CertProxyMapper interface {
	Verify(cert []byte) (*UserInfo, bool, error)
}

type FileCertProxyMapper struct {
	path string
}

func (v *FileCertProxyMapper) Verify(cert []byte) (*UserInfo, bool, error) {
	return nil, true, nil
}

type SANCertProxyMapper struct {
	userPrefix  string
	groupPrefix string
	extraPrefix string
}

func (v *SANCertProxyMapper) Verify(cert []byte) (*UserInfo, bool, error) {
	return nil, true, nil
}

type ScriptCertProxyMapper struct {
	path string
}

func (v *ScriptCertProxyMapper) Verify(cert []byte) (*UserInfo, bool, error) {
	return nil, true, nil
}

type CertProxyOptions struct {
	listenAddr        string
	backendAddr       string
	backendCA         string
	backendClientCert string
	backendClientKey  string
	proxyServingCert  string
	proxyServingKey   string
	proxyServingCA    string
	userHeader        string
	groupHeader       string
	extraHeader       string
	validatorScript   string
	fileMapPath       string
	scriptMapPath     string
	sanMapEnable      bool
	mappers           []CertProxyMapper
}

func (o *CertProxyOptions) ValidateOptions() error {
	if len(o.backendAddr) == 0 {
		return fmt.Errorf("backend-addr must be provided")
	}
	if len(o.backendCA) == 0 {
		return fmt.Errorf("backend-ca must be provided")
	}
	if len(o.backendClientCert) == 0 {
		return fmt.Errorf("backend-cert must be provided")
	}
	if len(o.backendClientKey) == 0 {
		return fmt.Errorf("backend-key must be provided")
	}
	if len(o.proxyServingCA) == 0 {
		return fmt.Errorf("server-ca must be provided")
	}
	if len(o.proxyServingCert) == 0 {
		return fmt.Errorf("server-cert must be provided")
	}
	if len(o.proxyServingKey) == 0 {
		return fmt.Errorf("server-key must be provided")
	}
	return nil
}

func RunCertProxy(opts *CertProxyOptions) {
	backendUrl, err := url.Parse(opts.backendAddr)
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

	caFile, err := ioutil.ReadFile(opts.backendCA)
	if err != nil {
		log.Fatalf("error reading CA file %s", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caFile) {
		log.Fatalf("error loading CA %s", err)
	}

	// load client cert and key for mutual TLS (front proxy CA - front proxy issued cert)
	backendCert, err := tls.LoadX509KeyPair(opts.backendClientCert, opts.backendClientKey)
	if err != nil {
		log.Fatalf("error loading backend cert/key", err)
	}

	transport.TLSClientConfig = &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{backendCert},
	}
	transport.TLSClientConfig.BuildNameToCertificate()

	// is this needed?
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Fatalf("error configuring transport %s", err)
	}

	proxy.Transport = transport
	proxyHandler := &proxyHandler{
		userHeader:  opts.userHeader,
		groupHeader: opts.groupHeader,
		extraHeader: opts.extraHeader,
		handler:     proxy,
		validator:   opts.validatorScript,
	}

	// proxy server setup
	servingCert, err := tls.LoadX509KeyPair(opts.proxyServingCert, opts.proxyServingKey)
	if err != nil {
		log.Fatalf("FATAL: loading tls config (%s, %s) failed - %s", opts.proxyServingCert, opts.proxyServingKey, err)
	}

	var serverPool *x509.CertPool
	if len(opts.proxyServingCA) > 0 {
		pool = x509.NewCertPool()
		serverCAFile, err := ioutil.ReadFile(opts.proxyServingCA)
		if err != nil {
			log.Fatalf("error reading CA file %s", err)
		}
		if !pool.AppendCertsFromPEM(serverCAFile) {
			log.Fatalf("error loading CA file %s", err)
		}
	}

	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{servingCert},
		ClientCAs:    serverPool,
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}
	config.BuildNameToCertificate()

	ln, err := net.Listen("tcp", opts.listenAddr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s) failed - %s", opts.listenAddr, err)
	}
	log.Printf("HTTPS: listening on %s", ln.Addr())
	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)

	srv := &http.Server{Handler: proxyHandler}
	err = srv.Serve(tlsListener)

	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: https.Serve() - %s", err)
	}
}

func (o *CertProxyOptions) SetMappers() error {
	var mappers []CertProxyMapper
	if o.sanMapEnable {
		sanMap := &SANCertProxyMapper{
			userPrefix:  "user",
			groupPrefix: "group",
			extraPrefix: "extra",
		}
		mappers = append(mappers, sanMap)
	}
	if len(o.fileMapPath) > 0 {
		fileMap := &FileCertProxyMapper{
			path: o.fileMapPath,
		}
		mappers = append(mappers, fileMap)
	}
	if len(o.scriptMapPath) > 0 {
		scriptMap := &ScriptCertProxyMapper{
			path: o.scriptMapPath,
		}
		mappers = append(mappers, scriptMap)
	}
	if len(mappers) < 1 {
		return fmt.Errorf("at least one cert mapper is required")
	}
	o.mappers = mappers

	return nil
}

func main() {
	listenAddr := flag.String("listen-addr", ":4181", "<addr>:<port> to listen on for HTTPS clients")
	backendAddr := flag.String("backend-addr", "", "the https url of the backend")
	backendCA := flag.String("backend-ca", "", "the file path to the backend CA bundle")
	backendCert := flag.String("backend-cert", "", "the file path to the backend client cert")
	backendKey := flag.String("backend-key", "", "the file path to the backend client key")
	serverCert := flag.String("server-cert", "", "the file path to the server certificate")
	serverKey := flag.String("server-key", "", "the file path to the server key")
	serverCA := flag.String("server-ca", "", "the file path to the server CA")
	userHeader := flag.String("user-header", "X-Remote-User", "the header name to pass user info, defaults to X-Remote-User")
	groupHeader := flag.String("group-header", "X-Remote-Group", "the header name to pass group info, defaults to X-Remote-User")
	extraHeader := flag.String("extra-header", "X-Remote-Extra-", "the header name prefix to pass extra info, defaults to X-Remote-Extra-")
	fileMapPath := flag.String("map-file", "", "map based on a file that maps certificates to userinfo")
	scriptMapPath := flag.String("map-script", "", "map based on the passed script that maps certificates to userinfo")
	sanMapEnable := flag.Bool("map-san", true, "map based on the certificate subjectAltName OtherName extension")
	flag.Parse()

	opts := &CertProxyOptions{
		listenAddr:        *listenAddr,
		backendAddr:       *backendAddr,
		backendCA:         *backendCA,
		backendClientCert: *backendCert,
		backendClientKey:  *backendKey,
		proxyServingCert:  *serverCert,
		proxyServingKey:   *serverKey,
		proxyServingCA:    *serverCA,
		userHeader:        *userHeader,
		groupHeader:       *groupHeader,
		extraHeader:       *extraHeader,
		fileMapPath:       *fileMapPath,
		scriptMapPath:     *scriptMapPath,
		sanMapEnable:      *sanMapEnable,
	}

	err := opts.ValidateOptions()
	if err != nil {
		log.Printf("%s\n", err)
		os.Exit(1)
	}
	err = opts.SetMappers()
	if err != nil {
		log.Printf("%s\n", err)
		os.Exit(1)
	}

	RunCertProxy(opts)
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
