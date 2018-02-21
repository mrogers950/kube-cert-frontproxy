package testutils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"
)

func DefaultCertFilename(certDir, prefix string) string {
	return path.Join(certDir, prefix+".crt")
}
func DefaultKeyFilename(certDir, prefix string) string {
	return path.Join(certDir, prefix+".key")
}
func DefaultSerialFilename(certDir, prefix string) string {
	return path.Join(certDir, prefix+".serial.txt")
}

type TLSCertificateConfig struct {
	Certs []*x509.Certificate
	Key   crypto.PrivateKey
}

func encodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}

func encodeKey(key crypto.PrivateKey) ([]byte, error) {
	b := bytes.Buffer{}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return []byte{}, err
		}
		if err := pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
			return b.Bytes(), err
		}
	case *rsa.PrivateKey:
		if err := pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
			return []byte{}, err
		}
	default:
		return []byte{}, errors.New("Unrecognized key type")

	}
	return b.Bytes(), nil
}

func (c *TLSCertificateConfig) GetPEMBytes() ([]byte, []byte, error) {
	certBytes, err := encodeCertificates(c.Certs...)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := encodeKey(c.Key)
	if err != nil {
		return nil, nil, err
	}

	return certBytes, keyBytes, nil
}

// SerialGenerator is an interface for getting a serial number for the cert.  It MUST be thread-safe.
type SerialGenerator interface {
	Next(template *x509.Certificate) (int64, error)
}

// SerialFileGenerator returns a unique, monotonically increasing serial number and ensures the CA on disk records that value.
type SerialFileGenerator struct {
	SerialFile string

	// lock guards access to the Serial field
	lock   sync.Mutex
	Serial int64
}

type CA struct {
	Config *TLSCertificateConfig

	SerialGenerator SerialGenerator
}

func (ca *CA) EnsureClientCertificate(certFile, keyFile string, userCN string, userOrg []string, serial string) (*TLSCertificateConfig, bool, error) {
	certConfig, err := GetTLSCertificateConfig(certFile, keyFile)
	if err != nil {
		certConfig, err = ca.MakeClientCertificate(certFile, keyFile, userCN, userOrg)
		return certConfig, true, err // true indicates we wrote the files.
	}

	return certConfig, false, nil
}

func userToSubject(cn string, org []string) pkix.Name {
	return pkix.Name{
		CommonName:   cn,
		Organization: org,
	}
}

func (ca *CA) signCertificate(template *x509.Certificate, requestKey crypto.PublicKey) (*x509.Certificate, error) {
	// Increment and persist serial
	serial, err := ca.SerialGenerator.Next(template)
	if err != nil {
		return nil, err
	}
	template.SerialNumber = big.NewInt(serial)
	return signCertificate(template, requestKey, ca.Config.Certs[0], ca.Config.Key)
}

func (ca *CA) MakeClientCertificate(certFile, keyFile string, userCN string, userOrg []string) (*TLSCertificateConfig, error) {
	log.Printf("Generating client cert in %s and key in %s", certFile, keyFile)
	// ensure parent dirs
	if err := os.MkdirAll(filepath.Dir(certFile), os.FileMode(0755)); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), os.FileMode(0755)); err != nil {
		return nil, err
	}

	clientPublicKey, clientPrivateKey, _ := NewKeyPair()
	clientTemplate := newClientCertificateTemplate(userToSubject(userCN, userOrg), time.Now)
	clientCrt, err := ca.signCertificate(clientTemplate, clientPublicKey)
	if err != nil {
		return nil, err
	}

	certData, err := encodeCertificates(clientCrt)
	if err != nil {
		return nil, err
	}
	keyData, err := encodeKey(clientPrivateKey)
	if err != nil {
		return nil, err
	}

	if err = ioutil.WriteFile(certFile, certData, os.FileMode(0644)); err != nil {
		return nil, err
	}
	if err = ioutil.WriteFile(keyFile, keyData, os.FileMode(0600)); err != nil {
		return nil, err
	}

	return GetTLSCertificateConfig(certFile, keyFile)
}

type SignerCertOptions struct {
	CertFile   string
	KeyFile    string
	SerialFile string

	lock sync.Mutex
	ca   *CA
}

func GetDisplayFilename(filename string) string {
	if absName, err := filepath.Abs(filename); err == nil {
		return absName
	}

	return filename
}

func (o *SignerCertOptions) Validate() error {
	if _, err := os.Stat(o.CertFile); len(o.CertFile) == 0 || err != nil {
		return fmt.Errorf("--signer-cert, %q must be a valid certificate file", GetDisplayFilename(o.CertFile))
	}
	if _, err := os.Stat(o.KeyFile); len(o.KeyFile) == 0 || err != nil {
		return fmt.Errorf("--signer-key, %q must be a valid key file", GetDisplayFilename(o.KeyFile))
	}
	if len(o.SerialFile) > 0 {
		if _, err := os.Stat(o.SerialFile); err != nil {
			return fmt.Errorf("--signer-serial, %q must be a valid file", GetDisplayFilename(o.SerialFile))
		}
	}

	return nil
}

// RandomSerialGenerator returns a serial based on time.Now and the subject
type RandomSerialGenerator struct {
}

func (s *RandomSerialGenerator) Next(template *x509.Certificate) (int64, error) {
	r := mathrand.New(mathrand.NewSource(time.Now().UTC().UnixNano()))
	return r.Int63(), nil
}

func CertificatesFromPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	ok := false
	certs := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}

		certs = append(certs, cert)
		ok = true
	}

	if !ok {
		return certs, errors.New("Could not read any certificates")
	}
	return certs, nil
}

func GetTLSCertificateConfig(certFile, keyFile string) (*TLSCertificateConfig, error) {
	if len(certFile) == 0 {
		return nil, errors.New("certFile missing")
	}
	if len(keyFile) == 0 {
		return nil, errors.New("keyFile missing")
	}

	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	certs, err := CertificatesFromPEM(certPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("Error reading %s: %s", certFile, err)
	}

	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	keyPairCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}
	key := keyPairCert.PrivateKey

	return &TLSCertificateConfig{certs, key}, nil
}

func GetCA(certFile, keyFile string) (*CA, error) {
	caConfig, err := GetTLSCertificateConfig(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	serialGenerator := &RandomSerialGenerator{}

	return &CA{
		SerialGenerator: serialGenerator,
		Config:          caConfig,
	}, nil
}

func (o *SignerCertOptions) CA() (*CA, error) {
	o.lock.Lock()
	defer o.lock.Unlock()
	if o.ca != nil {
		return o.ca, nil
	}
	ca, err := GetCA(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, err
	}
	o.ca = ca
	return ca, nil
}

type CreateClientCertOptions struct {
	SignerCertOptions *SignerCertOptions

	CertFile string
	KeyFile  string

	ExpireDays int

	User   string
	Groups []string

	Overwrite bool
	Output    io.Writer
}

type CreateServerCertOptions struct {
	SignerCertOptions *SignerCertOptions

	CertFile string
	KeyFile  string

	ExpireDays int

	Hostnames []string
	Overwrite bool
	Output    io.Writer
}

func (o CreateServerCertOptions) Validate(args []string) error {
	if len(args) != 0 {
		return errors.New("no arguments are supported")
	}
	if len(o.Hostnames) == 0 {
		return errors.New("at least one hostname must be provided")
	}
	if len(o.CertFile) == 0 {
		return errors.New("cert must be provided")
	}
	if len(o.KeyFile) == 0 {
		return errors.New("key must be provided")
	}

	if o.ExpireDays <= 0 {
		return errors.New("expire-days must be valid number of days")
	}

	if o.SignerCertOptions == nil {
		return errors.New("signer options are required")
	}
	if err := o.SignerCertOptions.Validate(); err != nil {
		return err
	}

	return nil
}

func (ca *CA) MakeAndWriteServerCert(certFile, keyFile string, hostnames []string, expireDays int) (*TLSCertificateConfig, error) {
	log.Printf("Generating server certificate in %s, key in %s", certFile, keyFile)

	server, err := ca.MakeServerCert(hostnames, expireDays)
	if err != nil {
		return nil, err
	}
	if err := server.writeCertConfig(certFile, keyFile); err != nil {
		return server, err
	}
	return server, nil
}

type CertificateExtensionFunc func(*x509.Certificate) error

func (ca *CA) MakeServerCert(hostnames []string, expireDays int, fns ...CertificateExtensionFunc) (*TLSCertificateConfig, error) {
	serverPublicKey, serverPrivateKey, _ := NewKeyPair()
	serverTemplate := newServerCertificateTemplate(pkix.Name{CommonName: hostnames[0]}, hostnames, time.Now)
	for _, fn := range fns {
		if err := fn(serverTemplate); err != nil {
			return nil, err
		}
	}
	serverCrt, err := ca.signCertificate(serverTemplate, serverPublicKey)
	if err != nil {
		return nil, err
	}
	server := &TLSCertificateConfig{
		Certs: append([]*x509.Certificate{serverCrt}, ca.Config.Certs...),
		Key:   serverPrivateKey,
	}
	return server, nil
}

func (ca *CA) EnsureServerCert(certFile, keyFile string, hostnames []string, expireDays int) (*TLSCertificateConfig, bool, error) {
	certConfig, err := GetServerCert(certFile, keyFile, hostnames)
	if err != nil {
		certConfig, err = ca.MakeAndWriteServerCert(certFile, keyFile, hostnames, expireDays)
		return certConfig, true, err
	}

	return certConfig, false, nil
}
func IPAddressesDNSNames(hosts []string) ([]net.IP, []string) {
	ips := []net.IP{}
	dns := []string{}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, host)
		}
	}

	// Include IP addresses as DNS subjectAltNames in the cert as well, for the sake of Python, Windows (< 10), and unnamed other libraries
	// Ensure these technically invalid DNS subjectAltNames occur after the valid ones, to avoid triggering cert errors in Firefox
	// See https://bugzilla.mozilla.org/show_bug.cgi?id=1148766
	for _, ip := range ips {
		dns = append(dns, ip.String())
	}

	return ips, dns
}

func GetServerCert(certFile, keyFile string, hostnames []string) (*TLSCertificateConfig, error) {
	server, err := GetTLSCertificateConfig(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cert := server.Certs[0]
	ips, dns := IPAddressesDNSNames(hostnames)
	missingIps := ipsNotInSlice(ips, cert.IPAddresses)
	missingDns := stringsNotInSlice(dns, cert.DNSNames)
	if len(missingIps) == 0 && len(missingDns) == 0 {
		log.Printf("Found existing server certificate in %s", certFile)
		return server, nil
	}

	return nil, fmt.Errorf("Existing server certificate in %s was missing some hostnames (%v) or IP addresses (%v).", certFile, missingDns, missingIps)
}
func (o CreateServerCertOptions) CreateServerCert() (*TLSCertificateConfig, error) {
	log.Printf("Creating a server cert with: %#v", o)

	signerCert, err := o.SignerCertOptions.CA()
	if err != nil {
		return nil, err
	}

	var ca *TLSCertificateConfig
	written := true
	if o.Overwrite {
		ca, err = signerCert.MakeAndWriteServerCert(o.CertFile, o.KeyFile, o.Hostnames, o.ExpireDays)
	} else {
		ca, written, err = signerCert.EnsureServerCert(o.CertFile, o.KeyFile, o.Hostnames, o.ExpireDays)
	}
	if written {
		log.Printf("Generated new server certificate as %s, key as %s\n", o.CertFile, o.KeyFile)
	} else {
		log.Printf("Keeping existing server certificate at %s, key at %s\n", o.CertFile, o.KeyFile)
	}
	return ca, err
}

func newServerCertificateTemplate(subject pkix.Name, hosts []string, currentTime func() time.Time) *x509.Certificate {
	lifetime := time.Duration(DefaultCertificateLifetimeInDays) * 24 * time.Hour

	template := &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    currentTime().Add(-1 * time.Second),
		NotAfter:     currentTime().Add(lifetime),
		SerialNumber: big.NewInt(1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IPAddresses, template.DNSNames = IPAddressesDNSNames(hosts)

	return template
}

var DefaultCertificateLifetimeInDays = 365

func CreateCert(commonName, certDir, caPrefix string) (*tls.Certificate, error) {
	signerCertOptions := &SignerCertOptions{
		CertFile:   DefaultCertFilename(certDir, caPrefix),
		KeyFile:    DefaultKeyFilename(certDir, caPrefix),
		SerialFile: DefaultSerialFilename(certDir, caPrefix),
	}
	clientCertOptions := &CreateClientCertOptions{
		SignerCertOptions: signerCertOptions,
		CertFile:          DefaultCertFilename(certDir, commonName),
		KeyFile:           DefaultKeyFilename(certDir, commonName),
		ExpireDays:        DefaultCertificateLifetimeInDays,
		User:              commonName,
		Overwrite:         true,
	}
	if err := clientCertOptions.Validate(nil); err != nil {
		return nil, err
	}
	certConfig, err := clientCertOptions.CreateClientCert()
	if err != nil {
		return nil, err
	}
	certBytes, keyBytes, err := certConfig.GetPEMBytes()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

type CreateSignerCertOptions struct {
	CertFile   string
	KeyFile    string
	SerialFile string
	ExpireDays int
	Name       string
	Output     io.Writer

	Overwrite bool
}

func (o CreateSignerCertOptions) Validate(args []string) error {
	if len(args) != 0 {
		return errors.New("no arguments are supported")
	}
	if len(o.CertFile) == 0 {
		return errors.New("cert must be provided")
	}
	if len(o.KeyFile) == 0 {
		return errors.New("key must be provided")
	}
	if o.ExpireDays <= 0 {
		return errors.New("expire-days must be valid number of days")
	}
	if len(o.Name) == 0 {
		return errors.New("name must be provided")
	}

	return nil
}

func (o CreateSignerCertOptions) CreateSignerCert() (*CA, error) {
	log.Printf("Creating a signer cert with: %#v", o)
	var ca *CA
	var err error
	written := true
	if o.Overwrite {
		ca, err = MakeCA(o.CertFile, o.KeyFile, o.Name, o.ExpireDays)
	} else {
		ca, written, err = EnsureCA(o.CertFile, o.KeyFile, o.Name, o.ExpireDays)
	}
	if written {
		log.Printf("Generated new CA for %s: cert in %s and key in %s\n", o.Name, o.CertFile, o.KeyFile)
	} else {
		log.Printf("Keeping existing CA cert at %s and key at %s\n", o.CertFile, o.KeyFile)
	}
	return ca, err
}

// EnsureCA returns a CA, whether it was created (as opposed to pre-existing), and any error
// if serialFile is empty, a RandomSerialGenerator will be used
func EnsureCA(certFile, keyFile, name string, expireDays int) (*CA, bool, error) {
	if ca, err := GetCA(certFile, keyFile); err == nil {
		return ca, false, err
	}
	ca, err := MakeCA(certFile, keyFile, name, expireDays)
	return ca, true, err
}
func NewKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

// Can be used as a certificate in http.Transport TLSClientConfig
func newClientCertificateTemplate(subject pkix.Name, currentTime func() time.Time) *x509.Certificate {
	lifetime := time.Duration(DefaultCertificateLifetimeInDays) * 24 * time.Hour

	return &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    currentTime().Add(-1 * time.Second),
		NotAfter:     currentTime().Add(lifetime),
		SerialNumber: big.NewInt(1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
}

// Can be used for CA or intermediate signing certs
func newSigningCertificateTemplate(subject pkix.Name, expireDays int, currentTime func() time.Time) *x509.Certificate {
	caLifetime := time.Duration(DefaultCertificateLifetimeInDays) * 24 * time.Hour

	return &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    currentTime().Add(-1 * time.Second),
		NotAfter:     currentTime().Add(caLifetime),
		SerialNumber: big.NewInt(1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}
}

func signCertificate(template *x509.Certificate, requestKey crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, requestKey, issuerKey)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, errors.New("Expected a single certificate")
	}
	return certs[0], nil
}

func (c *TLSCertificateConfig) writeCertConfig(certFile, keyFile string) error {
	if err := WriteCertificates(certFile, c.Certs...); err != nil {
		return err
	}
	if err := WriteKeyFile(keyFile, c.Key); err != nil {
		return err
	}
	return nil
}

func MakeCA(certFile, keyFile, name string, expireDays int) (*CA, error) {
	log.Printf("Generating new CA for %s cert, and key in %s, %s", name, certFile, keyFile)
	// Create CA cert
	rootcaPublicKey, rootcaPrivateKey, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	rootcaTemplate := newSigningCertificateTemplate(pkix.Name{CommonName: name}, expireDays, time.Now)
	rootcaCert, err := signCertificate(rootcaTemplate, rootcaPublicKey, rootcaTemplate, rootcaPrivateKey)
	if err != nil {
		return nil, err
	}
	caConfig := &TLSCertificateConfig{
		Certs: []*x509.Certificate{rootcaCert},
		Key:   rootcaPrivateKey,
	}
	if err := caConfig.writeCertConfig(certFile, keyFile); err != nil {
		return nil, err
	}

	serialGenerator := &RandomSerialGenerator{}

	return &CA{
		SerialGenerator: serialGenerator,
		Config:          caConfig,
	}, nil
}

func CreateCA(certDir, caPrefix string) (string, error) {
	createSignerCertOptions := CreateSignerCertOptions{
		CertFile:   DefaultCertFilename(certDir, caPrefix),
		KeyFile:    DefaultKeyFilename(certDir, caPrefix),
		SerialFile: DefaultSerialFilename(certDir, caPrefix),
		ExpireDays: DefaultCertificateLifetimeInDays,
		Name:       caPrefix,
		Overwrite:  true,
	}
	if err := createSignerCertOptions.Validate(nil); err != nil {
		return "", err
	}
	if _, err := createSignerCertOptions.CreateSignerCert(); err != nil {
		return "", err
	}
	return createSignerCertOptions.CertFile, nil
}

func (o CreateClientCertOptions) Validate(args []string) error {
	if len(args) != 0 {
		return errors.New("no arguments are supported")
	}
	if len(o.CertFile) == 0 {
		return errors.New("cert must be provided")
	}
	if len(o.KeyFile) == 0 {
		return errors.New("key must be provided")
	}
	if o.ExpireDays <= 0 {
		return errors.New("expire-days must be valid number of days")
	}
	if len(o.User) == 0 {
		return errors.New("user must be provided")
	}

	if o.SignerCertOptions == nil {
		return errors.New("signer options are required")
	}
	if err := o.SignerCertOptions.Validate(); err != nil {
		return err
	}

	return nil
}

// DefaultInfo provides a simple user information exchange object
// for components that implement the UserInfo interface.
type DefaultInfo struct {
	Name   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

func (o CreateClientCertOptions) CreateClientCert() (*TLSCertificateConfig, error) {
	log.Printf("Creating a client cert with: %#v and %#v", o, o.SignerCertOptions)

	signerCert, err := o.SignerCertOptions.CA()
	if err != nil {
		return nil, err
	}

	var cert *TLSCertificateConfig
	written := true
	if o.Overwrite {
		cert, err = signerCert.MakeClientCertificate(o.CertFile, o.KeyFile, o.User, o.Groups)
	} else {
		cert, written, err = signerCert.EnsureClientCertificate(o.CertFile, o.KeyFile, o.User, o.Groups, "")
	}
	if written {
		log.Printf("Generated new client cert as %s and key as %s\n", o.CertFile, o.KeyFile)
	} else {
		log.Printf("Keeping existing client cert at %s and key at %s\n", o.CertFile, o.KeyFile)
	}
	return cert, err
}

func WriteCertificates(path string, certs ...*x509.Certificate) error {
	// ensure parent dir
	if err := os.MkdirAll(filepath.Dir(path), os.FileMode(0755)); err != nil {
		return err
	}

	bytes, err := encodeCertificates(certs...)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, bytes, os.FileMode(0644))
}

func WriteKeyFile(path string, key crypto.PrivateKey) error {
	// ensure parent dir
	if err := os.MkdirAll(filepath.Dir(path), os.FileMode(0755)); err != nil {
		return err
	}

	b, err := encodeKey(key)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, b, os.FileMode(0600))
}

func writePublicKeyFile(path string, key *rsa.PublicKey) error {
	// ensure parent dir
	if err := os.MkdirAll(filepath.Dir(path), os.FileMode(0755)); err != nil {
		return err
	}

	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	b := bytes.Buffer{}
	if err := pem.Encode(&b, &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}); err != nil {
		return err
	}

	return ioutil.WriteFile(path, b.Bytes(), os.FileMode(0600))
}

func writePrivateKeyFile(path string, key *rsa.PrivateKey) error {
	// ensure parent dir
	if err := os.MkdirAll(filepath.Dir(path), os.FileMode(0755)); err != nil {
		return err
	}

	b := bytes.Buffer{}
	err := pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, b.Bytes(), os.FileMode(0600))
}
func stringsNotInSlice(needles []string, haystack []string) []string {
	missing := []string{}
	for _, needle := range needles {
		if !stringInSlice(needle, haystack) {
			missing = append(missing, needle)
		}
	}
	return missing
}

func stringInSlice(needle string, haystack []string) bool {
	for _, straw := range haystack {
		if needle == straw {
			return true
		}
	}
	return false
}

func ipsNotInSlice(needles []net.IP, haystack []net.IP) []net.IP {
	missing := []net.IP{}
	for _, needle := range needles {
		if !ipInSlice(needle, haystack) {
			missing = append(missing, needle)
		}
	}
	return missing
}

func ipInSlice(needle net.IP, haystack []net.IP) bool {
	for _, straw := range haystack {
		if needle.Equal(straw) {
			return true
		}
	}
	return false
}
