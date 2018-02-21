package main

import (
	"io/ioutil"
	"path"
	"testing"

	util "github.com/mrogers950/kube-cert-frontproxy/testutils"
)

func TestValidateCert(t *testing.T) {
	testDir, err := ioutil.TempDir("/tmp", "kube-cert-frontproxy-test")
	if err != nil {
		t.Fatalf("error setting up temp dir %s", err)
	}

	caFile := path.Join(testDir, "ca.crt")
	caKeyFile := path.Join(testDir, "cakey.pem")
	clientFile := path.Join(testDir, "client.crt")
	clientKeyFile := path.Join(testDir, "clientkey.pem")
	serverFile := path.Join(testDir, "server.crt")
	serverKeyFile := path.Join(testDir, "serverkey.pem")

	clientSubject := "client"
	serverSubject := "server"

	ca, err := util.MakeCA(caFile, caKeyFile, "CA", 20)
	if err != nil {
		t.Fatalf("error creating CA %s", err)
	}
	_, err = ca.MakeClientCertificate(clientFile, clientKeyFile, clientSubject, []string{"users"})
	if err != nil {
		t.Fatalf("error creating client certificate config %s", err)
	}
	_, err = ca.MakeAndWriteServerCert(serverFile, serverKeyFile, []string{serverSubject}, 10)
	if err != nil {
		t.Fatalf("error creating client certificate config %s", err)
	}
}

/*
func TestValidateCert(t *testing.T) {
	testDir, err := ioutil.TempDir("/tmp", "kube-cert-frontproxy-test")
	if err != nil {
		t.Fatalf("error setting up temp dir %s", err)
	}
	testValidatorScript := path.Join(testDir, "validate.py")
	// open and write validator script
	v, err := os.Open(testValidatorScript)
	if err != nil {
		t.Fatalf("error opening validator %s", err)
	}

	infoResult, err := ValidateCert(testCert, testValidatorScript)
}
*/
