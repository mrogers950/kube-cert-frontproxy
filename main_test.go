package main

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

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
