package main

import (
	"io/ioutil"
	"path"
	"testing"

	util "github.com/mrogers950/kube-cert-frontproxy/testutils"
)

func TestCertProxyOptions_SetMappers(t *testing.T) {
	for _, test := range []struct {
		name        string
		opts        *CertProxyOptions
		expectedErr string
	}{
		{
			name: "none",
			opts: &CertProxyOptions{
				listenAddr:        "",
				backendAddr:       "",
				backendCA:         "",
				backendClientCert: "",
				backendClientKey:  "",
				proxyServingCert:  "",
				proxyServingKey:   "",
				proxyServingCA:    "",
				userHeader:        "",
				groupHeader:       "",
				extraHeader:       "",
				validatorScript:   "",
				fileMapPath:       "",
				scriptMapPath:     "",
				sanMapEnable:      false,
				mappers:           nil,
			},
			expectedErr: "at least one cert mapper is required",
		},
		{
			name: "only san",
			opts: &CertProxyOptions{
				listenAddr:        "",
				backendAddr:       "",
				backendCA:         "",
				backendClientCert: "",
				backendClientKey:  "",
				proxyServingCert:  "",
				proxyServingKey:   "",
				proxyServingCA:    "",
				userHeader:        "",
				groupHeader:       "",
				extraHeader:       "",
				validatorScript:   "",
				fileMapPath:       "",
				scriptMapPath:     "",
				sanMapEnable:      true,
				mappers:           nil,
			},
		},
		{
			name: "all",
			opts: &CertProxyOptions{
				listenAddr:        "",
				backendAddr:       "",
				backendCA:         "",
				backendClientCert: "",
				backendClientKey:  "",
				proxyServingCert:  "",
				proxyServingKey:   "",
				proxyServingCA:    "",
				userHeader:        "",
				groupHeader:       "",
				extraHeader:       "",
				fileMapPath:       "/foo",
				scriptMapPath:     "/bar",
				sanMapEnable:      false,
				mappers:           nil,
			},
		},
	} {
		err := test.opts.SetMappers()
		var mapn int
		if len(test.opts.fileMapPath) > 0 {
			mapn++
		}
		if len(test.opts.scriptMapPath) > 0 {
			mapn++
		}
		if test.opts.sanMapEnable {
			mapn++
		}

		if len(test.opts.mappers) != mapn {
			t.Fatalf("expected %v mappers, got %v", mapn, len(test.opts.mappers))
		}

		if err != nil {
			if len(test.expectedErr) == 0 {
				t.Fatalf("unexpected error %s", err)
			}
			if err.Error() != test.expectedErr {
				t.Fatalf("expected error '%s', got '%s'", test.expectedErr, err.Error())
			}
		} else if len(test.expectedErr) > 0 {
			t.Fatalf("expected error %s", test.expectedErr)
		}

	}
}

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
