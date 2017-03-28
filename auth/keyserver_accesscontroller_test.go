package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var jsonKeyID = "QH6C:ST72:JAOS:ZBJC:ABP3:BTCG:NHJ5:46AI:PA3A:VPAV:QRNL:N5ZB"
var validSingleJsonKey = `{"e": "AQAB","kid": "QH6C:ST72:JAOS:ZBJC:ABP3:BTCG:NHJ5:46AI:PA3A:VPAV:QRNL:N5ZB","kty": "RSA","n": "yqdQgnelhAPMSeyH0kr3UGePK9oFOmNfwD0Ymnh7YYXr21VHWwyM2eVW3cnLd9KXywDFtGSe9oFDbnOuMCdUowdkBcaHju-isbv5KEbNSoy_T2Rip-6L0cY63YzcMJzv1nEYztYXS8wz76pSK81BKBCLapqOCmcPeCvV9yaoFZYvZEsXCl5jjXN3iujSzSF5Z6PpNFlJWTErMT2Z4QfbDKX2Nw6vJN6JnGpTNHZvgvcyNX8vkSgVpQ8DFnFkBEx54PvRV5KpHAq6AsJxKONMo11idQS2PfCNpa2hvz9O6UZe-eIX8jPo5NW8TuGZJumbdPT_nxTDLfCqfiZboeI0Pw"}`
var validJsonKeys = `{"keys": [{"e": "AQAB","kid": "QH6C:ST72:JAOS:ZBJC:ABP3:BTCG:NHJ5:46AI:PA3A:VPAV:QRNL:N5ZB","kty": "RSA","n": "yqdQgnelhAPMSeyH0kr3UGePK9oFOmNfwD0Ymnh7YYXr21VHWwyM2eVW3cnLd9KXywDFtGSe9oFDbnOuMCdUowdkBcaHju-isbv5KEbNSoy_T2Rip-6L0cY63YzcMJzv1nEYztYXS8wz76pSK81BKBCLapqOCmcPeCvV9yaoFZYvZEsXCl5jjXN3iujSzSF5Z6PpNFlJWTErMT2Z4QfbDKX2Nw6vJN6JnGpTNHZvgvcyNX8vkSgVpQ8DFnFkBEx54PvRV5KpHAq6AsJxKONMo11idQS2PfCNpa2hvz9O6UZe-eIX8jPo5NW8TuGZJumbdPT_nxTDLfCqfiZboeI0Pw"}]}`

type testCase struct {
	in  string
	out string
}

func TestKeyServerAccessControllerUpdateKeys(t *testing.T) {
	testCasesMultipleKeys := []testCase{
		{`not json`, "invalid character"},
		{`{"keys":[{"invalid-key":{}}]}`, "no valid keys found"},
	}
	for _, tc := range testCasesMultipleKeys {
		ac, ts := httpTestSetup(tc)
		err := ac.updateKeys()
		require.Contains(t, err.Error(), tc.out)
		ts.Close()
	}
	ac, _ := httpTestSetup(testCase{validJsonKeys, ""})
	err := ac.updateKeys()
	require.NoError(t, err)
	require.Equal(t, 1, len(ac.keys))
	require.Equal(t, jsonKeyID, ac.keys[jsonKeyID].KeyID)

}

func TestKeyServerAccessControllerUpdateKeysBadUrl(t *testing.T) {
	ac, ts := httpTestSetup(testCase{validJsonKeys, ""})
	ac.keyserver = "bad url"
	err := ac.updateKeys()
	require.Contains(t, err.Error(), "unsupported protocol scheme")
	ts.Close()

}

func TestTryFindKey(t *testing.T) {
	testCasesSingleKey := []testCase{
		{`not json`, "invalid character"},
		{`{"invalid-key": "missing"}`, "unknown json web key type"},
	}

	for _, tc := range testCasesSingleKey {
		ac, ts := httpTestSetup(tc)
		_, err := ac.tryFindKey(jsonKeyID)
		require.Contains(t, err.Error(), tc.out)
		ts.Close()
	}
	ac, _ := httpTestSetup(testCase{validSingleJsonKey, ""})
	publicKey, err := ac.tryFindKey(jsonKeyID)
	require.NoError(t, err)
	require.Equal(t, jsonKeyID, publicKey.KeyID)

}

func TestTryFindKeyBadUrl(t *testing.T) {
	ac, ts := httpTestSetup(testCase{validJsonKeys, ""})
	ac.keyserver = "bad url"
	_, err := ac.tryFindKey(jsonKeyID)
	require.Contains(t, err.Error(), "unsupported protocol scheme")
	ts.Close()
}

func TestCheckOptions(t *testing.T) {
	testCases := []testCase{
		{"", "quay token auth requires a valid option string"},
		{"not an int", "invalid duration not an int"},
		{"1", "missing unit in duration"},
	}

	config := make(map[string]interface{})
	config["realm"] = "real"
	config["issuer"] = "issuer"
	config["service"] = "service"
	config["keyserver"] = "keyserver"

	for _, tc := range testCases {
		if tc.in != "" {
			config["updateKeyInterval"] = tc.in
		}
		_, err := checkOptions(config)
		require.Contains(t, err.Error(), tc.out)
	}
	config["updateKeyInterval"] = "1s"
	opt, err := checkOptions(config)
	require.NoError(t, err)
	require.Equal(t, opt.updateKeyInterval, 1*time.Second)
}

func httpTestSetup(tc testCase) (keyserverAccessController, *httptest.Server) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(tc.in))

	}))
	ac := keyserverAccessController{
		keyserver: ts.URL,
		service:   "test",
	}
	return ac, ts
}
