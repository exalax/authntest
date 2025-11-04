package authntest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistration(t *testing.T) {
	user := newTestUser()
	authnSrv, err := newAuthnServer(user)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/reg/begin", authnSrv.handleRegBegin)
	mux.HandleFunc("/reg/finish", authnSrv.handleRegFinish)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := srv.Client()

	resp, err := client.Post(srv.URL+"/reg/begin", "application/json", nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	defer func() {
		_ = resp.Body.Close()
	}()
	pk, err := NewPasskey(resp.Body)
	require.NoError(t, err)

	pkResp, err := pk.CreationResponse()
	require.NoError(t, err)

	resp, err = client.Post(srv.URL+"/reg/finish", "application/json", bytes.NewReader(pkResp))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
}
