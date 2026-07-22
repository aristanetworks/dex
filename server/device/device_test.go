package device

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestGetDeviceVerificationURI(t *testing.T) {
	u, err := url.Parse("https://dex.example.com/non-root-path")
	require.NoError(t, err)

	h := &Handler{IssuerURL: *u}
	require.Equal(t, "/non-root-path/device/auth/verify_code", h.getDeviceVerificationURI())
}

func TestVerifyUserCodeConnectorIDPassthrough(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	store := memory.New(logger)
	issuerURL, err := url.Parse("https://dex.example.com")
	require.NoError(t, err)

	ctx := t.Context()
	require.NoError(t, store.CreateDeviceRequest(ctx, storage.DeviceRequest{
		UserCode:   "ABCD-EFGH",
		DeviceCode: "device-code-123",
		ClientID:   "test-client",
		Scopes:     []string{"openid"},
		Expiry:     time.Now().Add(10 * time.Minute),
	}))

	h := &Handler{
		IssuerURL: *issuerURL,
		Storage:   store,
		Now:       time.Now,
		Logger:    logger,
	}

	t.Run("connector_id passed through to auth redirect", func(t *testing.T) {
		form := url.Values{}
		form.Set("user_code", "ABCD-EFGH")
		form.Set("connector_id", "google")
		req := httptest.NewRequest(http.MethodPost, "/device/auth/verify_code", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		h.verifyUserCode(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)
		loc := rr.Header().Get("Location")
		locURL, err := url.Parse(loc)
		require.NoError(t, err)
		require.Equal(t, "google", locURL.Query().Get("connector_id"))
	})

	t.Run("no connector_id omits it from auth redirect", func(t *testing.T) {
		form := url.Values{}
		form.Set("user_code", "ABCD-EFGH")
		req := httptest.NewRequest(http.MethodPost, "/device/auth/verify_code", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		h.verifyUserCode(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)
		loc := rr.Header().Get("Location")
		locURL, err := url.Parse(loc)
		require.NoError(t, err)
		require.Empty(t, locURL.Query().Get("connector_id"))
	})
}
