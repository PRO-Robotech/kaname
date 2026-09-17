// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package breachcheck_test

import (
	"context"
	"crypto/sha1" // #nosec G505 -- протокол авторитета
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/clients/breachcheck"
)

func suffixOf(pw string) string {
	s := sha1.Sum([]byte(pw)) // #nosec G401
	return strings.ToUpper(hex.EncodeToString(s[:]))[5:]
}

// TestBreachCheck_F3_34_ThreeOutcomesByType — найден · чист · недоступен ·
// настроен не туда — четыре ответа авторитета, три типа исхода.
func TestBreachCheck_F3_34_ThreeOutcomesByType(t *testing.T) {
	ctx := context.Background()
	mode := "ok"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "ok":
			require.True(t, strings.HasPrefix(r.URL.Path, "/range/"))
			require.Len(t, strings.TrimPrefix(r.URL.Path, "/range/"), 5, "наружу уходят пять знаков")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("0000000000000000000000000000000000A:1\r\n" + suffixOf("password123456") + ":42\r\n"))
		case "down":
			w.WriteHeader(http.StatusBadGateway)
		case "html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>not here</html>"))
		case "404":
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := breachcheck.New(srv.URL, 0)
	require.NoError(t, err)

	v, err := c.Check(ctx, "password123456")
	require.NoError(t, err)
	require.Equal(t, humansession.BreachFound, v)
	v, err = c.Check(ctx, "a passphrase nobody leaked")
	require.NoError(t, err)
	require.Equal(t, humansession.BreachNotFound, v)

	mode = "down"
	_, err = c.Check(ctx, "x")
	require.ErrorIs(t, err, humansession.ErrBreachAuthorityUnavailable, "5xx — недоступен")
	mode = "html"
	_, err = c.Check(ctx, "x")
	require.ErrorIs(t, err, humansession.ErrBreachAuthorityMisconfigured, "HTML — не тот эндпоинт")
	mode = "404"
	_, err = c.Check(ctx, "x")
	require.ErrorIs(t, err, humansession.ErrBreachAuthorityMisconfigured, "404 — не тот эндпоинт")

	srv.Close()
	_, err = c.Check(ctx, "x")
	require.ErrorIs(t, err, humansession.ErrBreachAuthorityUnavailable, "отказ сети — недоступен")
	_, err = breachcheck.New("", 0)
	require.Error(t, err, "адрес без умолчания")
}
