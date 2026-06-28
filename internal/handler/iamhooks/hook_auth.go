// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hook_auth.go — Bearer auth для Hydra hook endpoints.
//
// Bearer `X-Kacho-Hook-Token` validated против authn.hook-shared-secret. Если
// configured secret пустой — accept без auth (только dev-mode; in production
// mode handler возвращает 500 на nil secret).
package iamhooks

import (
	"crypto/subtle"
	"net/http"
)

const hookAuthHeader = "X-Kacho-Hook-Token"

// requireHookAuth — middleware-style helper, проверяет Bearer-token из
// header'а. Возвращает true если auth прошел; false + 401 если нет.
//
// expected пустой — secret не настроен → fail-closed: 401. Это безопасное
// default-behaviour, потому что hook endpoints не должны быть accessible без
// auth даже в dev (Hydra всегда передает configured secret).
func requireHookAuth(w http.ResponseWriter, r *http.Request, expected string) bool {
	if expected == "" {
		// Misconfigured: secret должен быть set в production. Fail-closed.
		http.Error(w, `{"error":"hook_secret_not_configured"}`, http.StatusInternalServerError)
		return false
	}
	got := r.Header.Get(hookAuthHeader)
	if got == "" {
		// Альтернативный заголовок Authorization: Bearer <token>.
		if a := r.Header.Get("Authorization"); len(a) > 7 && a[:7] == "Bearer " {
			got = a[7:]
		}
	}
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="kacho-iam-hooks"`)
		http.Error(w, `{"error":"invalid_hook_token"}`, http.StatusUnauthorized)
		return false
	}
	return true
}
