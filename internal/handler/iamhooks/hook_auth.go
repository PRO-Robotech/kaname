// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hook_auth.go — Bearer auth для Hydra hook endpoints.
//
// Bearer `X-Kacho-Hook-Token` validated против authn.hook-shared-secret. Если
// configured secret пустой (misconfiguration) — fail-closed 500, БЕЗ auth-bypass
// (никакого dev-mode "accept without auth" — hook endpoints обязаны быть
// недоступны без валидного secret даже при пустой конфигурации).
package iamhooks

import (
	"crypto/subtle"
	"net/http"
)

const hookAuthHeader = "X-Kacho-Hook-Token"

// requireHookAuth — middleware-style helper, проверяет Bearer-token из
// header'а. Возвращает true если auth прошел; false + error-response если нет.
//
// expected пустой — secret не настроен → fail-closed: 500
// (`hook_secret_not_configured`), НЕ auth-bypass. Misconfiguration (secret не
// задан в конфиге) — это operator-ошибка, не "no auth required"; hook
// endpoints не должны быть accessible без валидного secret ни при каких
// условиях (Hydra всегда передает configured secret).
func requireHookAuth(w http.ResponseWriter, r *http.Request, expected string) bool {
	if expected == "" {
		// Misconfigured: secret должен быть set в production. Fail-closed: 500,
		// не dev-mode-bypass.
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
