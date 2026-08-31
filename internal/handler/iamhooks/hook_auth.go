// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hook_auth.go — Bearer auth для Hydra hook endpoints.
//
// Bearer `X-Kacho-Hook-Token` validated против authn.hook-shared-secret. Если
// configured secret пустой (misconfiguration) — fail-closed 500, БЕЗ auth-bypass
// (никакого dev-mode "accept without auth" — hook endpoints обязаны быть
// недоступны без валидного secret даже при пустой конфигурации).
//
// # Причин отказа ТРИ, и они различимы ТОЛЬКО в журнале (#1747)
//
//	заголовка нет     401  чинится настройкой ВЫЗЫВАЮЩЕГО
//	величина не та    401  чинится сверкой секрета у обеих сторон
//	секрет не задан   500  чинится настройкой ПРИНИМАЮЩЕГО
//
// Две первые дают ПОБАЙТОВО ОДИНАКОВЫЙ ответ — намеренно: различимый снаружи
// отказ здесь есть оракул существования. Раньше они были неразличимы и в
// журнале тоже, то есть не различались ниоткуда; теперь каждая называет свою
// причину оператору, не называя её вызывающему.
//
// Побайтовая одинаковость держится ПОСТРОЕНИЕМ — единственным производителем
// отказа `writeHookAuthRefusal`, а не совпадением литералов. Обе стороны
// утверждения (журнал различает · ответ не различает) закреплены пробой
// hook_auth_reason_test.go; способность каждой половины упасть отдельно —
// hook_auth_reason_injection_test.go.
package iamhooks

import (
	"crypto/subtle"
	"log/slog"
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
func requireHookAuth(w http.ResponseWriter, r *http.Request, expected string, logger *slog.Logger, tag string) bool {
	if expected == "" {
		// Misconfigured: secret должен быть set в production. Fail-closed: 500,
		// не dev-mode-bypass.
		//
		// Пишем в журнал: до #1747 эта полоса не оставляла НИЧЕГО, то есть
		// операторская ошибка нашей стороны была ненаблюдаема — «ноль отказов за
		// всю жизнь контроля» неотличимо от «контроль не сработал ни разу»
		// (`security.md` §Hardening п.8).
		if logger != nil {
			logger.Error(tag + ": hook secret is not configured; refusing closed")
		}
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

	// ── ПРИЧИНА РАЗВЕДЕНА В ЖУРНАЛЕ, НО НЕ В ОТВЕТЕ (#1747) ──────────────────
	//
	// «Заголовка нет» и «величина не та» — РАЗНЫЕ причины с разной починкой:
	// первая чинится настройкой ВЫЗЫВАЮЩЕГО (провайдер не шлёт величину или шлёт
	// её другим заголовком), вторая — сверкой секрета у ОБЕИХ сторон. До этой
	// правки они давали побайтово одинаковый 401 и ни одной строки в журнале,
	// поэтому не различались ниоткуда. Цена уже уплачена однажды: из наблюдения
	// «пустая настройка даёт 500» был выведен диагноз «величина есть и не та»,
	// который из наблюдения НЕ СЛЕДУЕТ, и полоса потратила заход впустую.
	//
	// ОТВЕТ ОСТАЁТСЯ ЕДИНЫМ НАМЕРЕННО. Различимый снаружи отказ здесь есть
	// ОРАКУЛ: по нему отличают «величина не та» от «заголовка нет», то есть
	// нащупывают, какой заголовок вообще читается. Поэтому обе ветки сходятся в
	// один и тот же `writeHookAuthRefusal` — не «пишут одинаковый ответ рядом»,
	// а зовут ОДНУ функцию: два места об одном предмете разошлись бы молча.
	//
	// В журнал идёт ПРИЧИНА, а не ВЕЛИЧИНА: ни ожидаемый секрет, ни
	// предъявленная строка не пишутся никуда. Диагностика, оплаченная утечкой
	// стерегомого секрета, — не диагностика.
	switch {
	case got == "":
		if logger != nil {
			logger.Warn(tag + ": hook auth header absent")
		}
		writeHookAuthRefusal(w)
		return false
	case subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1:
		if logger != nil {
			logger.Warn(tag + ": hook auth token mismatch")
		}
		writeHookAuthRefusal(w)
		return false
	}
	return true
}

// writeHookAuthRefusal — ЕДИНСТВЕННЫЙ производитель отказа аутентификации хука.
//
// Существует затем, чтобы побайтовая одинаковость двух причин держалась
// ПОСТРОЕНИЕМ, а не совпадением двух литералов, которые следующая правка
// разведёт молча. Всякая новая причина отказа обязана звать её, а не писать
// свой ответ.
func writeHookAuthRefusal(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="kacho-iam-hooks"`)
	http.Error(w, `{"error":"invalid_hook_token"}`, http.StatusUnauthorized)
}
