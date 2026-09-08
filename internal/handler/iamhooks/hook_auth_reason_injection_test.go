// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hook_auth_reason_injection_test.go — ДОКАЗАТЕЛЬСТВО, что проба #1747 способна
// упасть по КАЖДОЙ половине ОТДЕЛЬНО.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ОТДЕЛЬНОЕ ДОКАЗАТЕЛЬСТВО
//
// Утверждение соседней пробы — ПАРНОЕ: причина различима в журнале И
// неразличима в ответе. У парного утверждения есть свой способ выродиться:
// одна половина держит, вторая молчит, а суммарный вердикт зелен. Отличить это
// от исправной работы чтением нельзя — обе половины выглядят написанными.
//
// Поэтому дефект вносится ПООЧЕРЁДНО, и каждая инъекция обязана ронять ТОЛЬКО
// свою половину: инъекция, роняющая обе, доказывает лишь то, что проба вообще
// умеет краснеть, и оставляет вторую половину непроверенной.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ ПРОГОНА, И ТРЕТИЙ ОБЯЗАТЕЛЕН
//
//	контроль        — дефекта нет: молчат ОБЕ половины;
//	инъекция «оракул»   — ответы разведены: краснеет ТОЛЬКО половина B,
//	                      половина A (различимость в журнале) остаётся зелёной;
//	инъекция «тишина»   — журналы сведены: краснеет ТОЛЬКО половина A,
//	                      половина B (побайтовая одинаковость) остаётся зелёной.
//
// Без контроля молчание половины неотличимо от её мёртвости.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИНЪЕКЦИЯ — ПОДСТАВНОЙ ПРОИЗВОДИТЕЛЬ, А НЕ ПРАВКА ПРОДУКТА
//
// Дефект вносится в КОПИЮ решения, а не в `requireHookAuth`: проба, правящая
// прод-код на ходу, меняет его для всех соседей по пакету. Копия обязана быть
// СТРУКТУРНО той же формы — иначе доказывалась бы способность упасть на чём-то
// другом, чем продукт.
package iamhooks

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hookAuthRefusalWriter — форма производителя отказа, которую подменяет инъекция.
type hookAuthRefusalWriter func(w http.ResponseWriter, cause string)

// injectableHookAuth — структурная копия `requireHookAuth` с вынесенными
// наружу производителем отказа и производителем записи журнала. Ветвление,
// порядок проверок и коды — те же; подменяемы ровно две вещи, по одной на
// половину утверждения.
func injectableHookAuth(
	w http.ResponseWriter, r *http.Request, expected string,
	logger *slog.Logger, tag string,
	refuse hookAuthRefusalWriter,
	logLine func(logger *slog.Logger, tag, cause string),
) bool {
	got := r.Header.Get(hookAuthHeader)
	if got == "" {
		if a := r.Header.Get("Authorization"); len(a) > 7 && a[:7] == "Bearer " {
			got = a[7:]
		}
	}
	cause := ""
	switch {
	case got == "":
		cause = "absent"
	case hookAuthValueDiffers(got, expected):
		cause = "mismatch"
	default:
		return true
	}
	logLine(logger, tag, cause)
	refuse(w, cause)
	return false
}

// hookAuthValueDiffers — та же сверка, что в продукте, вынесенная ради
// читаемости ветвления копии.
func hookAuthValueDiffers(got, expected string) bool {
	return !(len(got) == len(expected) && got == expected)
}

// honestRefusal / honestLog — поведение БЕЗ дефекта.
func honestRefusal(w http.ResponseWriter, _ string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="kaname-hooks"`)
	http.Error(w, `{"error":"invalid_hook_token"}`, http.StatusUnauthorized)
}

func honestLog(logger *slog.Logger, tag, cause string) {
	if logger != nil {
		logger.Warn(tag + ": hook auth " + cause)
	}
}

// oracleRefusal — ИНЪЕКЦИЯ B: причина утекает в ответ (тело различается).
func oracleRefusal(w http.ResponseWriter, cause string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="kaname-hooks"`)
	http.Error(w, `{"error":"invalid_hook_token","cause":"`+cause+`"}`, http.StatusUnauthorized)
}

// mutedLog — ИНЪЕКЦИЯ A: обе причины пишут дословно одно.
func mutedLog(logger *slog.Logger, tag, _ string) {
	if logger != nil {
		logger.Warn(tag + ": hook auth failed")
	}
}

// probeHalves — что увидели бы обе половины утверждения на данной паре
// производителей. Возвращает (различимо в журнале, одинаково в ответе).
func probeHalves(t *testing.T, refuse hookAuthRefusalWriter, logLine func(*slog.Logger, string, string)) (logDistinct, respIdentical bool) {
	t.Helper()

	run := func(present bool) (body, headers, log string) {
		var buf bytes.Buffer
		// ВРЕМЯ СНИМАЕТСЯ. Два прогона идут в разные моменты, поэтому метка
		// времени различает записи ВСЕГДА — и «журналы различимы» становится
		// истинным даже там, где текст сведён к одному. Инъекция «тишина»
		// тогда не срабатывает, а проба читает собственный недетерминизм как
		// проверяемое свойство. Поймано конвейером: локально две записи
		// попадали в одну наносекунду и совпадали, на ранере — нет.
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		}))
		r := httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/token", nil)
		if present {
			r.Header.Set(hookAuthHeader, hookAuthProbePresented)
		}
		w := httptest.NewRecorder()
		if ok := injectableHookAuth(w, r, hookAuthProbeSecret, logger, "probe_hook", refuse, logLine); ok {
			t.Fatalf("копия пропустила вызов, которого пропускать не должна")
		}
		var hdr []string
		for k, v := range w.Result().Header {
			hdr = append(hdr, k+": "+strings.Join(v, ","))
		}
		sortStrings(hdr)
		return w.Body.String(), strings.Join(hdr, "\n"), buf.String()
	}

	aBody, aHdr, aLog := run(false)
	mBody, mHdr, mLog := run(true)

	logDistinct = strings.TrimSpace(aLog) != "" && strings.TrimSpace(mLog) != "" && aLog != mLog
	respIdentical = aBody == mBody && aHdr == mHdr
	return logDistinct, respIdentical
}

// TestHookAuthReasonInjection — три прогона; каждая инъекция роняет ТОЛЬКО свою
// половину.
func TestHookAuthReasonInjection(t *testing.T) {
	t.Run("контроль: дефекта нет — молчат обе половины", func(t *testing.T) {
		logDistinct, respIdentical := probeHalves(t, honestRefusal, honestLog)
		if !logDistinct {
			t.Errorf("контроль: половина A краснеет на исправном коде — она мертва или сформулирована не о том")
		}
		if !respIdentical {
			t.Errorf("контроль: половина B краснеет на исправном коде — она мертва или сформулирована не о том")
		}
	})

	t.Run("инъекция «оракул»: краснеет ТОЛЬКО половина B", func(t *testing.T) {
		logDistinct, respIdentical := probeHalves(t, oracleRefusal, honestLog)
		if respIdentical {
			t.Errorf("половина B НЕ ЗАМЕТИЛА причину, утёкшую в тело ответа — проба на оракул мертва")
		}
		if !logDistinct {
			t.Errorf("инъекция уронила ЛИШНЕЕ: половина A тоже покраснела, значит доказано не то")
		}
	})

	t.Run("инъекция «тишина»: краснеет ТОЛЬКО половина A", func(t *testing.T) {
		logDistinct, respIdentical := probeHalves(t, honestRefusal, mutedLog)
		if logDistinct {
			t.Errorf("половина A НЕ ЗАМЕТИЛА сведённые журналы — проба на различимость мертва")
		}
		if !respIdentical {
			t.Errorf("инъекция уронила ЛИШНЕЕ: половина B тоже покраснела, значит доказано не то")
		}
	})
}
