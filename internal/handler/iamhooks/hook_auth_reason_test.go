// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hook_auth_reason_test.go — отказ обратного хука НАЗЫВАЕТ СВОЮ ПРИЧИНУ В
// ЖУРНАЛЕ и НЕ называет её в ответе (#1747).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// У отказа `requireHookAuth` три разные причины с тремя разными починками:
//
//	заголовка нет      — провайдер не настроен слать величину (или шлёт не тем
//	                     заголовком): чинится настройкой ВЫЗЫВАЮЩЕГО;
//	величина не та     — обе стороны шлют, но расходятся: чинится сверкой секрета;
//	секрет не задан    — наша сторона не настроена: чинится настройкой ПРИНИМАЮЩЕГО.
//
// Первые две давали побайтово одинаковый `401` И НИ ОДНОЙ СТРОКИ В ЖУРНАЛЕ,
// поэтому различить их было нельзя ниоткуда — ни снаружи, ни изнутри.
//
// Цена измерена, а не предположена: отсутствие различия породило неверную
// посылку в задании целой полосы. Из наблюдения «пустая настройка даёт 500» был
// сделан вывод «значит величина есть и не та» — он НЕ СЛЕДУЕТ, потому что
// отсутствующий заголовок даёт тот же `401`. Полоса потратила заход на
// побайтовую сверку токена, отвечавшую на половину вопроса.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — ОБЕ СТОРОНЫ, И ПОЛОВИНА ХУЖЕ ОБЕИХ
//
//	A. РАЗЛИЧИМО В ЖУРНАЛЕ. Тексты, которые пишут две причины `401`, различны,
//	   и каждая пишет хоть что-то.
//	B. НЕРАЗЛИЧИМО В ОТВЕТЕ — байт в байт: код, тело, ВСЕ заголовки. Различимый
//	   отказ здесь есть ОРАКУЛ существования: по нему отличают «величина не та»
//	   от «заголовка нет», а значит нащупывают, какой заголовок вообще читают.
//
// Одна половина без другой хуже, чем ни одной. Только A — диагностика куплена
// оракулом. Только B — сегодняшнее состояние: тишина, выданная за защиту.
//
// C. ЖУРНАЛ НЕ НЕСЁТ НИ ОЖИДАЕМОЙ ВЕЛИЧИНЫ, НИ ПРЕДЪЯВЛЕННОЙ. Признак причины —
//
//	это ПРИЧИНА, а не значение: секрет в журнале означал бы, что диагностику
//	оплатили утечкой того самого секрета, который она стережёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТО НЕ УТВЕРЖДАЕТ
//
//   - НЕ утверждает конкретных СЛОВ в журнале. Предмет — различимость причин,
//     а не формулировка; проверка на дословный текст ломалась бы от правки
//     сообщения и ничего не защищала.
//   - НЕ утверждает ничего о полосе `500` (секрет не задан) в части ответа: она
//     и так отличима снаружи, и это осознанно — операторская ошибка нашей
//     стороны, а не оракул о чужом заголовке. Утверждается только то, что она
//     ПЕРЕСТАЛА БЫТЬ МОЛЧАЛИВОЙ.
//
// Способность упасть по КАЖДОЙ половине отдельно доказана инъекцией —
// hook_auth_reason_injection_test.go.
package iamhooks

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	hookAuthProbeSecret    = "s3cr3t-expected-value"
	hookAuthProbePresented = "wrong-presented-value"
)

// hookAuthOutcome — всё, что видит вызывающий, плюс всё, что видит оператор.
type hookAuthOutcome struct {
	Status  int
	Body    string
	Headers string
	Log     string
}

// runHookAuth прогоняет один отказ и снимает ОБЕ стороны разом: ответ (то, что
// уходит вызывающему) и журнал (то, что остаётся у нас).
func runHookAuth(t *testing.T, header string, present bool, expected string) hookAuthOutcome {
	t.Helper()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	r := httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/token", nil)
	if present {
		r.Header.Set(header, hookAuthProbePresented)
	}
	w := httptest.NewRecorder()

	if ok := requireHookAuth(w, r, expected, logger, "probe_hook"); ok {
		t.Fatalf("requireHookAuth пропустил вызов, которого пропускать не должен")
	}

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	// Заголовки снимаются ЦЕЛИКОМ и в устойчивом порядке: оракул прячется не
	// только в теле. `httptest.ResponseRecorder` отдаёт их картой, поэтому
	// сравнивать надо нормализованный слепок, а не карту.
	var hdr []string
	for k, v := range res.Header {
		hdr = append(hdr, k+": "+strings.Join(v, ","))
	}
	// Порядок карты в Go не определён — стабилизируем, иначе сравнение
	// «байт в байт» краснело бы через раз на исправном коде.
	sortStrings(hdr)

	return hookAuthOutcome{
		Status:  res.StatusCode,
		Body:    w.Body.String(),
		Headers: strings.Join(hdr, "\n"),
		Log:     logBuf.String(),
	}
}

// sortStrings — сортировка на месте без импорта ради одной строки.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// TestHookAuthRefusalNamesItsCauseInTheLogOnly — несущее утверждение: причина
// различима у оператора и НЕ различима у вызывающего.
func TestHookAuthRefusalNamesItsCauseInTheLogOnly(t *testing.T) {
	absent := runHookAuth(t, hookAuthHeader, false, hookAuthProbeSecret)
	mismatch := runHookAuth(t, hookAuthHeader, true, hookAuthProbeSecret)

	// ── B. ОТВЕТ БАЙТ В БАЙТ ОДИНАКОВ (положительный контроль стоит первым:
	// без него утверждение A зеленело бы на продукте, ставшем оракулом) ──
	if absent.Status != mismatch.Status {
		t.Errorf("ОРАКУЛ: код ответа различает причины: заголовка нет %d, величина не та %d",
			absent.Status, mismatch.Status)
	}
	if absent.Status != http.StatusUnauthorized {
		t.Errorf("отказ обязан оставаться 401, получено %d", absent.Status)
	}
	if absent.Body != mismatch.Body {
		t.Errorf("ОРАКУЛ: тело ответа различает причины:\n  заголовка нет:  %q\n  величина не та: %q",
			absent.Body, mismatch.Body)
	}
	if absent.Headers != mismatch.Headers {
		t.Errorf("ОРАКУЛ: заголовки ответа различают причины:\n  заголовка нет:\n%s\n  величина не та:\n%s",
			absent.Headers, mismatch.Headers)
	}

	// ── A. ЖУРНАЛ РАЗЛИЧАЕТ ──
	if strings.TrimSpace(absent.Log) == "" {
		t.Errorf("причина «заголовка нет» не оставила в журнале НИЧЕГО — отказ ненаблюдаем")
	}
	if strings.TrimSpace(mismatch.Log) == "" {
		t.Errorf("причина «величина не та» не оставила в журнале НИЧЕГО — отказ ненаблюдаем")
	}
	if absent.Log == mismatch.Log {
		t.Errorf("журнал НЕ различает две причины отказа — обе пишут дословно одно:\n%s", absent.Log)
	}

	// ── C. ЖУРНАЛ НЕ НЕСЁТ НИ ОЖИДАЕМОЙ ВЕЛИЧИНЫ, НИ ПРЕДЪЯВЛЕННОЙ ──
	for name, out := range map[string]hookAuthOutcome{"заголовка нет": absent, "величина не та": mismatch} {
		if strings.Contains(out.Log, hookAuthProbeSecret) {
			t.Errorf("УТЕЧКА (%s): журнал несёт ОЖИДАЕМУЮ величину секрета", name)
		}
		if strings.Contains(out.Log, hookAuthProbePresented) {
			t.Errorf("УТЕЧКА (%s): журнал несёт ПРЕДЪЯВЛЕННУЮ величину", name)
		}
	}
}

// TestHookAuthAlternativeHeaderIsNotASeparateCause — законный близнец: величина,
// приехавшая запасным заголовком `Authorization: Bearer`, обязана вести себя
// как ПРИСЛАННАЯ. Без этой пробы «заголовка нет» можно было бы объявить по
// первому же заголовку и получить неверный признак на исправном вызове.
func TestHookAuthAlternativeHeaderIsNotASeparateCause(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	r := httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/token", nil)
	r.Header.Set("Authorization", "Bearer "+hookAuthProbeSecret)
	w := httptest.NewRecorder()

	if ok := requireHookAuth(w, r, hookAuthProbeSecret, logger, "probe_hook"); !ok {
		t.Fatalf("верная величина в запасном заголовке отвергнута; журнал: %s", logBuf.String())
	}
	if strings.TrimSpace(logBuf.String()) != "" {
		t.Errorf("успешный проход не должен ничего писать в журнал, получено: %s", logBuf.String())
	}
}

// TestHookAuthUnconfiguredSecretIsObservable — третья причина: наша сторона не
// настроена. Ответ у неё СВОЙ (500) и это осознанно — это операторская ошибка
// принимающего, а не признак о чужом заголовке. Утверждается ровно то, что она
// перестала быть молчаливой.
func TestHookAuthUnconfiguredSecretIsObservable(t *testing.T) {
	out := runHookAuth(t, hookAuthHeader, true, "")

	if out.Status != http.StatusInternalServerError {
		t.Errorf("ненастроенный секрет обязан давать 500 (fail-closed), получено %d", out.Status)
	}
	if strings.TrimSpace(out.Log) == "" {
		t.Errorf("ненастроенный секрет не оставил в журнале НИЧЕГО — операторская ошибка ненаблюдаема")
	}
}

// TestHookAuthLogsCarryTheCallerTag — признак причины бесполезен, если не видно,
// КОТОРЫЙ хук отказал: у службы их четыре, и они чинятся по-разному.
func TestHookAuthLogsCarryTheCallerTag(t *testing.T) {
	out := runHookAuth(t, hookAuthHeader, false, hookAuthProbeSecret)
	if !strings.Contains(out.Log, "probe_hook") {
		t.Errorf("журнал не называет отказавший хук; получено: %s", out.Log)
	}
}
