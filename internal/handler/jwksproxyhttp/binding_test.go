// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_test.go — F1-44 (замок «только внутри» на КАЖДОМ пути публикации) и
// F1-46 (привязка «издатель → путь» на стороне публикатора, включая стража
// старта).
package jwksproxyhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
)

// twoRecordBinding — привязка публикатора с ДВУМЯ записями: наша (проекция
// ключницы) и зеркало прежнего издателя, сохраняемое до F4.
func twoRecordBinding(t *testing.T) jwksproxyhttp.Binding {
	t.Helper()
	ours := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
		Source: stubKeySet{keys: []domain.PublishedKey{ourKey(t, "kacho-a")}},
	})
	mirror := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{UpstreamURL: "https://provider.invalid/jwks"})
	b, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{
		{Issuer: "https://kaname.kacho.local", Path: "/.well-known/kaname/jwks.json", Handler: ours},
		{Issuer: "https://provider.kacho.local", Path: jwksproxyhttp.WellKnownJWKSPath, Handler: mirror},
	})
	if err != nil {
		t.Fatalf("привязка из двух законных записей обязана строиться: %v", err)
	}
	return b
}

// TestBinding_F1_44_EveryPublicationPathIsInternalOnly — F1-44.
//
// Обе стороны утверждаются ОДНОЙ пробой: порознь «404 снаружи» зелено на mux,
// где нет вообще ничего, а «резолвится внутри» ничего не говорит о внешней
// поверхности.
func TestBinding_F1_44_EveryPublicationPathIsInternalOnly(t *testing.T) {
	b := twoRecordBinding(t)

	internal, err := jwksproxyhttp.NewMux(b)
	if err != nil {
		t.Fatalf("внутренний mux обязан строиться на законной привязке: %v", err)
	}
	external := registrytokenhttp.NewMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	// Перечень проверяемых путей ВЫВОДИТСЯ из привязки, а не выписан в пробе:
	// выписанный разошёлся бы с ней молча при появлении третьей записи.
	paths := b.Paths()
	if len(paths) != 2 {
		t.Fatalf("привязка обязана давать перечень путей, получено %v", paths)
	}

	for _, p := range paths {
		// Внешний отвечает 404 по КАЖДОМУ пути — маршрутов там нет (ban #6).
		res := httptest.NewRecorder()
		external.ServeHTTP(res, httptest.NewRequest(http.MethodGet, p, nil))
		if res.Code != http.StatusNotFound {
			t.Fatalf("путь публикации %q резолвится на ВНЕШНЕЙ поверхности (код %d) — ban #6", p, res.Code)
		}

		// Внутренний РЕЗОЛВИТ каждый путь к своему обработчику.
		res = httptest.NewRecorder()
		internal.ServeHTTP(res, httptest.NewRequest(http.MethodGet, p, nil))
		if res.Code == http.StatusNotFound {
			t.Fatalf("путь публикации %q не резолвится на внутренней поверхности", p)
		}

		// Метод сужен на КАЖДОМ пути, и отказ несёт перечень допустимых.
		res = httptest.NewRecorder()
		internal.ServeHTTP(res, httptest.NewRequest(http.MethodPost, p, nil))
		if res.Code != http.StatusMethodNotAllowed {
			t.Fatalf("путь %q принимает POST (код %d) — маршрут обязан быть только на чтение", p, res.Code)
		}
		if allow := res.Header().Get("Allow"); !strings.Contains(allow, "GET") {
			t.Fatalf("путь %q: отказ по методу без перечня допустимых (%q)", p, allow)
		}
	}

	// Проба обязана ПАДАТЬ на ДОБАВЛЕННОЙ записи, чей путь зарегистрирован
	// снаружи, — иначе она утверждает о числе маршрутов, а не о свойстве
	// каждого. Проверяем это тем же предикатом на внешнем mux, которому такой
	// путь подмешан.
	leaky := registrytokenhttp.NewMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	leaky.Handle("/.well-known/kaname/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	res := httptest.NewRecorder()
	leaky.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/.well-known/kaname/jwks.json", nil))
	if res.Code == http.StatusNotFound {
		t.Fatalf("контроль инъекции сам неверен: путь, зарегистрированный снаружи, обязан резолвиться")
	}
}

// TestBinding_F1_46_RecordsAreDeclaredNotDerived — F1-46, сторона публикатора.
func TestBinding_F1_46_RecordsAreDeclaredNotDerived(t *testing.T) {
	b := twoRecordBinding(t)

	// Then — НАША запись содержит только наши ключи, чужих в ней нет.
	internal, err := jwksproxyhttp.NewMux(b)
	if err != nil {
		t.Fatalf("mux: %v", err)
	}
	res := httptest.NewRecorder()
	internal.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/.well-known/kaname/jwks.json", nil))
	body := res.Body.String()
	if !strings.Contains(body, "kacho-a") {
		t.Fatalf("наша запись обязана содержать наш ключ: %s", body)
	}

	// And — путь записи берётся ИЗ ОБЪЯВЛЕННОГО ПЕРЕЧНЯ: издатель ВНЕ перечня
	// не резолвится ни во что, а не превращается в адрес, выведенный из самого
	// издателя. Без этого утверждения реализация с производным путём проходит
	// все прочие, и половина про стража старта становится тождественно
	// истинной — «записи нет» не наступает ни при каком издателе.
	if _, ok := b.PathOf("https://outsider.example"); ok {
		t.Fatalf("издатель вне перечня резолвится в путь — путь ВЫВОДИТСЯ, а не объявлен")
	}
	// Положительный контроль: объявленный издатель резолвится.
	if p, ok := b.PathOf("https://kaname.kacho.local"); !ok || p != "/.well-known/kaname/jwks.json" {
		t.Fatalf("объявленный издатель обязан резолвиться в свой путь, получено %q/%v", p, ok)
	}

	// And — объявленный издатель есть НЕДОВЕРЕННЫЙ ВХОД: произвольная строка в
	// нём не попадает ни в путь, ни в исходящий адрес.
	for _, hostile := range []string{
		"../../../etc/passwd", "https://kaname.kacho.local/../x", "\x00", "<script>",
		"https://kaname.kacho.local\nX-Injected: 1", strings.Repeat("a", 4096),
	} {
		if p, ok := b.PathOf(hostile); ok {
			t.Fatalf("враждебный издатель %q резолвился в путь %q", hostile, p)
		}
	}
}

// TestBinding_F1_46_BootGuardRefusesIncompleteBinding — F1-46, страж старта.
func TestBinding_F1_46_BootGuardRefusesIncompleteBinding(t *testing.T) {
	ours := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: stubKeySet{}})

	cases := map[string][]jwksproxyhttp.Record{
		"издатель объявлен, записи источника нет": {
			{Issuer: "https://kaname.kacho.local", Path: "", Handler: ours},
		},
		"путь вырожден — одни разделители": {
			{Issuer: "https://kaname.kacho.local", Path: "///", Handler: ours},
		},
		"путь вырожден — пробелы": {
			{Issuer: "https://kaname.kacho.local", Path: "   ", Handler: ours},
		},
		"издатель пуст": {
			{Issuer: "", Path: "/a.json", Handler: ours},
		},
		"два издателя на один путь": {
			{Issuer: "https://a", Path: "/a.json", Handler: ours},
			{Issuer: "https://b", Path: "/a.json", Handler: ours},
		},
		"один издатель дважды": {
			{Issuer: "https://a", Path: "/a.json", Handler: ours},
			{Issuer: "https://a", Path: "/b.json", Handler: ours},
		},
		"запись без обработчика": {
			{Issuer: "https://a", Path: "/a.json"},
		},
		"привязка пуста": {},
	}
	for name, recs := range cases {
		if _, err := jwksproxyhttp.NewBinding(recs); err == nil {
			t.Fatalf("%s: привязка построилась — старт обязан отвергаться", name)
		}
	}

	// Положительный контроль на ОБЕИХ мощностях: с полной привязкой из одной и
	// из двух записей построение проходит.
	if _, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{
		{Issuer: "https://a", Path: "/a.json", Handler: ours},
	}); err != nil {
		t.Fatalf("привязка из одной законной записи обязана строиться: %v", err)
	}
	if _, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{
		{Issuer: "https://a", Path: "/a.json", Handler: ours},
		{Issuer: "https://b", Path: "/b.json", Handler: ours},
	}); err != nil {
		t.Fatalf("привязка из двух законных записей обязана строиться: %v", err)
	}
}

// TestBinding_F1_46_OneRecordFailingDoesNotCloseTheOther — §6.5: «целиком»
// относится к ЗАПИСИ. Недоступность одной записи не делает недоступной другую,
// иначе доступность прежнего провайдера стала бы условием проверки НАШИХ
// токенов — то есть усилила бы зависимость, ради снятия которой фаза делается.
func TestBinding_F1_46_OneRecordFailingDoesNotCloseTheOther(t *testing.T) {
	ours := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
		Source: stubKeySet{keys: []domain.PublishedKey{ourKey(t, "kacho-a")}},
	})
	brokenMirror := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
		Source: stubKeySet{err: errors.New("provider is unavailable")},
	})
	b, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{
		{Issuer: "https://kaname.kacho.local", Path: "/ours.json", Handler: ours},
		{Issuer: "https://provider", Path: "/mirror.json", Handler: brokenMirror},
	})
	if err != nil {
		t.Fatalf("привязка: %v", err)
	}
	mux, err := jwksproxyhttp.NewMux(b)
	if err != nil {
		t.Fatalf("mux: %v", err)
	}

	res := httptest.NewRecorder()
	mux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/mirror.json", nil))
	if res.Code == http.StatusOK {
		t.Fatalf("недоступная запись обязана отказывать")
	}
	res = httptest.NewRecorder()
	mux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/ours.json", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("наша запись закрылась вместе с чужой (код %d) — это усилило бы зависимость от прежнего провайдера", res.Code)
	}
	_ = context.Background()
}
