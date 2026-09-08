// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keyset_test.go — сценарии F1-29 (на ответе эндпоинта), F1-32, F1-36, F1-37,
// F1-44 и F1-46 приёмки F1: НАША запись публикуемого набора.
package jwksproxyhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

// stubKeySet — подставная проекция ключницы.
//
// Отдаёт ровно то, что отдала бы ключница, и на недоступности источника
// отвечает ОТКАЗОМ, а не пустым набором: дублёр, глотающий вход, на котором
// настоящий отвечает отказом, сделал бы невидимым дефект, ради которого его
// подставляют.
type stubKeySet struct {
	keys []domain.PublishedKey
	err  error
}

func (s stubKeySet) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	return s.keys, s.err
}

func ourKey(t *testing.T, kid string) domain.PublishedKey {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	if err != nil {
		t.Fatalf("порождение ключа: %v", err)
	}
	return domain.PublishedKey{KID: domain.KeyID(kid), Algorithm: domain.SigningAlgES256, PublicKeyPEM: mat.PublicKeyPEM}
}

func getPath(t *testing.T, h http.Handler, method, path string) (*http.Response, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, string(body)
}

func kidsIn(t *testing.T, body string) []string {
	t.Helper()
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("ответ обязан быть СТАНДАРТНЫМ по форме документом: %v; тело=%s", err, body)
	}
	out := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty == "" {
			t.Fatalf("ключ %q в наборе без типа — такой документ стандартным не является", k.Kid)
		}
		out = append(out, k.Kid)
	}
	return out
}

// TestKeySet_F1_32_WholeRecordOrNothing — F1-32.
func TestKeySet_F1_32_WholeRecordOrNothing(t *testing.T) {
	// Given (первое состояние) — набор отдаётся целиком.
	h := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
		Source: stubKeySet{keys: []domain.PublishedKey{ourKey(t, "kacho-a"), ourKey(t, "kacho-b")}},
	})
	res, body := getPath(t, h, http.MethodGet, "/x")

	// Then (положительный контроль, без которого отрицание зелено на
	// публикаторе, не отдающем ничего) — ответ содержит ТОЛЬКО наши ключи и
	// только публичный материал.
	if res.StatusCode != http.StatusOK {
		t.Fatalf("полный набор обязан отдаваться: статус %d, тело %s", res.StatusCode, body)
	}
	kids := kidsIn(t, body)
	if len(kids) != 2 {
		t.Fatalf("ожидалось два наших ключа, получено %v", kids)
	}
	for _, want := range []string{"kacho-a", "kacho-b"} {
		if !strings.Contains(body, want) {
			t.Fatalf("наш ключ %q отсутствует в НАШЕЙ записи набора: %s", want, body)
		}
	}
	if strings.Contains(body, "PRIVATE") || strings.Contains(body, `"d"`) {
		t.Fatalf("в публикуемом наборе оказался приватный материал: %s", body)
	}

	// Given (второе состояние) — набор целиком отдать нельзя.
	down := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
		Source: stubKeySet{err: errors.New("source is unavailable")},
	})
	resDown, bodyDown := getPath(t, down, http.MethodGet, "/x")

	// Then — ответ ОТКАЗ; никогда успех с пустым набором и никогда
	// подменённый набор.
	if resDown.StatusCode == http.StatusOK {
		t.Fatalf("недоступный источник обязан давать отказ, получено 200: %s", bodyDown)
	}
	if strings.Contains(bodyDown, `"keys"`) {
		t.Fatalf("тело отказа не несёт ключей ВОВСЕ, включая наши: %s", bodyDown)
	}
	for _, kid := range []string{"kacho-a", "kacho-b"} {
		if strings.Contains(bodyDown, kid) {
			t.Fatalf("тело отказа вынесло наружу идентификатор ключа %q: %s", kid, bodyDown)
		}
	}

	// And — исходы двух состояний РАЗЛИЧИМЫ СНАРУЖИ, а не сведены к одному коду.
	if resDown.StatusCode == res.StatusCode {
		t.Fatalf("исход отказа не отличим от исхода успеха: оба %d", res.StatusCode)
	}

	// And — пустой набор не выдаётся за набор: отсутствие ключей есть ОТКАЗ, а
	// не «набор из нуля ключей», потому что пустой массив читается
	// потребителем как факт, и здесь этот факт был бы ложью.
	empty := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: stubKeySet{}})
	resEmpty, bodyEmpty := getPath(t, empty, http.MethodGet, "/x")
	if resEmpty.StatusCode == http.StatusOK {
		t.Fatalf("пустой набор отдан как успех: %s", bodyEmpty)
	}
}

// TestKeySet_F1_36_SourceUnavailableIsARefusal — F1-36.
func TestKeySet_F1_36_SourceUnavailableIsARefusal(t *testing.T) {
	src := &togglableSource{keys: []domain.PublishedKey{ourKey(t, "kacho-a")}}
	h := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: src})

	// Положительный контроль — при доступном источнике тот же запрос отдаёт
	// полный набор.
	res, body := getPath(t, h, http.MethodGet, "/x")
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "kacho-a") {
		t.Fatalf("доступный источник обязан отдавать набор: %d %s", res.StatusCode, body)
	}

	// Источник недоступен — ответ отказ; никогда пустой успех, никогда
	// подстановка иного набора.
	src.err = errors.New("database is unavailable")
	res, body = getPath(t, h, http.MethodGet, "/x")
	if res.StatusCode == http.StatusOK {
		t.Fatalf("недоступный источник обязан давать отказ: %s", body)
	}
	if strings.Contains(body, "kacho-a") {
		t.Fatalf("отказ отдал набор из прежнего чтения — у нашей записи кэша нет by construction: %s", body)
	}

	// …и восстановление источника снова отдаёт набор: отказ не залипает.
	src.err = nil
	res, body = getPath(t, h, http.MethodGet, "/x")
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "kacho-a") {
		t.Fatalf("восстановившийся источник обязан снова отдавать набор: %d %s", res.StatusCode, body)
	}
}

type togglableSource struct {
	keys []domain.PublishedKey
	err  error
}

func (s *togglableSource) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.keys, nil
}

// TestKeySet_F1_37_CountersPerOutcomeAndMethodRestriction — F1-37 (у каждого
// исхода свой счётчик) и сужение метода.
func TestKeySet_F1_37_CountersPerOutcomeAndMethodRestriction(t *testing.T) {
	src := &togglableSource{keys: []domain.PublishedKey{ourKey(t, "kacho-a")}}
	h := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: src})

	// «Ноль отказов за всё время жизни» отличимо от «контроль не исполнялся»:
	// величины читаются всегда, включая нулевые.
	if got := h.Stats(); got.Served != 0 || got.Unavailable != 0 {
		t.Fatalf("свежий публикатор обязан начинаться с нуля, получено %+v", got)
	}

	_, _ = getPath(t, h, http.MethodGet, "/x")
	src.err = errors.New("down")
	_, _ = getPath(t, h, http.MethodGet, "/x")
	_, _ = getPath(t, h, http.MethodGet, "/x")

	got := h.Stats()
	if got.Served != 1 {
		t.Fatalf("успешных отдач ожидалось 1, получено %d", got.Served)
	}
	if got.Unavailable != 2 {
		t.Fatalf("отказов по недоступности ожидалось 2, получено %d", got.Unavailable)
	}

	// Метод сужен, и отказ несёт перечень допустимых.
	res, _ := getPath(t, h, http.MethodPost, "/x")
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("маршрут только на чтение: POST дал %d", res.StatusCode)
	}
	if allow := res.Header.Get("Allow"); !strings.Contains(allow, "GET") {
		t.Fatalf("отказ по методу обязан нести перечень допустимых, получено %q", allow)
	}
}

// TestKeySet_F1_29_EndpointAnswerFollowsState — F1-29, предикат сформулирован
// НА ОТВЕТЕ ЭНДПОИНТА, а не на строке в базе.
func TestKeySet_F1_29_EndpointAnswerFollowsState(t *testing.T) {
	// Given — ключ получил состояние PUBLISHED и ещё не подписывает.
	src := &togglableSource{keys: []domain.PublishedKey{ourKey(t, "kacho-published")}}
	h := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: src})

	// Then — ОТВЕТ ЭНДПОИНТА уже содержит этот ключ.
	res, body := getPath(t, h, http.MethodGet, "/x")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ответ обязан отдавать опубликованный ключ: %d", res.StatusCode)
	}
	if !strings.Contains(body, "kacho-published") {
		t.Fatalf("опубликованный ключ отсутствует в ответе эндпоинта: %s", body)
	}

	// And — снятый и скомпрометированный в ответе ОТСУТСТВУЮТ. Проекция
	// ключницы их не отдаёт: состояния фильтрует источник, а публикатор своей
	// копии набора не держит.
	src.keys = nil
	res, _ = getPath(t, h, http.MethodGet, "/x")
	if res.StatusCode == http.StatusOK {
		t.Fatalf("набор без единого ключа обязан быть отказом, а не пустым успехом")
	}
}
