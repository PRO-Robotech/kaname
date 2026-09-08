// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_material_window_wiring_test.go — ОКНО ПЕРЕХОДА #1143 ДОЕЗЖАЕТ ДО ПОЛОСЫ.
//
// Ручка, объявленная и не провязанная, — мёртвый контроль: оператор считает,
// что принимает оба вида, а полоса отвергает прежний, и узнаёт он об этом от
// арендатора. Поэтому здесь утверждается ИСХОД, а не наличие поля в структуре.
//
// # Чем измеряется исход, если снаружи отказ ОДИН И ТОТ ЖЕ
//
// Наружу и закрытое, и открытое окно отвечают 401 с одним телом — иначе ручка
// стала бы оракулом посадки. Значит различать их обязан СЧЁТЧИК, и именно это
// делает его не украшением, а единственным наблюдаемым различием:
//
//	окно закрыто → исход key_material_refused;
//	окно открыто → полоса ушла к проверяющему, и «вид не принимается» не звучит.
//
// Пула здесь нет намеренно и это безопасно: предъявляется заведомо негодный
// материал, а проверяющий разбирает PEM ДО обращения к хранилищу — то есть до
// базы дело не доходит ни в одной из двух ветвей.
package registrytokenwire_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
)

type countingObserver struct{ seen map[string]int }

func (o *countingObserver) ObserveCredentialKind(outcome string) { o.seen[outcome]++ }

// keyMaterialLogin — вход в том виде, в каком его слал клиент до #1143.
const keyMaterialLogin = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key-1143\n-----END PRIVATE KEY-----"

func dockerLogin(t *testing.T, h http.Handler, user, pass string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, registrytokenhttp.TokenPath+"?service=registry.probe.local", nil)
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func buildLane(t *testing.T, until time.Time, obs *countingObserver) http.Handler {
	t.Helper()
	mux, err := registrytokenwire.Build(nil, registrytokenwire.BuildConfig{
		Realm:                  "https://api.kacho.local/iam/token",
		Service:                "registry.probe.local",
		KeyMaterialWindowUntil: until,
		CredentialKindObserver: obs,
	})
	if err != nil {
		t.Fatalf("сборка полосы: %v", err)
	}
	return mux
}

// Окно ЗАКРЫТО (умолчание) — прежний вид отвергается как негодный ВИД, и это
// считается.
func TestKeyMaterialWindow_ClosedByDefaultReachesTheLaneAndIsCounted(t *testing.T) {
	obs := &countingObserver{seen: map[string]int{}}
	h := buildLane(t, time.Time{}, obs)

	if code := dockerLogin(t, h, "soc_0000000000001143k", keyMaterialLogin); code != http.StatusUnauthorized {
		t.Fatalf("вход прежним видом при закрытом окне обязан давать 401, получено %d", code)
	}
	if got := obs.seen[registrytokenuc.OutcomeKeyMaterialRefused]; got != 1 {
		t.Fatalf("счётчик обязан быть ПРОВЯЗАН и посчитать отказ прежнему виду: %d "+
			"(непровязанный счётчик оставляет оператора без единственного наблюдаемого "+
			"различия между закрытым и открытым окном)", got)
	}
}

// Окно ОТКРЫТО — то же самое обращение уходит ПРОВЕРЯЮЩЕМУ, а не в отказ по
// виду. Наружу по-прежнему 401 (материал заведомо негоден), и это утверждается
// тут же: различимость снаружи была бы оракулом посадки.
func TestKeyMaterialWindow_DeclaredInstantReachesTheLane(t *testing.T) {
	obs := &countingObserver{seen: map[string]int{}}
	h := buildLane(t, time.Now().Add(time.Hour), obs)

	if code := dockerLogin(t, h, "soc_0000000000001143k", keyMaterialLogin); code != http.StatusUnauthorized {
		t.Fatalf("негодный материал обязан давать 401 и при открытом окне, получено %d", code)
	}
	if got := obs.seen[registrytokenuc.OutcomeKeyMaterialRefused]; got != 0 {
		t.Fatalf("при ОБЪЯВЛЕННОМ окне отказа по ВИДУ быть не должно — значит ручка "+
			"до полосы не доехала и окно существует только в настройке: %d", got)
	}
}

// Окно ИСТЕКЛО — сборка его не открывает. Проба стоит отдельно от «закрыто по
// умолчанию»: непровязанная ручка зеленила бы первую и эту разом, а вот вместе
// с проверкой выше они разделяют «ручки нет» и «ручка есть, но истекла».
func TestKeyMaterialWindow_ElapsedInstantDoesNotOpenTheLane(t *testing.T) {
	obs := &countingObserver{seen: map[string]int{}}
	h := buildLane(t, time.Now().Add(-time.Minute), obs)

	if code := dockerLogin(t, h, "soc_0000000000001143k", keyMaterialLogin); code != http.StatusUnauthorized {
		t.Fatalf("истёкшее окно обязано давать 401, получено %d", code)
	}
	if got := obs.seen[registrytokenuc.OutcomeKeyMaterialRefused]; got != 1 {
		t.Fatalf("истёкшее окно обязано отвергать прежний вид и считать это: %d", got)
	}
}
