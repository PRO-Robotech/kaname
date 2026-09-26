// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// issuing_surface_test.go — объявление аутентификации внешней поверхности
// выдачи называет КАЖДЫЙ способ, которым на ней аутентифицируется запрос, и
// исключение без аутентификации — с причиной (задача PRO-Robotech/kaname#423,
// возврат ревью безопасности сборки 425).
//
// Церемония монтирует на эту поверхность эндпоинт авторизации (его запрос
// аутентифицирует сессия нашего входа) и метаданные обнаружения (публичное
// чтение без аутентификации). Объявление, которое о них молчит, — самоотчёт
// процесса и дескриптор посадки без пути без аутентификации, при том что путь
// смонтирован. Без церемонии их в объявлении нет: объявление говорит о том, что
// смонтировано.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

func TestIssuingSurfaceAuthNamesEveryMountedPresentation(t *testing.T) {
	mounted, ok := issuingSurfaceAuth(true).Get()
	if !ok {
		t.Fatalf("объявление аутентификации поверхности выдачи не несёт значения")
	}
	for _, want := range []string{
		ceremonyhttp.AuthorizePath, loginlanehttp.CookieSession, // путь авторизации и чем он аутентифицирован
		ceremonyhttp.DiscoveryPath, "без аутентификации", "RFC 8414", // исключение и его причина
	} {
		if !strings.Contains(string(mounted), want) {
			t.Errorf("объявление поверхности с церемонией не называет %q: %q", want, mounted)
		}
	}

	bare, ok := issuingSurfaceAuth(false).Get()
	if !ok {
		t.Fatalf("близнец: объявление без церемонии не несёт значения")
	}
	for _, absent := range []string{ceremonyhttp.AuthorizePath, ceremonyhttp.DiscoveryPath} {
		if strings.Contains(string(bare), absent) {
			t.Errorf("близнец: объявление поверхности без церемонии называет несмонтированный %q", absent)
		}
	}
	if !strings.Contains(string(bare), "docker-токена") {
		t.Errorf("близнец: объявление без церемонии потеряло способы машинных полос: %q", bare)
	}
}

// issuingAuthProducer — то, что проверяется: производитель объявления по
// обработчику поверхности. Параметром, а не прямым вызовом: тем же предикатом
// инъекция подаёт производителя, не читающего обработчик, и требует красного.
type issuingAuthProducer func(http.Handler) servicecontract.Axis[servicecontract.SurfaceAuthMech]

// opaqueHandler — обработчик, который маршрута назвать не умеет.
type opaqueHandler struct{}

func (opaqueHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

// checkIssuingAuthFollowsTheMount — сам предикат: объявление меняется ВМЕСТЕ с
// тем, что смонтировано, и не объявляет того, чего не прочло.
func checkIssuingAuthFollowsTheMount(produce issuingAuthProducer) error {
	noop := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	muxWith := func(paths ...string) *http.ServeMux {
		mux := http.NewServeMux()
		mux.Handle("/iam/token", noop)
		for _, p := range paths {
			mux.Handle(p, noop)
		}
		return mux
	}

	mounted, ok := produce(muxWith(ceremonyhttp.AuthorizePath, ceremonyhttp.DiscoveryPath)).Get()
	if !ok {
		return fmt.Errorf("церемония смонтирована, а объявление не несёт значения")
	}
	for _, want := range []string{ceremonyhttp.AuthorizePath, loginlanehttp.CookieSession, ceremonyhttp.DiscoveryPath, "RFC 8414"} {
		if !strings.Contains(string(mounted), want) {
			return fmt.Errorf("церемония смонтирована, а объявление не называет %q: %q", want, mounted)
		}
	}
	for name, h := range map[string]http.Handler{"маршрутизатор без церемонии": muxWith(), "обработчика нет": nil} {
		bare, ok := produce(h).Get()
		if !ok {
			return fmt.Errorf("%s: объявление не несёт значения", name)
		}
		if strings.Contains(string(bare), ceremonyhttp.AuthorizePath) || strings.Contains(string(bare), ceremonyhttp.DiscoveryPath) {
			return fmt.Errorf("%s: объявление называет несмонтированные пути церемонии: %q", name, bare)
		}
	}
	for name, h := range map[string]http.Handler{
		"смонтирована половина церемонии":  muxWith(ceremonyhttp.AuthorizePath),
		"обработчик не называет маршрутов": opaqueHandler{},
	} {
		if a := produce(h); a.Declared() {
			return fmt.Errorf("%s: объявление выдано о том, чего производитель не прочёл либо что невыразимо: %v", name, a)
		}
	}
	return nil
}

// TestIssuingSurfaceAuthFollowsTheMountedHandler — предикат на действующем
// производителе; провязку производителя с поверхностью держит гейт
// `TestIssuingSurfaceAuthIsDerivedFromItsMountedHandler`.
func TestIssuingSurfaceAuthFollowsTheMountedHandler(t *testing.T) {
	if err := checkIssuingAuthFollowsTheMount(issuingSurfaceAuthOf); err != nil {
		t.Fatalf("%v", err)
	}
}

// TestIssuingSurfaceAuthInjection_ProducerThatIgnoresTheMountIsFound —
// способность предиката упасть: производитель, не читающий обработчик (форма
// опыта 423F2 — объявление прежнее при смонтированной церемонии), и
// производитель, объявляющий непрочитанное, — красные.
func TestIssuingSurfaceAuthInjection_ProducerThatIgnoresTheMountIsFound(t *testing.T) {
	for name, produce := range map[string]issuingAuthProducer{
		"объявление всегда прежнее": func(http.Handler) servicecontract.Axis[servicecontract.SurfaceAuthMech] {
			return issuingSurfaceAuth(false)
		},
		"непрочитанное объявлено «без церемонии»": func(h http.Handler) servicecontract.Axis[servicecontract.SurfaceAuthMech] {
			if a := issuingSurfaceAuthOf(h); a.Declared() {
				return a
			}
			return issuingSurfaceAuth(false)
		},
	} {
		if err := checkIssuingAuthFollowsTheMount(produce); err == nil {
			t.Errorf("%s: предикат не покраснел", name)
		}
	}
}
