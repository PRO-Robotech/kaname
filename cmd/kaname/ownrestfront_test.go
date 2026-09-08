// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/servicecontract"
)

// restFrontUp — объявление поднятого фронта под транспортом. Помощник, а не
// литерал по месту: тот же вход подаётся нескольким пробам, и разъехавшиеся
// копии читались бы как осознанная разница, которой нет.
func restFrontUp() ownRESTFront {
	return ownRESTFront{addr: ":9098", tls: &tls.Config{MinVersion: tls.VersionTLS12}}
}

// TestOwnRESTFrontAxis_ThreeStatesAreDistinguishable — у оси три состояния, и
// каждое обязано быть отличимо от двух других.
//
// Отрицательная сторона здесь несущая: «фронта нет» и «фронт открытым текстом»
// схлопнуты в одно значение разрешали бы открытый текст молчанием, а ровно от
// этого ось и заведена.
func TestOwnRESTFrontAxis_ThreeStatesAreDistinguishable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		front ownRESTFront
		want  string
	}{
		{"поднят под транспортом", restFrontUp(), observability.OwnRESTFrontTLS},
		{"поднят открытым текстом", ownRESTFront{addr: ":9098"}, observability.OwnRESTFrontPlaintext},
		{"адрес не объявлен профилем", ownRESTFront{}, observability.OwnRESTFrontNotRaised},
		{
			// Транспорт объявлен, а адреса нет: защищать нечего, потому что
			// поверхности нет. Слить это с «поднят» значило бы отчитываться о
			// защите того, чего не существует.
			"транспорт без адреса — всё равно не поднят",
			ownRESTFront{tls: &tls.Config{MinVersion: tls.VersionTLS12}},
			observability.OwnRESTFrontNotRaised,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := observability.OwnRESTFrontFrom(tc.front); got != tc.want {
				t.Fatalf("величина оси = %q, ждали %q", got, tc.want)
			}
		})
	}
}

// TestOwnRESTFrontMatchesTheSurfaceDescriptor — объявление и профиль поверхности
// отвечают на два вопроса ОДИНАКОВО.
//
// Проба существует потому, что величину оси и подъём фронта читают РАЗНЫЕ
// потребители: самоотчёт берёт её у объявления, а поверхность поднимается по
// дескриптору. Пока оба выводятся из одного значения, разойтись им нечем — но
// «нечем» обязано проверяться, а не подразумеваться: дескриптор живёт в чужом
// модуле и волен сменить семантику, и тогда самоотчёт начнёт описывать не ту
// посадку, которую процесс принял.
func TestOwnRESTFrontMatchesTheSurfaceDescriptor(t *testing.T) {
	mode, err := servicecontract.ParseMode("production")
	if err != nil {
		t.Fatalf("посадка не разобрана: %v", err)
	}
	handler := http.NewServeMux()

	for _, tc := range []struct {
		name  string
		front ownRESTFront
	}{
		{"поднят под транспортом", restFrontUp()},
		{"поднят открытым текстом", ownRESTFront{addr: ":9098"}},
		{"адрес не объявлен профилем", ownRESTFront{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Дескриптор собирается ровно так, как его собирает композиционный
			// корень, — из ТОГО ЖЕ объявления.
			var h http.Handler
			if tc.front.Enabled() {
				h = handler
			}
			desc, derr := iamHTTPSurface(servicecontract.Surface{
				Name:    "собственный REST-фронт (проба согласия)",
				Mode:    mode,
				Addr:    addrAxis(tc.front.addr, "профиль поверхность не объявил"),
				Handler: h,
				Reach:   servicecontract.ReachClusterInternal,
				Auth: servicecontract.Value[servicecontract.SurfaceAuthMech](
					"цепочка собственного слушателя"),
				TLS: tc.front.tls,
			})
			if derr != nil {
				t.Fatalf("профиль поверхности не принят: %v", derr)
			}
			if got, want := tc.front.Enabled(), desc.Enabled(); got != want {
				t.Fatalf("Enabled: объявление=%v, дескриптор=%v", got, want)
			}
			if got, want := tc.front.UnderTLS(), desc.UnderTLS(); got != want {
				t.Fatalf("UnderTLS: объявление=%v, дескриптор=%v", got, want)
			}
			// И, как следствие, совпадает величина оси.
			if got, want := observability.OwnRESTFrontFrom(tc.front),
				observability.OwnRESTFrontFrom(desc); got != want {
				t.Fatalf("величина оси: объявление=%q, дескриптор=%q", got, want)
			}
		})
	}
}
