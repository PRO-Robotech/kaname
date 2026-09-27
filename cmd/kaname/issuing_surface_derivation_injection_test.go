// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// issuing_surface_derivation_injection_test.go — способность гейта
// `TestIssuingSurfaceAuthIsDerivedFromItsMountedHandler` упасть и смолчать,
// доказанная на синтетике (задача PRO-Robotech/kaname#423, опыт 423F2).
//
// Дефекты — каждая форма, которой объявление расходится с монтажом: флаг рядом
// с монтажом (форма до починки; её снятая строка и была опытом 423F2),
// производитель от ДРУГОГО обработчика, постоянное значение, флаговая форма
// где угодно вне производителя. Близнец — выведение от того же обработчика, в
// том числе через переприсваивание и под псевдонимами импортов. Пустой обход и
// потерянный монтаж — не «находок 0», а отказ предпосылки.

import (
	"strings"
	"testing"
)

// issuingRootSource — композиционный корень синтетики: монтаж церемонии на
// mux, переприсваивание в обработчик поверхности и её объявление с осью auth.
func issuingRootSource(auth string, extra string) string {
	return `package main

import (
	"net/http"

	"github.com/PRO-Robotech/corelib/servicecontract"
	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
)

func serve(c *ceremony) error {
	var registryTokenHandler http.Handler
	ceremonyMounted := false
	mux := http.NewServeMux()
	if c != nil {
		ceremonyMounted = true
		mux.Handle(ceremonyhttp.AuthorizePath, c.Authorize)
		mux.Handle(ceremonyhttp.DiscoveryPath, c.Discovery)
	}
	registryTokenHandler = mux
	_ = ceremonyMounted
	_, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "выдача",
		Handler: registryTokenHandler,
		Auth:    ` + auth + `,
	})
	` + extra + `
	return err
}
`
}

const issuingProducerSource = `package main

import "net/http"

func issuingSurfaceAuthOf(h http.Handler) axis { return issuingSurfaceAuth(h != nil) }
`

func judgeSynthetic(t *testing.T, root string) (issuingDerivationCensus, []string, error) {
	t.Helper()
	return judgeIssuingSurfaceDerivation(map[string]string{
		"serve.go":           root,
		"issuing_surface.go": issuingProducerSource,
		"serve_test.go":      "package main\n\nfunc x() { issuingSurfaceAuth(true) }\n",
	})
}

func TestIssuingSurfaceDerivationInjection_LawfulDerivationIsSilent(t *testing.T) {
	for _, form := range []struct{ name, src string }{
		{"от переприсвоенного обработчика", issuingRootSource("issuingSurfaceAuthOf(registryTokenHandler)", "")},
		{"от самого mux", strings.Replace(issuingRootSource("issuingSurfaceAuthOf(mux)", ""),
			"Handler: registryTokenHandler,", "Handler: mux,", 1)},
		{"под псевдонимами импортов", strings.NewReplacer(
			`"github.com/PRO-Robotech/corelib/servicecontract"`, `sc "github.com/PRO-Robotech/corelib/servicecontract"`,
			`"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"`, `ch "github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"`,
			"servicecontract.Surface", "sc.Surface", "ceremonyhttp.", "ch.",
		).Replace(issuingRootSource("issuingSurfaceAuthOf(registryTokenHandler)", ""))},
	} {
		t.Run(form.name, func(t *testing.T) {
			c, findings, err := judgeSynthetic(t, form.src)
			if err != nil {
				t.Fatalf("законная форма — отказ обхода: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("законная форма дала находки:\n%s", strings.Join(findings, "\n"))
			}
			if c.CeremonySurfaces != 1 || c.CeremonyMounts != 2 {
				t.Fatalf("законная форма прочитана не вся: %s", c.Summary())
			}
		})
	}
}

func TestIssuingSurfaceDerivationInjection_EveryDivergenceIsFound(t *testing.T) {
	for _, form := range []struct{ name, src, want string }{
		{"423F2: флаг рядом с монтажом (форма до починки)",
			issuingRootSource("issuingSurfaceAuth(ceremonyMounted)", ""), "флаговой формой issuingSurfaceAuth(ceremonyMounted)"},
		{"производитель от другого обработчика",
			issuingRootSource("issuingSurfaceAuthOf(nil)", ""), "выведено из nil"},
		{"постоянное значение",
			issuingRootSource(`servicecontract.Value[servicecontract.SurfaceAuthMech]("два вида")`, ""), "не выводит её из обработчика"},
		{"флаговая форма в стороне от объявления",
			issuingRootSource("issuingSurfaceAuthOf(registryTokenHandler)", "_ = issuingSurfaceAuth(true)"), "флаговой формой issuingSurfaceAuth(true)"},
	} {
		t.Run(form.name, func(t *testing.T) {
			_, findings, err := judgeSynthetic(t, form.src)
			if err != nil {
				t.Fatalf("дефект — отказ обхода, а не находка: %v", err)
			}
			joined := strings.Join(findings, "\n")
			if !strings.Contains(joined, form.want) {
				t.Fatalf("расхождение объявления с монтажом не найдено (ждали %q):\n%s", form.want, joined)
			}
			if !strings.Contains(joined, "serve.go:") {
				t.Fatalf("находка без координаты:\n%s", joined)
			}
		})
	}
}

func TestIssuingSurfaceDerivationInjection_EmptyWalkAndLostMountAreNotGreen(t *testing.T) {
	if _, _, err := judgeIssuingSurfaceDerivation(map[string]string{"serve_test.go": "package main\n"}); err == nil {
		t.Fatalf("обход без прод-файлов не отказал — «находок 0» неотличимо от «ничего не прочитано»")
	}
	noMount := strings.NewReplacer(
		"mux.Handle(ceremonyhttp.AuthorizePath, c.Authorize)", "",
		"mux.Handle(ceremonyhttp.DiscoveryPath, c.Discovery)", "_ = ceremonyhttp.AuthorizePath",
	).Replace(issuingRootSource("issuingSurfaceAuthOf(registryTokenHandler)", ""))
	_, findings, err := judgeSynthetic(t, noMount)
	if err != nil {
		t.Fatalf("потерянный монтаж — отказ обхода, а не находка предпосылки: %v", err)
	}
	if !strings.Contains(strings.Join(findings, "\n"), "предпосылка не выполнена") {
		t.Fatalf("потерянный монтаж церемонии прошёл молча: %v", findings)
	}
}
