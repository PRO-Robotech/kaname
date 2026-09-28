// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// hooks_mux_audit_drop_row_test.go — ряд потерь журнала хуков держится ОТ КОРНЯ
// (kaname#436, возврат check-verifier по #389, находка 1).
//
// # Признак
//
// Проба сборки полос (`issuance_hooks_audit_drop_test.go`) судит шпиона, поданного
// в `buildIssuanceHooks`, а не ряд реестра. Корень, подающий сборке пустой
// приёмник или приёмник с половиной видов, ту пробу проходит, а витрина молчит о
// потерях ровно так, как молчит исправная полоса, не потерявшая ничего.
//
// # Как судится
//
// `buildHooksMux` собирается с НАСТОЯЩИМ реестром величин, реестр скрейпится его же
// обработчиком (`Registry.Handler`, тот, что отдаёт `/metrics`), и по каждому виду
// из набора, объявленного пакетом полосы (`AuditEventTypes`), судится клетка ряда
// `kaname_authn_hook_audit_dropped_total`: она есть и равна нулю. Вид без клетки
// назван по имени; клетка вида, которого пакет не объявлял, — тоже находка.
//
// # Чего эта проба НЕ держит
//
// Что приёмник, поданный полосам, — тот же, что завёл клетки: корень, заведший
// клетки одним вызовом и подавший полосам другой приёмник, её прошёл бы. Это держит
// `TestHooksMuxCountsARefusedAuditRecordOnTheRegistryRow`
// (`hooks_mux_audit_drop_row_integration_test.go`): потеря, произведённая базой,
// двигает клетку реестра через тот же корень.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// auditDropRowLineRE — строка клетки ряда в текстовом формате витрины: имя, набор
// меток, значение и необязательная отметка времени.
var auditDropRowLineRE = regexp.MustCompile(
	`^` + regexp.QuoteMeta(metrics.AuthnHookAuditDropsMetric) + `\{([^}]*)\} (\S+)(?: -?[0-9]+)?$`)

// auditDropRowLabelRE — единственная метка ряда.
var auditDropRowLabelRE = regexp.MustCompile(`^event_type="([^"\\]*)"$`)

// parseAuditDropRow — клетки ряда потерь из текста витрины: вид → значение.
//
// Строка, начинающаяся именем ряда и не разобранная, — ОТКАЗ, а не пропуск:
// разборщик, молча отбросивший незнакомую форму, дал бы «клетки нет» там, где она
// есть в другой записи.
func parseAuditDropRow(exposition string) (map[string]float64, error) {
	cells := map[string]float64{}
	for _, line := range strings.Split(exposition, "\n") {
		if !strings.HasPrefix(line, metrics.AuthnHookAuditDropsMetric) {
			continue
		}
		m := auditDropRowLineRE.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("строка ряда %s не разобрана: %q", metrics.AuthnHookAuditDropsMetric, line)
		}
		l := auditDropRowLabelRE.FindStringSubmatch(m[1])
		if l == nil {
			return nil, fmt.Errorf("метки клетки ряда не сводятся к одной event_type: %q", line)
		}
		v, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			return nil, fmt.Errorf("значение клетки не число: %q: %w", line, err)
		}
		if _, dup := cells[l[1]]; dup {
			return nil, fmt.Errorf("клетка вида %q на витрине дважды", l[1])
		}
		cells[l[1]] = v
	}
	return cells, nil
}

// scrapeAuditDropRow — скрейп реестра его собственным обработчиком витрины.
func scrapeAuditDropRow(t *testing.T, reg *metrics.Registry) map[string]float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("витрина реестра ответила %d: %s", rec.Code, rec.Body.String())
	}
	cells, err := parseAuditDropRow(rec.Body.String())
	if err != nil {
		t.Fatalf("разбор витрины: %v", err)
	}
	return cells
}

// auditDropRowFaults — клетки ряда против объявленного набора видов. Пусто —
// ряд сходится: клетка каждого вида есть и равна нулю, чужих клеток нет.
func auditDropRowFaults(declared []string, cells map[string]float64) []string {
	var out []string
	isDeclared := map[string]bool{}
	for _, e := range declared {
		isDeclared[e] = true
		v, ok := cells[e]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("вид %q: клетки ряда нет — «потерь не было» по нему невыразимо", e))
		case v != 0:
			out = append(out, fmt.Sprintf("вид %q: клетка заведена не нулём (%v) без единой потери", e, v))
		}
	}
	var foreign []string
	for e := range cells {
		if !isDeclared[e] {
			foreign = append(foreign, e)
		}
	}
	sort.Strings(foreign)
	for _, e := range foreign {
		out = append(out, fmt.Sprintf("клетка вида %q, которого пакет полосы не объявлял", e))
	}
	return out
}

// TestHooksMuxSeedsTheAuditDropRowForEveryDeclaredKind — корень, собравший полосу
// хуков, заводит на реестре клетку ряда потерь журнала по каждому объявленному
// виду, и каждая равна нулю.
func TestHooksMuxSeedsTheAuditDropRowForEveryDeclaredKind(t *testing.T) {
	declared := handlerinternal.AuditEventTypes()
	if len(declared) == 0 {
		t.Fatal("предпосылка: пакет полосы не объявил ни одного вида записи журнала — судить нечего")
	}
	cfg := roadCfg(config.IdentityProviderExternal, "9097")
	reg := metrics.NewRegistry()
	h, err := buildHooksMux(nil, nil, nil, nil, reg, cfg, quietLogger())
	if err != nil {
		t.Fatalf("предпосылка: корень отказал в сборке полосы хуков (%v) — ряд судить не у чего", err)
	}
	if h == nil {
		t.Fatal("предпосылка: корень не собрал полосу хуков (обработчика нет) — ряд судить не у чего")
	}
	cells := scrapeAuditDropRow(t, reg)
	faults := auditDropRowFaults(declared, cells)
	t.Logf("перепись: видов объявлено %d · клеток ряда %s на витрине %d · расхождений %d",
		len(declared), metrics.AuthnHookAuditDropsMetric, len(cells), len(faults))
	for _, f := range faults {
		t.Errorf("ряд потерь журнала хуков, собранный корнем: %s", f)
	}
}

// TestAuditDropRowJudgeRedsOnTheRootDefectsItIsFor — судья ряда краснеет на обоих
// дефектах корня, ради которых заведён, и молчит на законном близнеце. Вход —
// НАСТОЯЩИЙ реестр, заведённый так, как завёл бы его дефектный корень.
func TestAuditDropRowJudgeRedsOnTheRootDefectsItIsFor(t *testing.T) {
	declared := handlerinternal.AuditEventTypes()
	if len(declared) < 2 {
		t.Fatalf("предпосылка: для половины видов нужно хотя бы два, объявлено %d", len(declared))
	}
	half := declared[:len(declared)/2]
	lost := declared[len(declared)/2:]

	cases := []struct {
		name  string
		wire  func(*metrics.Registry)
		wants []string // виды, которые находка обязана назвать; пусто — молчание
	}{
		{"пустой приёмник: реестр не заведён вовсе", func(*metrics.Registry) {}, declared},
		{"приёмник с половиной видов", func(r *metrics.Registry) { r.AuthnHookAuditDropsRecorder(half) }, lost},
		{"ЗАКОННЫЙ БЛИЗНЕЦ: приёмник со всеми видами", func(r *metrics.Registry) {
			r.AuthnHookAuditDropsRecorder(declared)
		}, nil},
		{"клетка двинулась без потери", func(r *metrics.Registry) {
			r.AuthnHookAuditDropsRecorder(declared).AuditDropped(declared[0])
		}, declared[:1]},
		{"клетка чужого вида", func(r *metrics.Registry) {
			r.AuthnHookAuditDropsRecorder(append(append([]string(nil), declared...), "authn.probe.foreign"))
		}, []string{"authn.probe.foreign"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := metrics.NewRegistry()
			c.wire(reg)
			faults := auditDropRowFaults(declared, scrapeAuditDropRow(t, reg))
			if len(faults) != len(c.wants) {
				t.Fatalf("находок %d, ожидалось %d: %v", len(faults), len(c.wants), faults)
			}
			joined := strings.Join(faults, "\n")
			for _, e := range c.wants {
				if !strings.Contains(joined, strconv.Quote(e)) {
					t.Errorf("находка не называет вид %q: %v", e, faults)
				}
			}
		})
	}
}

// TestAuditDropRowParserRefusesAFormItDoesNotKnow — строка ряда в незнакомой форме
// роняет разбор, а не пропадает; строки чужих рядов разбор не трогает.
func TestAuditDropRowParserRefusesAFormItDoesNotKnow(t *testing.T) {
	name := metrics.AuthnHookAuditDropsMetric
	for _, bad := range []string{
		name + `{event_type="authn.token.issued",extra="x"} 0`,
		name + ` 0`,
		name + `{event_type="authn.token.issued"} zero`,
		name + `{event_type="a"} 0` + "\n" + name + `{event_type="a"} 0`,
	} {
		if _, err := parseAuditDropRow(bad); err == nil {
			t.Errorf("незнакомая форма строки ряда принята молча: %q", bad)
		}
	}
	cells, err := parseAuditDropRow("# HELP " + name + " x\n# TYPE " + name + " counter\n" +
		name + `{event_type="authn.token.issued"} 0` + "\n" +
		name + `{event_type="authn.refresh.denied"} 3 1700000000000` + "\n" +
		`kaname_other_total{event_type="authn.token.issued"} 7`)
	if err != nil {
		t.Fatalf("законная витрина не разобрана: %v", err)
	}
	if len(cells) != 2 || cells["authn.token.issued"] != 0 || cells["authn.refresh.denied"] != 3 {
		t.Fatalf("разбор законной витрины дал %v", cells)
	}
}
