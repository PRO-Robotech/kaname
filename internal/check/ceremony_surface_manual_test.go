// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_surface_manual_test.go — маршрут, решаемый по ПУТИ ЗАПРОСА в теле
// обработчика (ceremony_surface_manual.go), в обе стороны (kaname#320).
//
// Каждая инъекция — один факт F-cer: обёртка поверхности диагностики решает
// маршрут по пути запроса ещё одной формой. Форма записи пути — не перечень
// распознавателя, а то, куда путь ТЕЧЁТ: переменная, поле своей структуры,
// параметр именованной функции, литерала функции и метода, получатель метода
// своего типа, адрес запроса, разобранный из его строки. Близнецы — тот же путь,
// который маршрута не выбирает: журнал, ответ клиенту, длина.
package check_test

import (
	"strings"
	"testing"
)

// manualInjection — решение о маршруте по пути запроса одной формой.
type manualInjection struct {
	id   string
	edit func(f *ceremonyFixture)
	want []string
}

// manualCond — обёртка с условием cond и ответом на совпадение.
func manualCond(imports, pre, cond string) func(f *ceremonyFixture) {
	return func(f *ceremonyFixture) {
		ceremonyManualOnMetrics(f, ceremonyManualSource(imports, pre, cond, "w.WriteHeader(http.StatusOK)"))
	}
}

func manualInjections() []manualInjection {
	decided := "по пути запроса в теле обработчика"
	return []manualInjection{
		{"Z13_path_in_a_field_of_an_own_struct", manualCond("", "",
			`if c := (struct{ p string }{p: r.URL.Path}); c.p == "/iam/v1/authorize"`),
			[]string{decided, "сравнение пути", "ceremony_probe_manual.go:"}},

		{"Z14_request_embedded_in_an_own_type", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_req.go", "\t\"net/http\"", "type ceremonyReq struct{ *http.Request }")
			manualCond("", "", `if cr := (ceremonyReq{r}); cr.URL.Path == "/iam/v1/authorize"`)(f)
		}, []string{decided, "сравнение пути", "ceremony_probe_manual.go:"}},

		// Z15, Z18 — функции сопоставления из опытов приёмки проверки, круг 2:
		// путь, приведённый к байтам, в чужой функции-признаке, и strings.Cut —
		// признак среди результатов кортежа, названный шапкой распознавателя.
		{"Z15_bytes_equal_over_the_path", manualCond("\n\t\"bytes\"", "",
			`if bytes.Equal([]byte(r.URL.Path), []byte("/iam/v1/authorize"))`),
			[]string{decided, "сопоставление пути функцией bytes.Equal", "ceremony_probe_manual.go:"}},

		{"Z18_strings_cut_of_the_path", manualCond("\n\t\"strings\"", "",
			`if _, rest, ok := strings.Cut(r.URL.Path, "/iam/v1/"); ok && rest == "authorize"`),
			[]string{decided, "сопоставление пути функцией strings.Cut", "ceremony_probe_manual.go:"}},

		{"Z16_named_helper_with_a_boolean_result", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_is.go", "",
				"func ceremonyIsAuthorize(p string) bool { return p == \"/iam/v1/authorize\" }")
			manualCond("", "", `if ceremonyIsAuthorize(r.URL.Path)`)(f)
		}, []string{decided, "сопоставление пути функцией", "ceremonyIsAuthorize"}},

		{"Z17_method_of_an_own_string_type", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_is.go", "",
				"type ceremonyPath string\n\nfunc (p ceremonyPath) isAuthorize() bool { return p == \"/iam/v1/authorize\" }")
			manualCond("", "", `if ceremonyPath(r.URL.Path).isAuthorize()`)(f)
		}, []string{decided, "сравнение пути", "ceremony_probe_is.go:"}},

		{"Z22_closure_helper", manualCond("",
			"\tceremonyIs := func(p string) bool { return p == \"/iam/v1/authorize\" }\n",
			`if ceremonyIs(r.URL.Path)`),
			[]string{decided, "сравнение пути", "ceremony_probe_manual.go:"}},

		{"Z23_url_parsed_from_the_request_uri", manualCond("\n\t\"net/url\"", "",
			`if u, err := url.Parse(r.RequestURI); err == nil && u.Path == "/iam/v1/authorize"`),
			[]string{decided, "сравнение пути", "ceremony_probe_manual.go:"}},

		{"Z24_named_helper_with_a_string_parameter_and_no_result", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_route.go", "\t\"net/http\"",
				"func ceremonyRoute(w http.ResponseWriter, r *http.Request, p string, next http.Handler) {\n"+
					"\tif p == \"/iam/v1/authorize\" {\n\t\tw.WriteHeader(http.StatusOK)\n\t\treturn\n\t}\n\tnext.ServeHTTP(w, r)\n}")
			ceremonyManualOnMetrics(f, "package main\n\nimport \"net/http\"\n\n"+
				"func ceremonyProbeManual(next http.Handler) http.Handler {\n"+
				"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ceremonyRoute(w, r, r.URL.Path, next) })\n}\n")
		}, []string{decided, "сравнение пути", "ceremony_probe_route.go:"}},

		{"Z25_path_parsed_into_a_route_struct", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_route.go", "\t\"strings\"",
				"type ceremonyParsed struct{ svc, method string }\n\n"+
					"func ceremonyParse(p string) ceremonyParsed {\n\ts := strings.Split(strings.Trim(p, \"/\"), \"/\")\n"+
					"\tif len(s) < 3 {\n\t\treturn ceremonyParsed{}\n\t}\n\treturn ceremonyParsed{svc: s[0], method: s[2]}\n}")
			manualCond("", "", `if rt := ceremonyParse(r.URL.Path); rt.svc == "iam" && rt.method == "authorize"`)(f)
		}, []string{decided, "сравнение пути", "ceremony_probe_manual.go:"}},

		// Обработчик своего НЕ-структурного типа: его метод ServeHTTP достижим
		// потому, что значение типа рождено в достижимом коде (приведением), а
		// не потому, что рождена структура.
		{"M1_handler_of_an_own_non_struct_type", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_handler.go", "\t\"net/http\"",
				"type ceremonyH int\n\nfunc (ceremonyH) ServeHTTP(w http.ResponseWriter, r *http.Request) {\n"+
					"\tif r.URL.Path == \"/iam/v1/authorize\" {\n\t\tw.WriteHeader(http.StatusOK)\n\t}\n}")
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorMetrics, `metricsMux.Handle("/probe-h/", ceremonyH(0))`)
		}, []string{decided, "сравнение пути", "ceremony_probe_handler.go:"}},

		// Путь, отданный параметру функции-ЗНАЧЕНИЯ (форма журнала живого
		// дерева: LoggerMiddleware(mux, func(method, path string, status int))),
		// выбирает маршрут в её теле.
		{"M2_function_value_parameter_decides", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, "package main\n\nimport \"net/http\"\n\n"+
				"func ceremonyWith(next http.Handler, decide func(path string) bool) http.Handler {\n"+
				"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"+
				"\t\tif decide(r.URL.Path) {\n\t\t\tw.WriteHeader(http.StatusOK)\n\t\t\treturn\n\t\t}\n\t\tnext.ServeHTTP(w, r)\n\t})\n}\n\n"+
				"func ceremonyProbeManual(next http.Handler) http.Handler {\n"+
				"\treturn ceremonyWith(next, func(path string) bool { return path == \"/iam/v1/authorize\" })\n}\n")
		}, []string{decided, "сравнение пути", "ceremony_probe_manual.go:"}},

		// G2: цикл записей ceremonyP ↔ ceremonyQ и НЕДОСТИЖИМАЯ функция, первой
		// спрашивающая ceremonyP. Выводимость из пути не зависит от того, кто
		// спросил первым.
		{"G2_derivation_does_not_depend_on_who_asks_first", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, manualCycleSource(true))
		}, []string{decided, "сравнение пути", "ceremony_probe_manual.go:14"}},

		{"G2c_same_cycle_without_the_first_asker", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, manualCycleSource(false))
		}, []string{decided, "сравнение пути", "ceremony_probe_manual.go:12"}},
	}
}

// manualCycleSource — цикл записей переменных пакета; poison — недостижимая
// функция, объявленная раньше обработчика, спрашивает ceremonyP первой.
// Строка сравнения по ceremonyQ: 14 с ней, 12 без неё.
func manualCycleSource(poison bool) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport \"net/http\"\n\nvar ceremonyP, ceremonyQ string\n\n")
	if poison {
		b.WriteString("func ceremonyUnusedMatch() bool { return ceremonyP == \"/probe\" }\n\n")
	}
	b.WriteString("func ceremonyProbeManual(next http.Handler) http.Handler {\n" +
		"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n" +
		"\t\tceremonyP = ceremonyQ\n\t\tceremonyP = r.URL.Path\n\t\tceremonyQ = ceremonyP\n" +
		"\t\tif ceremonyQ == \"/iam/v1/authorize\" {\n\t\t\tw.WriteHeader(http.StatusOK)\n\t\t\treturn\n\t\t}\n" +
		"\t\tnext.ServeHTTP(w, r)\n\t})\n}\n")
	return b.String()
}

// TestCeremonySurfaceManualRoutingForms — каждая форма краснеет, и находка
// называет форму и место решения.
func TestCeremonySurfaceManualRoutingForms(t *testing.T) {
	for _, inj := range manualInjections() {
		t.Run(inj.id, func(t *testing.T) {
			f := newCeremonyFixture(t)
			inj.edit(f)
			report := f.mustJudge(fixtureCeremonyCoordinates())
			got := requireFinding(t, report, inj.want...)
			t.Logf("находок %d; своя: %s", len(report.Findings), got)
		})
	}
}

// TestCeremonySurfaceManualRoutingCountsEveryDecision — G1: в ОДНОЙ функции
// цикл записей p ↔ q и закрытие, первым спрашивающее p. Перепись решений
// насчитывает ОБА решения — и по p, и по q; без цикла (G1d) — те же два.
func TestCeremonySurfaceManualRoutingCountsEveryDecision(t *testing.T) {
	hit := "\t\tif q == \"/iam/v1/authorize\" {\n\t\t\tw.WriteHeader(http.StatusOK)\n\t\t\treturn\n\t\t}\n"
	closure := "\t\t_ = func() bool { return p == \"/probe\" }\n"
	body := func(pre string) string {
		return "package main\n\nimport \"net/http\"\n\n" +
			"func ceremonyProbeManual(next http.Handler) http.Handler {\n" +
			"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n" + pre + closure + hit +
			"\t\tnext.ServeHTTP(w, r)\n\t})\n}\n"
	}
	for _, tc := range []struct {
		id, src string
		lines   []string
	}{
		{"G1_cycle_and_a_closure_asking_first", body("\t\tvar p, q string\n\t\tp = q\n\t\tp = r.URL.Path\n\t\tq = p\n"),
			[]string{"ceremony_probe_manual.go:11", "ceremony_probe_manual.go:12"}},
		{"G1d_no_cycle", body("\t\tp := r.URL.Path\n\t\tq := p\n"),
			[]string{"ceremony_probe_manual.go:9", "ceremony_probe_manual.go:10"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newCeremonyFixture(t)
			ceremonyManualOnMetrics(f, tc.src)
			report := f.mustJudge(fixtureCeremonyCoordinates())
			got := report.Census.ManualRouting
			if len(got) != len(tc.lines) {
				t.Fatalf("решений маршрута насчитано %d (%v), ожидалось %d (%v)", len(got), got, len(tc.lines), tc.lines)
			}
			for i, want := range tc.lines {
				if !strings.HasSuffix(got[i], want) {
					t.Errorf("решение %d: %s, ожидалось …%s", i, got[i], want)
				}
			}
		})
	}
}

// manualTwin — близнец; noRead — близнец не читает путь в достижимом коде
// (чтение в недостижимой функции, чтение хоста), и перепись чтений у него не
// растёт.
type manualTwin struct {
	ceremonyTwin
	noRead bool
}

// manualTwins — тот же путь запроса, который маршрута не выбирает.
func manualTwins() []manualTwin {
	unreached := manualTwin{ceremonyTwin{"W4_compare_in_an_unreached_function", func(f *ceremonyFixture) {
		ceremonyRootFile(f, "ceremony_probe_dead.go", "\t\"net/http\"",
			"func ceremonyUnusedRoute(r *http.Request) bool { return r.URL.Path == \"/iam/v1/authorize\" }")
	}}, true}
	out := []manualTwin{unreached}
	for _, t := range []ceremonyTwin{
		{"W6_derived_path_only_logged", manualCond("\n\t\"log/slog\"\n\t\"strings\"", "",
			`if slog.Debug("запрос", "путь", strings.ToLower(r.URL.Path)); false`)},
		{"F1_path_written_to_the_response_by_fprintf", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, manualStmtSource("\n\t\"fmt\"", "\t\tfmt.Fprintf(w, \"no route %s\", r.URL.Path)\n"))
		}},
		{"F2_path_written_to_the_response_as_bytes", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, manualStmtSource("", "\t\t_, _ = w.Write([]byte(r.URL.Path))\n"))
		}},
		{"M3_path_in_an_own_struct_field_only_logged", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, manualStmtSource("\n\t\"log/slog\"",
				"\t\tc := struct{ p string }{p: r.URL.Path}\n\t\tslog.Info(\"запрос\", \"путь\", c.p)\n"))
		}},
		{"M4_helper_compares_only_a_constant", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_is.go", "",
				"func ceremonyIsAuthorize(p string) bool { return p == \"/iam/v1/authorize\" }")
			ceremonyManualOnMetrics(f, manualStmtSource("\n\t\"log/slog\"",
				"\t\tslog.Info(\"запрос\", \"путь\", r.URL.Path, \"проба\", ceremonyIsAuthorize(\"/probe\"))\n"))
		}},
		{"M5_route_struct_field_not_derived_from_the_path", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_route.go", "",
				"type ceremonyParsed struct{ method, kind string }\n\n"+
					"func ceremonyParse(p string) ceremonyParsed { return ceremonyParsed{method: p, kind: \"probe\"} }")
			manualCond("", "", `if rt := ceremonyParse(r.URL.Path); rt.kind == "authorize"`)(f)
		}},
		{"M6_function_value_parameter_only_logged", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, "package main\n\nimport (\n\t\"log/slog\"\n\t\"net/http\"\n)\n\n"+
				"func ceremonyWith(next http.Handler, log func(path string)) http.Handler {\n"+
				"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { log(r.URL.Path); next.ServeHTTP(w, r) })\n}\n\n"+
				"func ceremonyProbeManual(next http.Handler) http.Handler {\n"+
				"\treturn ceremonyWith(next, func(path string) { slog.Info(\"запрос\", \"путь\", path) })\n}\n")
		}},
	} {
		out = append(out, manualTwin{ceremonyTwin: t})
	}
	// Хост адреса запроса — не путь: сравнение хоста маршрута по пути не
	// выбирает.
	return append(out, manualTwin{ceremonyTwin{"M7_host_of_the_request_url_compared",
		manualCond("", "", `if u := r.URL; u.Hostname() == "kaname.invalid"`)}, true})
}

// manualStmtSource — обёртка, выполняющая оператор и делегирующая дальше.
func manualStmtSource(imports, stmt string) string {
	return "package main\n\nimport (\n\t\"net/http\"" + imports + "\n)\n\n" +
		"func ceremonyProbeManual(next http.Handler) http.Handler {\n" +
		"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n" + stmt +
		"\t\tnext.ServeHTTP(w, r)\n\t})\n}\n"
}

// TestCeremonySurfaceManualRoutingTwinsAreSilent — путь прочитан, маршрута не
// выбирает: молчит, и молчит, ВИДЯ чтение — чтений больше, чем в контроле.
func TestCeremonySurfaceManualRoutingTwinsAreSilent(t *testing.T) {
	control := newCeremonyFixture(t).mustJudge(fixtureCeremonyCoordinates()).Census.URLPathReads
	for _, twin := range manualTwins() {
		t.Run(twin.id, func(t *testing.T) {
			f := newCeremonyFixture(t)
			twin.edit(f)
			report := f.mustJudge(fixtureCeremonyCoordinates())
			requireSilent(t, report)
			if got := report.Census.URLPathReads; !twin.noRead && got <= control {
				t.Fatalf("близнец молчит, а чтений пути запроса %d при %d в контроле — чтение близнеца "+
					"распознаватель не увидел: %s", got, control, report.Census.Summary())
			}
		})
	}
}

// TestCeremonySurfaceManualRoutingSeesTheLiveCarrier — живой положительный
// контроль выведения: путь, отданный журналу параметром функции-значения
// (iamhooks.LoggerMiddleware), насчитан носителем пути, а решением не назван.
func TestCeremonySurfaceManualRoutingSeesTheLiveCarrier(t *testing.T) {
	report := judgeLiveCeremony(t)
	c := report.Census
	if c.PathCarriers == 0 {
		t.Fatalf("носителей пути 0 на живом дереве — выведение ослепло: путь уходит в параметр журнала "+
			"hooks_mux.go (LoggerMiddleware): %s", c.Summary())
	}
	if len(c.ManualRouting) != 0 {
		t.Fatalf("живое дерево решает маршрут по пути запроса: %v", c.ManualRouting)
	}
	t.Logf("чтений пути %d · носителей %d · решений %d", c.URLPathReads, c.PathCarriers, len(c.ManualRouting))
}
