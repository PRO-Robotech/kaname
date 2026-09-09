// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scrape_declared_test.go — служба, производящая величины, объявляет СПОСОБ их
// снять; и способ этот исполним на том профиле, который его объявляет.
//
// # Предмет
//
// Величины производились богато, а у отдельно поставленной установки способа
// снять их не было НИ ОДНОГО: порта Service нет, объявления сбора нет, объекта
// монитора нет, поверхность поднята по TLS (задача #2338). «Сломан продукт» и
// «не создано условие» в три часа ночи не различались ничем.
//
// # Почему гейт живёт здесь, а не в общей переписи чартов
//
// Общая перепись (`internal/repohygiene`, `TestEveryRenderedChartDeclaresItsScrape`)
// судит чарты, которые РЕНДЕРИТ ЗОНТИЧНЫЙ релиз, и перечень их выводит из его
// зависимостей — осознанно. Этот чарт зонтичный релиз не тянет: у него есть свой
// каталог сабчарта. То есть отдельная поставка лежала вне популяции той переписи
// BY CONSTRUCTION — граница проведена ровно там, куда дефект и попал.
//
// Второго идиома об одном предмете здесь не заводится: ФОРМА объявления взята у
// платформы дословно (`prometheus.io/*` в шаблоне пода). Разные у гейтов только
// популяции, и у каждой один судья.
//
// # Что здесь утверждается
//
//	Р1  величины действительно производятся — иначе гейту нечего стеречь;
//	Р2  способ снять их объявлен, и объявлен ЯВНО: «сбора нет» — законный выбор
//	    оператора, но он называется, а не получается молчанием;
//	Р3  объявление исполнимо: порт тот, на котором поверхность поднята, а схема
//	    та, которой поднят её транспорт;
//	Р4  перепись печатается ДВУМЯ величинами.
package deploy_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// metricsConstructorRe — конструкторы серий величин.
//
// Читается УЗЕЛ вызова, а не текст файла: имена конструкторов встречаются в
// комментариях и в шапках, и счёт по подстроке считал бы прозу объявлением.
var metricsConstructorRe = regexp.MustCompile(`^New(Counter|Gauge|Histogram|Summary)(Vec)?$|^NewDesc$`)

func TestServiceProducingSeriesDeclaresHowToCollectThem(t *testing.T) {
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")

	series, files, err := countMetricSeries(filepath.Join(root, "internal/observability/metrics"))
	require.NoError(t, err, "перепись серий")
	require.NoError(t, seriesPresent(series), "предпосылка гейта")

	roster, err := surfaceroster.Read(root)
	require.NoError(t, err, "перечень поверхностей")
	var metricsAddr string
	for _, s := range roster.Surfaces {
		if s.SettingKey == "api-server.metrics-endpoint" {
			metricsAddr = s.DefaultAddr
		}
	}
	require.NotEmpty(t, metricsAddr,
		"процесс не объявляет диагностической поверхности — стеречь её сбор было бы не о чем")

	for _, profile := range []string{"values.prod.yaml", "values.dev.yaml"} {
		t.Run(profile, func(t *testing.T) {
			rendered := renderStandaloneChart(t, []string{"values.yaml", profile})
			declared, findings := judgeScrapeDeclaration(t, rendered, portOfAddr(metricsAddr))

			t.Logf("ПЕРЕПИСЬ сбора величин (%s):\n"+
				"  серий %d в %d файлах · СПОСОБ СНЯТИЯ ОБЪЯВЛЕН: %s",
				profile, series, files, declared)
			require.Emptyf(t, findings,
				"серий %d · способ снятия объявлен: %s; расходится %d:\n  - %s",
				series, declared, len(findings), strings.Join(findings, "\n  - "))
		})
	}
}

// judgeScrapeDeclaration — само суждение.
func judgeScrapeDeclaration(t *testing.T, rendered string, wantPort string) (string, []string) {
	t.Helper()
	scrape := renderedScrapeDeclared(t, rendered)
	envs := renderedContainerEnv(t, rendered)
	ann := renderedPodAnnotations(t, rendered)

	var findings []string
	if !scrape.enabled {
		// «Сбора здесь нет» — законный выбор, но он ОБЪЯВЛЯЕТСЯ. Молчание от
		// объявленного отказа неотличимо ничем, и различить их обязан гейт.
		reason := ann["kaname.cloud/metrics-scrape-disabled-because"]
		if strings.TrimSpace(reason) == "" {
			findings = append(findings, "сбор выключен и причина не названа: "+
				"«сбора в этой установке нет намеренно» неотличимо от «забыли объявить», "+
				"а величины при этом производятся и не снимаются никем")
			return "нет, без причины", findings
		}
		return fmt.Sprintf("нет, объявлено: %s", reason), findings
	}

	if scrape.port != wantPort {
		findings = append(findings, fmt.Sprintf(
			"объявление сбора называет порт %s, а процесс поднимает диагностику на %s: "+
				"агент придёт не туда, и «величин нет» будет означать «спросили не там»",
			scrape.port, wantPort))
	}

	wantScheme := "http"
	if envs["KANAME_METRICS_SERVER_MTLS_ENABLE"] == "true" {
		wantScheme = "https"
	}
	if scrape.scheme != wantScheme {
		findings = append(findings, fmt.Sprintf(
			"объявление сбора называет схему %q, а транспорт поверхности поднят ручкой "+
				"KANAME_METRICS_SERVER_MTLS_ENABLE=%q, то есть схема обязана быть %q: "+
				"агент, пришедший открытым текстом на слушатель под TLS, получит ответ вне "+
				"полосы успеха, и сбора не будет вовсе",
			scrape.scheme, envs["KANAME_METRICS_SERVER_MTLS_ENABLE"], wantScheme))
	}
	if scrape.scheme == "" {
		findings = append(findings, "объявление сбора не называет схемы: "+
			"умолчание агента — открытый текст, и на поверхности под TLS оно молча неверно")
	}

	return fmt.Sprintf("да, %s://:%s%s", scrape.scheme, scrape.port, "/metrics"), findings
}

// seriesPresent — ПРЕДПОСЫЛКА гейта: величины действительно производятся.
//
// Отдельной функцией: доказательство способности гейта упасть зовёт её же. Ноль
// серий означал бы «стеречь нечего», и требовать объявления сбора у службы,
// которая ничего не производит, гейт не вправе — но и молчать о пустом обходе
// он не вправе тоже.
func seriesPresent(series int) error {
	if series == 0 {
		return fmt.Errorf("в реестре величин не прочитано ни одной серии: обход пуст, " +
			"и «ноль находок» стало бы неотличимо от «ноль прочитанного»")
	}
	return nil
}

// countMetricSeries считает объявления серий по УЗЛАМ вызова.
func countMetricSeries(dir string) (int, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("реестр величин %s: %w", dir, err)
	}
	series, files := 0, 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return 0, 0, fmt.Errorf("разбор %s: %w", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !metricsConstructorRe.MatchString(sel.Sel.Name) {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "prometheus" {
				series++
			}
			return true
		})
	}
	return series, files, nil
}

// renderedPodAnnotations — аннотации шаблона пода.
func renderedPodAnnotations(t *testing.T, rendered string) map[string]string {
	t.Helper()
	out := map[string]string{}
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k != "Deployment" {
			return
		}
		spec, _ := doc["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		meta, _ := tmpl["metadata"].(map[string]any)
		ann, _ := meta["annotations"].(map[string]any)
		for k, v := range ann {
			out[k] = fmt.Sprintf("%v", v)
		}
	})
	return out
}
