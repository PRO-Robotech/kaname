// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// api_token_not_mounted_test.go — ПОСТАВЛЯЕМЫЙ ЧАРТ НЕ МОНТИРУЕТ В ПОД ТОКЕН API
// КЛАСТЕРА (задача #997).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Kubernetes по умолчанию кладёт в каждый под токен ServiceAccount, под которым
// тот запущен: файл в `/var/run/secrets/kubernetes.io/serviceaccount/`. Служба
// API кластера не вызывает — клиента кластера в её коде нет (Р2 ниже), — а
// токен, который процессу не нужен, есть удостоверение, доступное любому, кто
// получил чтение файловой системы пода. Цена держится в ноль только тем, что
// права учётки пусты; выключение монтирования снимает сам материал.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
//	Р1  spec пода объявляет `automountServiceAccountToken: false` на КАЖДОЙ
//	    поставляемой цепочке профилей, и каждая ServiceAccount рендера (если
//	    чарт её заводит) — тоже;
//	Р2  ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: прод-код службы клиента кластера не несёт и
//	    файла токена не читает — иначе выключение сломало бы саму службу;
//	Р3  величина — ручка значений с ОДНИМ адресом: включение ручкой меняет
//	    рендер, небулево значение отвергается рендером с названием ручки;
//	Р4  перепись печатается величинами: «ноль находок» отличимо от «ноль
//	    прочитанного».
//
// Вердикт Р1 и Р3 выносится по РЕНДЕРУ: спрашивается «что получит кластер», а
// не «упомянут ли ключ в шаблоне». Способность мер упасть — инъекцией в
// api_token_not_mounted_injection_test.go.
//
// Приставка `TestProdProfile_Rendered` у проб рендера — намеренная: по ней их
// берёт полоса `deploy/render-guard.sh`, единственная, где отсутствие helm —
// отказ, а не пропуск.
package deploy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// apiTokenKnob — ручка значений; apiTokenField — поле spec пода и ServiceAccount.
const (
	apiTokenKnob  = "automountServiceAccountToken"
	apiTokenField = "automountServiceAccountToken"
)

// apiTokenMount — что рендер объявляет о монтировании токена.
type apiTokenMount struct {
	Specs, SpecsOff int   // spec пода Deployment: осмотрено · объявлено false
	SAs, SAsOff     int   // ServiceAccount: осмотрено · объявлено false
	Values          []any // величины поля в spec пода, как их видит разбор
}

// apiTokenMountInRender судит рендер. Отделено от дерева прогона намеренно: мера,
// чью способность падать нельзя предъявить иначе как поломкой настоящего чарта,
// доказательства не имеет.
func apiTokenMountInRender(rendered string) apiTokenMount {
	var m apiTokenMount
	isOff := func(obj map[string]any) bool {
		b, isBool := obj[apiTokenField].(bool)
		return isBool && !b
	}
	for _, doc := range strings.Split(rendered, "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var obj map[string]any
		if yaml.Unmarshal([]byte(doc), &obj) != nil {
			continue // не объект — о нём судит рендер, не эта мера
		}
		switch kind, _ := obj["kind"].(string); kind {
		case "Deployment":
			spec, _ := obj["spec"].(map[string]any)
			tmpl, _ := spec["template"].(map[string]any)
			ps, ok := tmpl["spec"].(map[string]any)
			if !ok {
				continue
			}
			m.Specs++
			m.Values = append(m.Values, ps[apiTokenField])
			if isOff(ps) {
				m.SpecsOff++
			}
		case "ServiceAccount":
			m.SAs++
			if isOff(obj) {
				m.SAsOff++
			}
		}
	}
	return m
}

// TestProdProfile_RenderedPodDoesNotMountTheClusterAPIToken — Р1 и Р4.
func TestProdProfile_RenderedPodDoesNotMountTheClusterAPIToken(t *testing.T) {
	var chains, specs, off, sas int
	for _, chain := range deliveredProfileChains {
		m := apiTokenMountInRender(renderStandaloneChart(t, chain, minimalOperatorCoordinates...))
		chains++
		require.NotZerof(t, m.Specs, "цепочка %v: Deployment в рендере не найден ни один — "+
			"обход пуст, и вердикт беспредметен", chain)
		if m.SpecsOff != m.Specs {
			t.Errorf("цепочка %v: `%s: false` объявлен в %d spec пода из %d (величины %#v) — "+
				"кластер смонтирует поду токен ServiceAccount: умолчание платформы — "+
				"МОНТИРОВАТЬ, а службе токен не нужен", chain, apiTokenField, m.SpecsOff, m.Specs, m.Values)
		}
		if m.SAsOff != m.SAs {
			t.Errorf("цепочка %v: ServiceAccount рендера %d, с `%s: false` — %d", chain,
				m.SAs, apiTokenField, m.SAsOff)
		}
		specs += m.Specs
		off += m.SpecsOff
		sas += m.SAs
	}
	t.Logf("перепись: поставляемых цепочек %d · spec пода осмотрено %d · без токена %d · "+
		"ServiceAccount в рендере %d", chains, specs, off, sas)
}

// TestProdProfile_RenderedTokenKnobIsTheOnlyAddress — Р3, первая половина: поле
// spec пода берётся из ручки, а не стоит литералом рядом с ней. Иначе ручка была
// бы объявленной и неисполнимой: оператор включил бы монтирование, а под остался
// бы прежним.
func TestProdProfile_RenderedTokenKnobIsTheOnlyAddress(t *testing.T) {
	chain := []string{"values.yaml", "values.prod.yaml"}
	sets := append(append([]string{}, minimalOperatorCoordinates...), apiTokenKnob+"=true")
	m := apiTokenMountInRender(renderStandaloneChart(t, chain, sets...))
	require.NotZero(t, m.Specs, "обход пуст: Deployment в рендере не найден")
	require.Zerof(t, m.SpecsOff, "`%s=true` не сдвинул spec пода (величины %#v): поле стоит "+
		"литералом, и у величины два адреса", apiTokenKnob, m.Values)
	for _, v := range m.Values {
		require.Equalf(t, true, v, "`%s=true` дал в spec пода %#v", apiTokenKnob, v)
	}
}

// TestProdProfile_RenderedTokenKnobRefusesANonBoolean — Р3, вторая половина.
//
// Строка `"false"` в условии шаблона истинна, а в поле spec пода её не примет
// API-сервер, — значит небулево значение обязано падать РЕНДЕРОМ с названием
// ручки, а не установкой с текстом схемы. Снятый ключ — тот же отказ: величину
// безопасности умолчание чарта не подставляет молча.
func TestProdProfile_RenderedTokenKnobRefusesANonBoolean(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"string", apiTokenKnob + `: "false"`},
		{"number", apiTokenKnob + `: 0`},
		{"unset", apiTokenKnob + `:`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := chartCopy(t)
			patchInCopy(t, dir, "values.yaml", apiTokenKnob+": false", tc.line)
			out, err := renderChartAtAllowingFailure(t, dir,
				[]string{"values.yaml", "values.prod.yaml"}, minimalOperatorCoordinates...)
			require.Errorf(t, err, "рендер принял `%s` — небулево значение дошло бы до кластера", tc.line)
			require.Containsf(t, out, apiTokenKnob, "отказ рендера не называет ручку:\n%s", out)
		})
	}
}

// TestServiceProcessNeverReadsTheClusterAPI — Р2, ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него выключение монтирования выглядело бы бесплатным по построению.
// Спрашивается обратное: не обращается ли прод-код службы к API кластера — тогда
// выключение сломало бы службу, и решение было бы неверным.
//
// Судится РАЗБОР Go, а не поиск по тексту: импорт клиента кластера и строковый
// литерал пути к файлу токена — узлы дерева, комментарий их не изображает.
func TestServiceProcessNeverReadsTheClusterAPI(t *testing.T) {
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "go.mod"))
	require.NoErrorf(t, err, "корень модуля %s без go.mod — обход шёл бы не по дереву службы", root)

	const tokenDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	clusterClient := []string{"k8s.io/client-go", "sigs.k8s.io/controller-runtime"}
	var files, findings int
	fset := token.NewFileSet()
	require.NoError(t, filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata", ".stand":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files++
		rel, _ := filepath.Rel(root, p)
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, c := range clusterClient {
				if path == c || strings.HasPrefix(path, c+"/") {
					findings++
					t.Errorf("%s:%d импортирует клиента кластера %q — служба обращается к API "+
						"кластера, и выключение монтирования токена её сломает",
						rel, fset.Position(imp.Pos()).Line, path)
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if s, uerr := strconv.Unquote(lit.Value); uerr == nil && strings.Contains(s, tokenDir) {
				findings++
				t.Errorf("%s:%d читает каталог токена учётки %q", rel, fset.Position(lit.Pos()).Line, s)
			}
			return true
		})
		return nil
	}), "обход прод-кода модуля")
	require.NotZerof(t, files, "обход пуст: прод-файлов Go под %s ноль — «находок ноль» "+
		"неотличимо от «ноль прочитанного»", root)
	t.Logf("перепись: прод-файлов Go разобрано %d · обращений к API кластера и к файлу токена %d",
		files, findings)
}
