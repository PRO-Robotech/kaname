// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// api_token_not_mounted_test.go — ПОСТАВЛЯЕМЫЙ ЧАРТ НЕ МОНТИРУЕТ В ПОД ТОКЕН API
// КЛАСТЕРА (задача kaname#997).
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
//	Р3  величина — ЛИТЕРАЛ шаблона, а не ручка значений: ни один поставляемый
//	    файл значений ключа не объявляет, и попытка оператора включить
//	    монтирование через `--set` рендер не сдвигает — включать нечего, а
//	    ручка без потребителя была бы лишней поверхностью;
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

// apiTokenField — поле spec пода и ServiceAccount; тем же именем оператор
// пытался бы завести ручку значений, которой у чарта нет (Р3).
const apiTokenField = "automountServiceAccountToken"

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

// TestProdProfile_RenderedTokenIgnoresAnOperatorOverride — Р3, рендер: поле spec
// пода стоит литералом, и `--set` одноимённого ключа его не сдвигает. Будь поле
// взято из значений, оператор включил бы монтирование одной строкой, и выключение
// держалось бы умолчанием, а не построением.
func TestProdProfile_RenderedTokenIgnoresAnOperatorOverride(t *testing.T) {
	var specs int
	for _, chain := range deliveredProfileChains {
		sets := append(append([]string{}, minimalOperatorCoordinates...), apiTokenField+"=true")
		m := apiTokenMountInRender(renderStandaloneChart(t, chain, sets...))
		require.NotZerof(t, m.Specs, "цепочка %v: Deployment в рендере не найден — вердикт беспредметен", chain)
		require.Equalf(t, m.Specs, m.SpecsOff, "цепочка %v: `--set %s=true` сдвинул spec пода "+
			"(величины %#v) — поле берётся из значений, и у выключения появилась ручка",
			chain, apiTokenField, m.Values)
		specs += m.Specs
	}
	t.Logf("перепись: цепочек %d · spec пода под `--set %s=true` осмотрено %d · все без токена",
		len(deliveredProfileChains), apiTokenField, specs)
}

// TestDeliveredValuesDeclareNoTokenKnob — Р3, объявления: ни один поставляемый
// файл значений ключа не несёт. Судятся ОБЪЯВЛЕНИЯ значений, а не рендер: ключ,
// который шаблон не читает, рендер не показал бы, а оператор принял бы его за
// действующую настройку.
func TestDeliveredValuesDeclareNoTokenKnob(t *testing.T) {
	seen := map[string]bool{}
	var files int
	for _, chain := range deliveredProfileChains {
		for _, f := range chain {
			if seen[f] {
				continue
			}
			seen[f] = true
			b, err := os.ReadFile(f) // #nosec G304 -- имя из перечня поставляемых профилей
			require.NoErrorf(t, err, "чтение %s", f)
			var top map[string]any
			require.NoErrorf(t, yaml.Unmarshal(b, &top), "разбор %s", f)
			require.NotEmptyf(t, top, "%s: ключей верхнего уровня ноль — «ключа нет» "+
				"неотличимо от «ничего не прочитано»", f)
			files++
			_, declared := top[apiTokenField]
			require.Falsef(t, declared, "%s объявляет `%s` — шаблон его не читает (поле — литерал), "+
				"и ключ выглядел бы настройкой, не будучи ею", f, apiTokenField)
		}
	}
	t.Logf("перепись: файлов значений осмотрено %d · с ключом `%s` 0", files, apiTokenField)
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
