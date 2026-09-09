// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operator_keys_carry_no_foreign_prefix_test.go — КЛЮЧИ, КОТОРЫЕ ВИДИТ ОПЕРАТОР,
// ПРИНАДЛЕЖАТ ЭТОМУ ПРОДУКТУ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Критерий витрины: «увидит ли это тот, кто ставит службу в ЧУЖОМ облаке, не
// открывая наш исходный код». По двум видам ключей ответ — да:
//
//	ключ аннотации   он читает `kubectl describe pod` — ключ печатается дословно;
//	ключ значений    он пишет РУКАМИ в своём профиле.
//
// Здесь стояли ключи с доменом чужой платформы (`<чужой домен>/image-id`,
// `<чужой домен>/config-checksum`) и ключ значений с её приставкой, приходивший
// СТРОКОВЫМ ДОВОДОМ выборки, а не путём после `.Values`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ФОРМА СТРОКОВОГО ДОВОДА НАЗВАНА ОТДЕЛЬНО
//
// Соседний предмет судил ключи по образцу `\.Values\.<приставка>…` и по чарту
// продукта дал НОЛЬ. Ноль означал не «чисто», а «форма распознавателю
// неизвестна»: ключ приходил доводом `dig "<ключ>" … (.Values.global)`. Форма, о
// которой распознаватель не знает, не даёт ни красного, ни зелёного — она
// молчит, и всё записанное в ней оказывается вне наблюдения. Поэтому обе формы
// перечислены здесь явно, и у каждой свой случай инъекции.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРАВИЛА ПОЛОЖИТЕЛЬНЫЕ, А НЕ «НЕ УПОМИНАТЬ ЧУЖОЕ ИМЯ»
//
// Запрет по литералу чужого имени ловит ровно то имя, которое в него вписали, и
// молчит на следующем. Оба правила ниже сформулированы от СВОЕГО, поэтому
// ловят и ту приставку, о которой никто не думал:
//
//	вид А  доменная часть ключа аннотации обязана быть доменом ЭТОГО продукта;
//	вид Б  первый сегмент пути значений обязан быть объявлен в `values.yaml`
//	       этого чарта — обеими формами записи.
//
// Правило вида Б бьёт в корень: ключ, которого нет ни в одном профиле чарта,
// оператор не может ни найти, ни задать. Такой ключ приходит СНАРУЖИ — из
// накладки чужого зонтика, — и в отдельной поставке производителя не имеет
// вовсе, поэтому величина у него всегда одна и та же заглушка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОБА НЕ ДЕЛАЕТ
//
//   - не судит ЗНАЧЕНИЯ (адреса, домен доверия, координаты образа) — их судят
//     соседние пробы каталога, и два места об одном предмете разошлись бы молча;
//   - не судит прозу комментариев: чарт вправе назвать соседа, объясняя, с чем
//     он разговаривает. Различает не «код против комментария», а то, что ключ
//     ВЫВОДИТСЯ в манифест либо ЧИТАЕТСЯ из значений;
//   - не судит ключи, которых оператор не видит: имена внутри именованных
//     шаблонов предметом витрины не являются.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА — КЛЮЧ, и осмотренное печатается отдельно от найденного
//
// Обход, не давший ни одного ключа ни одного вида, есть ОТКАЗ, а не чистый
// чарт: «ноль находок» обязано быть отличимо от «ноль прочитанного».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ДОКАЗАНА СПОСОБНОСТЬ УПАСТЬ
//
// Разбор — чистая функция auditOperatorKeyPrefixes над каталогом поставки.
// Инъекция — operator_keys_carry_no_foreign_prefix_injection_test.go: вход
// НАСТОЯЩИЙ, каждый случай меняет ровно один факт, контроль в обе стороны.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// productKeyDomain — домен ЭТОГО продукта. Единственный литерал пробы, и он
// называет своё, а не чужое: правило положительное.
const productKeyDomain = "kaname.cloud"

// standardKeyDomains — домены, чьи ключи объявляет не продукт, а ЧИТАТЕЛЬ этих
// ключей. Ведомость, и она истекает сама: запись, которой нечего разрешать,
// находкой не становится, но и не прощает ничего сверх своего домена.
//
// ЧТО РАЗЛИЧАЕТ ЗАПИСЬ ЭТОЙ ВЕДОМОСТИ ОТ ЧУЖОГО БРЕНДА НА ВИТРИНЕ. Ключ, чьё имя
// выбираем МЫ, обязан называть наш продукт: оператор читает его дословно, и
// чужое имя там — витрина. Ключ, чьё имя выбирает тот, КТО ЕГО ЧИТАЕТ,
// переименованию не подлежит вовсе: имя и есть протокол обращения к нему.
//
// `prometheus.io` — второй род (задача #2338). Объявление сбора величин читает
// СОБИРАТЕЛЬ, и читает по этим именам; названное нашим доменом, оно не будет
// прочитано никем — то есть станет ровно тем дефектом, ради которого заводилось:
// величины производятся, снять их нечем, а на витрине при этом порядок. Той же
// формой отдают себя на сбор все прочие службы дерева и зонтичный чарт этой,
// поэтому свой идиом здесь был бы ещё и вторым местом об одном предмете.
//
// Ведомость НЕ прощает домену ничего сверх его собственных ключей: разрешён
// домен, а не приставка, и `prometheus.io.example.com` под запись не подпадает.
var standardKeyDomains = []string{"kubernetes.io", "k8s.io", "prometheus.io"}

// annotationBlockRe — начало блока аннотаций в шаблоне.
var annotationBlockRe = regexp.MustCompile(`^\s*annotations:\s*$`)

// annotationKeyRe — ключ внутри блока аннотаций: `<домен>/<имя>: …` либо
// `<имя>: …`. Ключ с доменом — тот, что несёт косую черту.
var annotationKeyRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._/-]*)\s*:`)

// valuesPathRe — ПЕРВАЯ форма ключа значений: путь после `.Values.`.
var valuesPathRe = regexp.MustCompile(`\.Values\.([A-Za-z0-9_]+)`)

// digKeyRe — ВТОРАЯ форма: ключ строковым доводом выборки. Именно она осталась
// вне наблюдения соседнего предмета, поэтому названа отдельно.
var digKeyRe = regexp.MustCompile(`\bdig\s+"([A-Za-z0-9_.-]+)"`)

// valuesAnchorRe — ПОЛНЫЙ путь после `.Values`, которым выборка привязана к
// дереву значений: `.Values`, `.Values.global`, `.Values.tls.server`.
var valuesAnchorRe = regexp.MustCompile(`\.Values((?:\.[A-Za-z0-9_]+)*)`)

// operatorKey — один найденный ключ витрины.
type operatorKey struct {
	kind  string // "аннотация" | "значения"
	name  string
	file  string
	line  int
	form  string   // чем опознан: важно для вида Б — форм записи две
	scope []string // для довода выборки: путь поддерева значений, в котором ищется ключ
}

// operatorKeyCensus — объём осмотренного.
type operatorKeyCensus struct {
	FilesRead       int
	LinesRead       int
	AnnotationKeys  int
	ValuesKeysPath  int
	ValuesKeysDig   int
	DeclaredTopKeys int
}

func (c operatorKeyCensus) String() string {
	return fmt.Sprintf(
		"шаблонов прочитано %d · строк %d · ключей аннотаций %d · ключей значений %d "+
			"(путём %d · доводом выборки %d) · объявлено ключей верхнего уровня %d",
		c.FilesRead, c.LinesRead, c.AnnotationKeys,
		c.ValuesKeysPath+c.ValuesKeysDig, c.ValuesKeysPath, c.ValuesKeysDig, c.DeclaredTopKeys)
}

// collectOperatorKeys — ключи обоих видов во всех шаблонах чарта.
//
// Файл именованных шаблонов пропускается, пока он не рендерит объектов: его
// текст несёт ПРОЗУ об этих же ключах, и распознаватель, читающий её как
// объявление, краснел бы на собственном объяснении. Предпосылка проверяется,
// а не подразумевается.
func collectOperatorKeys(chartDir string) ([]operatorKey, operatorKeyCensus, error) {
	var (
		keys   []operatorKey
		census operatorKeyCensus
	)

	tmplDir := filepath.Join(chartDir, templatesDir)
	entries, err := os.ReadDir(tmplDir)
	if err != nil {
		return nil, census, fmt.Errorf("каталог шаблонов не читается: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		raw, readErr := os.ReadFile(filepath.Join(tmplDir, name))
		if readErr != nil {
			return nil, census, fmt.Errorf("шаблон %s не читается: %w", name, readErr)
		}
		text := string(raw)
		// Координата — ОТ КАТАЛОГА ЧАРТА, а не голое имя файла. Голое имя в
		// этом дереве не адресует: `deployment.yaml` есть и у чарта продукта, и
		// у подчарта стенда, и находка по нему посылает читателя не туда —
		// ровно тот класс, ради которого заведён держатель имён чартов.
		where := templatesDir + "/" + name

		if name == helpersFile {
			if strings.Contains(text, "\nkind:") {
				return nil, census, fmt.Errorf(
					"%s объявляет ресурс — он больше не только именованные шаблоны, "+
						"и его ключи витрины перестали осматриваться", name)
			}
			// Ключи ЗНАЧЕНИЙ именованные шаблоны читают наравне с остальными:
			// оператор задаёт их так же руками. Осматриваются обе формы, а
			// блок аннотаций здесь не ищется — объектов файл не рендерит.
			census.FilesRead++
			lines := strings.Split(text, "\n")
			census.LinesRead += len(lines)
			collectValuesKeys(where, lines, &keys, &census)
			continue
		}

		census.FilesRead++
		lines := strings.Split(text, "\n")
		census.LinesRead += len(lines)
		collectValuesKeys(where, lines, &keys, &census)

		// Блок аннотаций опознаётся отступом: шаблоны чарта — YAML, и
		// вложенность в них выражена отступом, а не догадкой.
		blockIndent := -1
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "{{") {
				continue
			}
			ind := len(line) - len(strings.TrimLeft(line, " "))
			if blockIndent >= 0 && ind <= blockIndent {
				blockIndent = -1
			}
			if annotationBlockRe.MatchString(line) {
				blockIndent = ind
				continue
			}
			if blockIndent < 0 {
				continue
			}
			m := annotationKeyRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			census.AnnotationKeys++
			keys = append(keys, operatorKey{
				kind: "аннотация", name: m[1], file: where, line: i + 1, form: "ключ манифеста",
			})
		}
	}
	return keys, census, nil
}

// collectValuesKeys — обе формы ключа значений в одном файле.
func collectValuesKeys(file string, lines []string, keys *[]operatorKey, census *operatorKeyCensus) {
	for i, line := range lines {
		for _, m := range valuesPathRe.FindAllStringSubmatch(line, -1) {
			census.ValuesKeysPath++
			*keys = append(*keys, operatorKey{
				kind: "значения", name: m[1], file: file, line: i + 1, form: "путь после .Values",
			})
		}
		// Выборка судится ТОЛЬКО когда она привязана к дереву значений на той
		// же строке. Выборка по псевдониму (`dig "mode" "" $cur`) читает
		// вложенную величину, которой чарт уже владеет, — ключом витрины она не
		// является, и судить её значило бы краснеть на законной форме.
		anchor := valuesAnchorRe.FindStringSubmatch(line)
		if anchor == nil {
			continue
		}
		scope := []string{}
		for _, seg := range strings.Split(strings.TrimPrefix(anchor[1], "."), ".") {
			if seg != "" {
				scope = append(scope, seg)
			}
		}
		for _, m := range digKeyRe.FindAllStringSubmatch(line, -1) {
			census.ValuesKeysDig++
			*keys = append(*keys, operatorKey{
				kind: "значения", name: m[1], file: file, line: i + 1,
				form: "строковый довод выборки", scope: scope,
			})
		}
	}
}

// auditOperatorKeyPrefixes — разбор каталога поставки.
func auditOperatorKeyPrefixes(chartDir string) (findings []string, census string, err error) {
	keys, c, err := collectOperatorKeys(chartDir)
	if err != nil {
		return nil, "", err
	}

	defaults, err := readChartValues(filepath.Join(chartDir, chartDefaultsFile))
	if err != nil {
		return nil, "", fmt.Errorf("базовые значения не читаются: %w", err)
	}
	declared := map[string]bool{}
	for k := range defaults {
		declared[k] = true
	}
	c.DeclaredTopKeys = len(declared)

	// declaredIn — объявлен ли ключ в поддереве значений, названном областью.
	// Область пуста — корень: тогда это тот же словарь, что и у пути.
	declaredIn := func(scope []string, key string) bool {
		node := any(defaults)
		for _, seg := range scope {
			m, ok := node.(map[string]any)
			if !ok {
				return false
			}
			node, ok = m[seg]
			if !ok {
				return false
			}
		}
		m, ok := node.(map[string]any)
		if !ok {
			return false
		}
		_, ok = m[key]
		return ok
	}

	// ПОЛОЖИТЕЛЬНЫЕ КОНТРОЛИ: без них молчание ниже относилось бы к пустоте.
	if c.FilesRead == 0 {
		return nil, c.String(), fmt.Errorf("обход пуст: шаблонов не прочитано ни одного — вердикт беспредметен")
	}
	if c.AnnotationKeys == 0 {
		return nil, c.String(), fmt.Errorf(
			"обход пуст: ключей аннотаций не найдено ни одного (шаблонов %d, строк %d) — "+
				"вид А судить не на чем, и молчание по нему ничего не значит", c.FilesRead, c.LinesRead)
	}
	if c.ValuesKeysPath+c.ValuesKeysDig == 0 {
		return nil, c.String(), fmt.Errorf(
			"обход пуст: ключей значений не найдено ни одного — распознаватель не знает ни одной " +
				"формы этого чарта, и вид Б не судится")
	}
	if len(declared) == 0 {
		return nil, c.String(), fmt.Errorf(
			"обход пуст: базовые значения чарта не объявляют ни одного ключа верхнего уровня — " +
				"сверять принадлежность не с чем")
	}

	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].file != keys[j].file {
			return keys[i].file < keys[j].file
		}
		return keys[i].line < keys[j].line
	})

	seen := map[string]bool{}
	for _, k := range keys {
		id := k.kind + "\x00" + k.name
		if seen[id] {
			continue
		}
		seen[id] = true

		switch k.kind {
		case "аннотация":
			domain, _, hasDomain := strings.Cut(k.name, "/")
			if !hasDomain || domain == productKeyDomain || standardDomain(domain) {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"  %s:%d — ключ аннотации %q объявлен доменом %q, а не доменом продукта (%q). "+
					"Оператор чужого облака читает этот ключ дословно (`kubectl describe pod`): "+
					"на витрине стоит чужой бренд. Назовите ключ своим доменом.",
				k.file, k.line, k.name, domain, productKeyDomain))
		case "значения":
			if len(k.scope) > 0 {
				// Ключ выборки ищется в СВОЁМ поддереве: судить его словарём
				// верхнего уровня значило бы принять совпадение имён за
				// объявление.
				if declaredIn(k.scope, k.name) {
					continue
				}
			} else if declared[k.name] {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"  %s:%d — ключ значений %q (%s%s) не объявлен в %s. Ключ, которого нет ни в одном "+
					"профиле чарта, оператор не может ни найти, ни задать: он приходит СНАРУЖИ, из "+
					"чужой накладки, а в отдельной поставке производителя не имеет вовсе — величина "+
					"у него всегда одна и та же заглушка. Объявите ключ этим чартом либо снимите "+
					"полосу целиком.",
				k.file, k.line, k.name, k.form, scopeSuffix(k.scope), chartDefaultsFile))
		}
	}

	return findings, c.String(), nil
}

// scopeSuffix — область выборки в тексте находки. Без неё координата называет
// ключ, но не место, где его искали.
func scopeSuffix(scope []string) string {
	if len(scope) == 0 {
		return ""
	}
	return " внутри .Values." + strings.Join(scope, ".")
}

// standardDomain — домен, объявленный платформой контейнеров, а не продуктом.
func standardDomain(domain string) bool {
	for _, d := range standardKeyDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func TestOperatorKeysCarryNoForeignPrefix(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	findings, census, err := auditOperatorKeyPrefixes(chartDir)
	if err != nil {
		t.Fatalf("обход не состоялся: %v", err)
	}
	t.Logf("перепись: %s · находок %d", census, len(findings))

	if len(findings) != 0 {
		t.Fatalf("ключи витрины оператора называют чужое:\n%s", strings.Join(findings, "\n"))
	}
}
