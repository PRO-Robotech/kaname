// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// foreign_object_defaults_test.go — БАЗОВЫЕ ЗНАЧЕНИЯ ЧАРТА НЕ НАЗЫВАЮТ ОБЪЕКТ,
// КОТОРОГО ЧАРТ НЕ СОЗДАЁТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Здесь стояли имена нашего зонтичного релиза — `db.host` и
// `db.passwordSecretName` оба несли `kacho-umbrella-pg-iam`. Дефектов было два,
// и второй хуже первого:
//
//  1. чужой бренд на витрине оператора: имя объекта первое, что арендатор видит
//     при установке;
//  2. умолчание, которое ВСЕГДА НЕПУСТО и ведёт в никуда. Настройка выглядит
//     заданной, потому что значение есть, и не работает, потому что значение
//     наше. Ни один профиль не обязан ничего задавать, чтобы это заметить, —
//     отказ приходит уже в кластере: `secret "kacho-umbrella-pg-iam" not found`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ПРОБА СУДИТ И ЧЕГО НЕ СУДИТ — граница названа первой
//
// Она ДЕКЛАРАТИВНА: читает объявления — базовые значения и ТЕКСТ шаблонов, — а
// не отрендеренный вывод. Рендер требует helm и потому может пропуститься;
// объявление читается всегда.
//
// Она судит ТОЛЬКО `values.yaml` — то, что применяется, когда оператор не сказал
// ничего. Профиль (`values.prod.yaml`, `values.dev.yaml`) назвать такое имя не
// просто вправе, а ОБЯЗАН: он выбирается явно, читается тем, кто ставит, и
// именно там координата чужого кластера объявляется. Требовать пустоты и от
// профилей значило бы запретить единственное законное место для этих величин.
//
// Она НЕ судит посадку безопасности: её судит страж старта процесса
// (`Config.Validate`) со своим перечнем, и проба профиля рядом (`prod_profile_test.go`)
// спрашивает вердикт у него самого.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОПУЛЯЦИЯ ВЫВОДИТСЯ, А НЕ ВЫПИСЫВАЕТСЯ
//
// Выписанный перечень ключей разошёлся бы с шаблоном МОЛЧА: новая ссылка на
// секрет появляется коммитом в шаблон, перечень о ней не знает и остаётся
// зелёным. Поэтому позиции ссылки на объект (`secretName:`, `name:`/`key:` под
// `secretKeyRef:`, `name:` под `configMap:`) находятся в тексте шаблонов, а
// псевдонимы (`$tls := .Values.tls`, `range $k, $v := .Values.secrets`)
// разрешаются до путей значений. Класс шире экземпляра: новая ссылка входит в
// популяцию сама.
//
// ЗАКОННЫЙ БЛИЗНЕЦ ОТЛИЧАЕТСЯ ЗНАЧЕНИЕМ, А НЕ ПОЗИЦИЕЙ. Ссылка на объект,
// который чарт СОЗДАЁТ САМ (том из `<name>-config`), стоит в такой же позиции и
// нарушением не является. Поэтому множество созданных имён тоже ВЫВОДИТСЯ — из
// `metadata.name` самих шаблонов, — и непустое умолчание, попавшее в него,
// молчит. Проба, судящая по позиции, краснела бы на верном чарте.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// chartDefaultsFile — единственный профиль, который применяется, когда оператор
// не сказал ничего. Предмет пробы — он.
const chartDefaultsFile = "values.yaml"

// templatesDir — каталог шаблонов чарта относительно пакета.
const templatesDir = "templates"

// helpersFile — файл именованных шаблонов. Объектов он не рендерит (это
// утверждается предпосылкой ниже), поэтому позиции ссылки в нём не ищутся: его
// текст несёт ПРОЗУ об этих же ключах, и распознаватель, читающий её как
// объявление, краснел бы на собственном объяснении.
const helpersFile = "_helpers.tpl"

// valuesRefRe — ссылка на значение чарта: `.Values.db.passwordSecretName`.
var valuesRefRe = regexp.MustCompile(`\.Values\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)`)

// aliasRefRe — ссылка через псевдоним шаблона: `$tls.secretName`, `$v.secretKey`.
var aliasRefRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)((?:\.[A-Za-z0-9_]+)+)`)

// aliasAssignRe — объявление псевдонима: `$tls := .Values.tls`.
var aliasAssignRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*\.Values\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)`)

// rangeAssignRe — обход карты: `range $k, $v := .Values.secrets`. Элемент карты
// адресуется путём `<карта>.*`, и звёздочка раскрывается по фактическим ключам
// базовых значений.
var rangeAssignRe = regexp.MustCompile(`range\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*\.Values\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)`)

// actionRe — одно действие шаблона целиком: `{{ .Values.name }}`.
var actionRe = regexp.MustCompile(`\{\{-?\s*(.*?)\s*-?\}\}`)

// objectRef — одна найденная позиция ссылки на объект.
type objectRef struct {
	file string
	line int
	path string // путь в дереве значений; пусто — ссылка не через значения
	expr string // текст строки, как он стоит в шаблоне
	kind string // чем позиция опознана
}

// indentOf — глубина отступа строки. Ею опознаётся вложенность блока: шаблоны
// чарта — YAML, и вложенность в них выражена отступом.
func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// resolveRefs — пути значений, на которые ссылается строка шаблона, с учётом
// псевдонимов. Возвращает пути в форме дерева значений (`secrets.*.secretName`).
func resolveRefs(line string, aliases map[string]string) []string {
	var out []string
	for _, m := range valuesRefRe.FindAllStringSubmatch(line, -1) {
		out = append(out, m[1])
	}
	for _, m := range aliasRefRe.FindAllStringSubmatch(line, -1) {
		base, ok := aliases["$"+m[1]]
		if !ok {
			continue
		}
		out = append(out, base+m[2])
	}
	return out
}

// collectObjectRefs — позиции ссылки на объект во ВСЕХ шаблонах чарта, плюс
// перепись осмотренного.
//
// Позиций три вида, и каждый назван, потому что распознаватель обязан знать все
// законные формы записи предмета: форма, о которой он не знает, не даёт ни
// красного, ни зелёного — она молчит.
func collectObjectRefs(t *testing.T) (refs []objectRef, filesRead, linesRead int, createdExprs []string) {
	t.Helper()

	entries, err := os.ReadDir(templatesDir)
	require.NoError(t, err, "каталог шаблонов не читается: %s", templatesDir)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(templatesDir, name))
		require.NoError(t, err, "шаблон не читается: %s", name)
		text := string(raw)

		if name == helpersFile {
			// ПРЕДПОСЫЛКА, А НЕ ДОПУЩЕНИЕ: файл именованных шаблонов пропускается
			// только пока он не рендерит объектов. Заведут в нём ресурс — проба
			// скажет об этом, вместо того чтобы молча его не осмотреть.
			require.NotContains(t, text, "\nkind:",
				"%s объявляет ресурс — он больше не только именованные шаблоны, и его позиции ссылки перестали осматриваться", name)
			continue
		}

		filesRead++
		lines := strings.Split(text, "\n")
		linesRead += len(lines)

		aliases := map[string]string{}
		// blockStack — открытые именованные блоки: отступ и имя.
		type block struct {
			indent int
			name   string
		}
		var stack []block

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			for _, m := range aliasAssignRe.FindAllStringSubmatch(line, -1) {
				aliases["$"+m[1]] = m[2]
			}
			for _, m := range rangeAssignRe.FindAllStringSubmatch(line, -1) {
				aliases["$"+m[2]] = m[3] + ".*"
			}

			ind := indentOf(line)
			for len(stack) > 0 && ind <= stack[len(stack)-1].indent {
				stack = stack[:len(stack)-1]
			}

			key := ""
			if idx := strings.Index(trimmed, ":"); idx > 0 {
				key = strings.TrimLeft(strings.TrimSpace(trimmed[:idx]), "- ")
			}
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].name
			}

			switch {
			case key == "secretName":
				for _, p := range resolveRefs(line, aliases) {
					refs = append(refs, objectRef{name, i + 1, p, trimmed, "secretName"})
				}
			case parent == "secretKeyRef" && (key == "name" || key == "key"):
				for _, p := range resolveRefs(line, aliases) {
					refs = append(refs, objectRef{name, i + 1, p, trimmed, "secretKeyRef." + key})
				}
			case parent == "configMap" && key == "name":
				for _, p := range resolveRefs(line, aliases) {
					refs = append(refs, objectRef{name, i + 1, p, trimmed, "configMap.name"})
				}
			case parent == "metadata" && key == "name":
				createdExprs = append(createdExprs,
					strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:]))
			}

			if key != "" && strings.HasSuffix(trimmed, ":") {
				stack = append(stack, block{ind, key})
			}
		}
	}
	return refs, filesRead, linesRead, createdExprs
}

// leafAt — значение базовых значений по точечному пути. Второй результат
// говорит, объявлен ли ключ вовсе.
func leafAt(values map[string]any, path string) (any, bool) {
	var cur any = values
	for _, seg := range strings.Split(path, ".") {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = asMap[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// expandStar — раскрытие пути с `*` по фактическим ключам базовых значений.
// Карта пуста — путей ноль, и это верно: умолчаний, которые могли бы назвать
// чужой объект, в ней нет.
func expandStar(values map[string]any, path string) []string {
	idx := strings.Index(path, ".*")
	if idx < 0 {
		return []string{path}
	}
	head, tail := path[:idx], path[idx+2:]
	node, ok := leafAt(values, head)
	if !ok {
		return nil
	}
	asMap, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(asMap))
	for k := range asMap {
		keys = append(keys, fmt.Sprintf("%s.%v%s", head, k, tail))
	}
	sort.Strings(keys)
	return keys
}

// renderNameExpr — имя объекта, которое чарт создаёт, вычисленное из выражения
// шаблона на базовых значениях.
//
// Форм всего две, и обе названы; выражение иной формы роняет прогон, а не
// пропускается молча: непрочитанное выражение сделало бы множество созданных
// имён УЖЕ действительного, и законный близнец стал бы находкой.
func renderNameExpr(t *testing.T, values map[string]any, file, expr string) string {
	t.Helper()
	out := actionRe.ReplaceAllStringFunc(expr, func(action string) string {
		inner := actionRe.FindStringSubmatch(action)[1]
		if i := strings.Index(inner, "|"); i >= 0 {
			inner = strings.TrimSpace(inner[:i])
		}
		m := valuesRefRe.FindStringSubmatch(inner)
		require.NotNil(t, m,
			"%s: выражение имени %q не разбирается — распознаватель не знает этой формы, и множество созданных чартом имён вышло бы уже действительного", file, expr)
		v, ok := leafAt(values, m[1])
		require.True(t, ok, "%s: выражение имени ссылается на необъявленный ключ %s", file, m[1])
		return fmt.Sprintf("%v", v)
	})
	return strings.Trim(strings.TrimSpace(out), `"`)
}

// TestChartDefaultsNameNoObjectTheChartDoesNotCreate — отрицание: ни одно
// базовое значение чарта не называет объект, которого чарт не создаёт.
//
// Рядом стоит положительный контроль: множество созданных чартом имён обязано
// быть непустым, а популяция позиций — тоже. Без него отрицание зеленело бы на
// чарте без единой ссылки, то есть на пустом обходе.
func TestChartDefaultsNameNoObjectTheChartDoesNotCreate(t *testing.T) {
	raw, err := os.ReadFile(chartDefaultsFile)
	require.NoError(t, err, "базовые значения не читаются: %s", chartDefaultsFile)

	var values map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &values), "базовые значения не разбираются")
	require.NotEmpty(t, values, "обход пуст: базовые значения пусты — вердикт беспредметен")

	refs, filesRead, linesRead, createdExprs := collectObjectRefs(t)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Пустая популяция и пустое множество созданных имён
	// делают отрицание вакуумным: оно зеленеет, ничего не прочитав.
	require.NotEmpty(t, refs, "обход пуст: позиций ссылки на объект не найдено ни одной — вердикт беспредметен")
	require.NotEmpty(t, createdExprs, "обход пуст: чарт не объявляет ни одного `metadata.name` — множество созданных им имён пусто, и всякая ссылка читалась бы чужой")

	created := map[string]bool{}
	createdList := make([]string, 0, len(createdExprs))
	for _, expr := range createdExprs {
		name := renderNameExpr(t, values, "templates", expr)
		if !created[name] {
			created[name] = true
			createdList = append(createdList, name)
		}
	}
	sort.Strings(createdList)

	// ПРЕДПОСЫЛКА АДРЕСА БАЗЫ. Адрес узла не стоит в позиции ссылки на объект: его
	// склеивает `printf` в строку подключения, поэтому по позиции он не находится
	// и добавляется явно. Предпосылка проверяется, а не подразумевается: перестанет
	// шаблон собирать адрес из этого ключа — проба скажет об этом, вместо того
	// чтобы стеречь ключ, у которого больше нет читателя.
	cm, err := os.ReadFile(filepath.Join(templatesDir, "configmap.yaml"))
	require.NoError(t, err, "шаблон настроек не читается")
	require.Contains(t, string(cm), "postgres://",
		"шаблон настроек больше не собирает строку подключения — предпосылка ключа db.host отпала")
	require.Contains(t, string(cm), ".Values.db.host",
		"шаблон настроек больше не читает db.host — стеречь этот ключ не за чем")
	refs = append(refs, objectRef{"configmap.yaml", 0, "db.host", "printf \"postgres://…\" … .Values.db.host …", "dsn.host"})

	// Популяция путей: раскрытая, упорядоченная, без повторов.
	seen := map[string]objectRef{}
	for _, r := range refs {
		if r.path == "" {
			continue
		}
		for _, p := range expandStar(values, r.path) {
			if _, dup := seen[p]; !dup {
				seen[p] = r
			}
		}
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	require.NotEmpty(t, paths, "обход пуст: путей значений в позициях ссылки не выведено ни одного — вердикт беспредметен")

	var findings []string
	for _, p := range paths {
		v, declared := leafAt(values, p)
		if !declared {
			continue
		}
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s == "" || s == "<nil>" {
			continue
		}
		if created[s] {
			// ЗАКОННЫЙ БЛИЗНЕЦ: умолчание называет объект, который чарт создаёт
			// сам. Позиция та же, нарушения нет.
			continue
		}
		r := seen[p]
		findings = append(findings, fmt.Sprintf(
			"  %s = %q — %s:%d (%s): объект с таким именем чарт НЕ СОЗДАЁТ, а умолчание у него непусто, "+
				"поэтому установка выглядит настроенной и отказывает уже в кластере. Снимите умолчание "+
				"(пустая строка) и назовите координату в профиле — %s", p, s, r.file, r.line, r.kind, "values.prod.yaml"))
	}

	t.Logf("перепись: шаблонов прочитано %d · строк %d · позиций ссылки на объект %d · путей значений %d · "+
		"имён, создаваемых чартом %d (%s) · находок %d",
		filesRead, linesRead, len(refs), len(paths), len(createdList), strings.Join(createdList, ", "), len(findings))

	require.Empty(t, findings, "базовые значения чарта называют объекты, которых он не создаёт:\n%s",
		strings.Join(findings, "\n"))
}
