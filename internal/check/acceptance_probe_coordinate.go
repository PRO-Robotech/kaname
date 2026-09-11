// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_probe_coordinate.go — гейт: имя пробы, названное приёмкой
// КООРДИНАТОЙ, резолвится функцией в дереве.
//
// Порт с монорепо (`internal/repohygiene/acceptanceprobecoordinate.go`, снят
// вынесением службы — `kacho#2597`). До этой правки держатель
// (`TestAcceptanceProbeCoordinateResolves`) не существовал ни в одном файле, а
// восемь живых приёмок службы (`roles-come-as-data-not-migrations.md`,
// `model-block-prose-has-a-home.md`, `model-generated-from-manifest.md`,
// `classes-form-of-role-right.md`, `retire-tenant-condition-surface.md`,
// `system-role-segments-resolve.md`, `module-manifest-resources-roles-deprecated.md`,
// `module-manifest-roles-and-seed-grants.md`) продолжали называть его своим.
//
// # Предмет
//
// Приёмка ссылается на пробу, чтобы читатель мог её открыть и прогнать. Проба
// переживает не всякую правку: её переименовывают, сводят с соседней, снимают
// вместе с предметом — и делают это в СВОЁМ изменении, которое чужой приёмки
// не касается. Тогда координата остаётся стоять, а функции за ней нет.
//
// Класс — утверждение, пережившее свой предмет, и он опаснее обычной
// устаревшей строки: следующий идёт по названному адресу, не находит ничего и
// делает вывод О ДЕРЕВЕ, а не о документе.
//
// # Почему координатой считается ТОЛЬКО целый пролёт кода
//
// Имя пробы встречается в приёмке в трёх видах, и лишь один из них — координата:
//
//	`TestFoo`                            — КООРДИНАТА: пролёт целиком есть имя
//	`go test -run '^TestFoo$' -count=1`  — предикат: имя стоит внутри команды
//	«проба TestFoo снята вместе с предметом» — проза разбора
//
// Проверка по подстроке краснела бы на втором и третьем, то есть на
// СОБСТВЕННОМ объяснении документа. Поэтому документ читается РАЗОБРАННЫМ:
// огороженные блоки кода пропускаются целиком, а из строки берутся только
// пролёты `…`, чьё содержимое ЦЕЛИКОМ есть имя пробы.
//
// # Почему резолв по ПРЕФИКСУ, а не по равенству
//
// Корпус называет пробу двумя законными формами: полным именем и
// ИДЕНТИФИКАТОРОМ СЦЕНАРИЯ (`TestIAMCT112`), которым отбирают семейство —
// `-run '^TestIAMCT112'`. Отсюда правило: координата резолвится, если
// ОБЪЯВЛЕННОЕ имя начинается с неё. Направление существенно:
// `TestFoo‹хвост›` → `TestFoo` этим правилом не прощается — объявленное короче
// координаты и её префиксом не является.
package check

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// ProbeCoordinateShape — форма имени пробы Go. Три знака минимум после вида:
// голое `Test` резолвилось бы префиксом ко всему дереву.
var ProbeCoordinateShape = regexp.MustCompile(`^(Test|Fuzz|Benchmark|Example)[A-Za-z0-9_]{2,}$`)

var (
	probeCoordinateFence  = regexp.MustCompile("^\\s*(```|~~~)")
	probeCoordinateInline = regexp.MustCompile("`([^`\n]+)`")
	probeCoordinateDecl   = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark|Example)[A-Za-z0-9_]*)\s*\(`)
)

// ProbeCoordinate — одно вхождение координаты: имя и место, где оно стоит.
type ProbeCoordinate struct {
	Name string
	Doc  string
	Line int
}

// DeadProbeCoordinate — ПОСЛАБЛЕНИЕ: координата, о которой известно, что она
// не резолвится, и чей предмет принадлежит ДРУГОМУ кругу приёмки.
//
// Запись заводится ПО ФАКТУ, а не с запасом. Послабление ИСТЕКАЕТ САМО, и оба
// конца — находка: имя стало резолвиться → исключать нечего; имя больше не
// стоит ни в одном документе → исключать нечего.
type DeadProbeCoordinate struct {
	Name  string
	Docs  []string
	Issue int
	Note  string
}

// AcceptanceProbeCoordinateExemptions — ВЕДОМОСТЬ ПУСТА, и это её цель, а не
// её поломка. Заводя запись — назови номер задачи и предикат снятия в
// комментарии рядом.
var AcceptanceProbeCoordinateExemptions []DeadProbeCoordinate

// ProbeCoordinatesIn разбирает документ и возвращает координаты — только их.
func ProbeCoordinatesIn(doc, body string) []ProbeCoordinate {
	var found []ProbeCoordinate
	inFence := false
	for i, line := range strings.Split(body, "\n") {
		if probeCoordinateFence.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range probeCoordinateInline.FindAllStringSubmatch(line, -1) {
			// `TestFoo/подпроба` — координата семейства; судится основание.
			name := strings.TrimSpace(m[1])
			if idx := strings.IndexByte(name, '/'); idx >= 0 {
				name = name[:idx]
			}
			if !ProbeCoordinateShape.MatchString(name) {
				continue
			}
			found = append(found, ProbeCoordinate{Name: name, Doc: doc, Line: i + 1})
		}
	}
	return found
}

// ProbeCoordinateResolves — объявленное имя начинается с координаты. declared
// обязан быть отсортирован: имя с префиксом P сортируется не раньше P, поэтому
// кандидат ровно один и находится двоичным поиском.
func ProbeCoordinateResolves(name string, declared []string) bool {
	i := sort.SearchStrings(declared, name)
	return i < len(declared) && strings.HasPrefix(declared[i], name)
}

// ProbeCoordinateCensus — перепись обхода. «Ноль находок» обязано быть
// отличимо от «ноль прочитанного», поэтому объём осмотренного — отдельное
// утверждение.
type ProbeCoordinateCensus struct {
	Docs        int
	Declared    int
	Coordinates int
	Resolved    int
	Exempted    int
	Findings    []string
}

// JudgeProbeCoordinates — судящее ядро. Вход подаётся значениями, а не
// читается из дерева: инъекция обязана уметь дать ему свой вход, не трогая
// рабочую копию, из которой запущена.
func JudgeProbeCoordinates(docs map[string]string, declared []string, exemptions []DeadProbeCoordinate) ProbeCoordinateCensus {
	sorted := append([]string(nil), declared...)
	sort.Strings(sorted)

	exempt := make(map[string]*DeadProbeCoordinate, len(exemptions))
	for i := range exemptions {
		exempt[exemptions[i].Name] = &exemptions[i]
	}
	used := make(map[string]bool, len(exemptions))

	c := ProbeCoordinateCensus{Docs: len(docs), Declared: len(sorted)}

	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		for _, co := range ProbeCoordinatesIn(p, docs[p]) {
			c.Coordinates++
			if ProbeCoordinateResolves(co.Name, sorted) {
				c.Resolved++
				continue
			}
			if e, ok := exempt[co.Name]; ok {
				c.Exempted++
				used[e.Name] = true
				continue
			}
			c.Findings = append(c.Findings, "МЁРТВАЯ КООРДИНАТА "+co.Doc+":"+strconv.Itoa(co.Line)+
				" — приёмка называет пробу `"+co.Name+"`, а функции, чьё имя с неё начинается, "+
				"в дереве НЕТ. Исходов три: назвать преемницу — но только прочитав ЕЁ ТЕЛО, "+
				"потому что живой адрес с ложным содержанием хуже мёртвого: он не краснеет; "+
				"снять координату, написав имя ПРОЗОЙ, — если проба снята вместе с предметом "+
				"либо преемница утверждает ДРУГОЕ (свидетельство круга остаётся, живого адреса "+
				"не заводится); либо — когда правка сделала бы вердикт круга непрослеживаемым — "+
				"завести запись послабления с номером задачи и предикатом снятия")
		}
	}

	// Второй конец самоистечения: послабление, которому нечего исключать.
	for _, e := range exemptions {
		if used[e.Name] {
			continue
		}
		why := "имя больше не стоит ни в одной приёмке"
		if ProbeCoordinateResolves(e.Name, sorted) {
			why = "имя снова резолвится функцией в дереве"
		}
		c.Findings = append(c.Findings, "ПОСЛАБЛЕНИЕ БЕЗ ПРЕДМЕТА `"+e.Name+"` — "+why+
			". Запись снимается тем же изменением: послабление, которому нечего исключать, "+
			"достаётся следующему читателю и прощает уже другое")
	}
	return c
}

// AcceptanceDocsOfTree — приёмки, живущие в каталоге приёмок службы. Перечень
// ВЫВОДИТСЯ обходом, а не выписывается.
//
// Порт сужен до posture этого дерева: монорепо держало приёмки НЕСКОЛЬКИХ
// служб под `services/*/docs/engineering/acceptance/`, а самостоятельный клон
// службы несёт СВОЙ единственный каталог прямо у корня —
// `docs/engineering/acceptance/`. Сужение измерено, а не предположено: в
// дереве продукта второго дома приёмок не было никогда (`polyrepo.md`
// §«У приёмки домов ДВА» — второй дом был именно этот, iam-only).
func AcceptanceDocsOfTree(root string) (map[string]string, error) {
	dir := filepath.Join(root, "docs", "engineering", "acceptance")
	all, err := treecorpus.UnderWithSuffix(dir, ".md")
	if err != nil {
		return nil, err
	}
	docs := make(map[string]string, len(all))
	for _, abs := range all {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			return nil, rerr
		}
		body, rerr := os.ReadFile(abs)
		if rerr != nil {
			return nil, rerr
		}
		docs[filepath.ToSlash(rel)] = string(body)
	}
	return docs, nil
}

// DeclaredProbesOfTree — имена всех проб дерева, объявленных в отслеживаемых
// файлах проб.
func DeclaredProbesOfTree(root string) ([]string, error) {
	all, err := treecorpus.UnderWithSuffix(root, "_test.go")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, abs := range all {
		body, rerr := os.ReadFile(abs)
		if rerr != nil {
			return nil, rerr
		}
		for _, m := range probeCoordinateDecl.FindAllStringSubmatch(string(body), -1) {
			seen[m[1]] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
