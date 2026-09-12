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
//
// # НАЗВАННЫЙ ДОМ: чужой репозиторий — вне суждения, но НЕ прощён
//
// Служба вынесена из монорепо (`kacho#2598`), и приёмки уехали вместе с ней, а
// гейты дерева остались там, где судят своё дерево. Отсюда третья форма записи
// координаты:
//
//	`TestFoo`                              — координата ЭТОГО дерева, судится;
//	`PRO-Robotech/kacho:TestFoo`           — координата ЧУЖОГО дома;
//	`PRO-Robotech/kacho@d941344bd9:TestFoo` — чужой дом, связанный ревизией.
//
// Чужой дом ВНЕ суждения по построению: ни подтвердить, ни опровергнуть
// объявление функции в чужом репозитории этот гейт не может — дерева рядом нет,
// а сеть в прогоне гейта запрещена. Доктрина в дереве уже есть и здесь не
// заводится второй раз: `carried_coordinate_ledger.go` §«Кросс-репо координата —
// вне суждения ОБОИХ сторон».
//
// «Вне суждения» отличается от «прощено» ДВУМЯ свойствами, и оба обязательны:
//
//  1. чужая координата СЧИТАЕТСЯ, а её дома ПЕЧАТАЮТСЯ переписью. Дом, стоящий
//     в корпусе один раз, тем самым виден — опечатка в имени репозитория не
//     уходит молча;
//  2. приставка, домом НЕ являющаяся (`kacho:TestFoo`, `IAM-MV-04:TestFoo`), —
//     НАХОДКА. Без этого любой не-разобранный префикс снимал бы координату с
//     суждения, и приставка стала бы способом спрятать адрес, а не назвать дом.
//
// Замер перед введением формы: пролётов вида `<что-то>:<имя-пробы>` в корпусе
// приёмок — НОЛЬ в обе стороны (и разобранных домом, и не разобранных), то есть
// правило 2 не краснеет ни на одной существующей строке.
package check

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// ProbeCoordinateShape — форма имени пробы Go. Три знака минимум после вида:
// голое `Test` резолвилось бы префиксом ко всему дереву.
var ProbeCoordinateShape = regexp.MustCompile(`^(Test|Fuzz|Benchmark|Example)[A-Za-z0-9_]{2,}$`)

// ProbeCoordinateHomeShape — форма НАЗВАННОГО ДОМА: `<владелец>/<репозиторий>`
// и, необязательно, `@<ревизия>`. Ревизия — только шестнадцатеричная и не короче
// семи знаков: короткая или произвольная строка после `@` сделала бы домом любую
// опечатку.
var ProbeCoordinateHomeShape = regexp.MustCompile(
	`^([A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:@([0-9a-fA-F]{7,40}))?$`)

var (
	probeCoordinateFence  = regexp.MustCompile("^\\s*(```|~~~)")
	probeCoordinateInline = regexp.MustCompile("`([^`\n]+)`")
	probeCoordinateDecl   = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark|Example)[A-Za-z0-9_]*)\s*\(`)
)

// ProbeCoordinate — одно вхождение координаты: имя, дом и место, где оно стоит.
type ProbeCoordinate struct {
	Name string
	// Home — названный дом `владелец/репозиторий`. Пусто — дом ЭТО дерево.
	Home string
	// Rev — ревизия названного дома, если названа.
	Rev string
	// Span — пролёт, как он стоит в документе. Нужен находке: без него читатель
	// не найдёт строку, у которой имя пробы лишь хвост.
	Span string
	// HomeMalformed — приставка есть, а домом она не является.
	HomeMalformed bool
	Doc           string
	Line          int
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
	for lineNo, line := range strings.Split(body, "\n") {
		if probeCoordinateFence.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range probeCoordinateInline.FindAllStringSubmatch(line, -1) {
			co, ok := probeCoordinateOf(strings.TrimSpace(m[1]))
			if !ok {
				continue
			}
			co.Doc, co.Line = doc, lineNo+1
			found = append(found, co)
		}
	}
	return found
}

// probeCoordinateOf разбирает ОДИН пролёт. Дом отделяется по ПОСЛЕДНЕМУ
// двоеточию: путь с номером строки (`…/acceptanceledger_test.go:116`) несёт
// двоеточие штатно, и отделение по первому сделало бы домом кусок пути.
func probeCoordinateOf(span string) (ProbeCoordinate, bool) {
	head, name := "", span
	if i := strings.LastIndexByte(span, ':'); i >= 0 {
		head, name = strings.TrimSpace(span[:i]), strings.TrimSpace(span[i+1:])
	}
	// `TestFoo/подпроба` — координата семейства; судится основание.
	if idx := strings.IndexByte(name, '/'); idx >= 0 {
		name = name[:idx]
	}
	if !ProbeCoordinateShape.MatchString(name) {
		return ProbeCoordinate{}, false
	}
	co := ProbeCoordinate{Name: name, Span: span}
	if head == "" {
		return co, true
	}
	m := ProbeCoordinateHomeShape.FindStringSubmatch(head)
	if m == nil {
		co.HomeMalformed = true
		return co, true
	}
	co.Home, co.Rev = m[1], m[2]
	return co, true
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
	// Foreign — координаты, назвавшие ЧУЖОЙ дом: вне суждения, но в переписи.
	Foreign int
	// ForeignHomes — различные названные дома, по алфавиту. Печатаются, чтобы дом,
	// стоящий в корпусе один раз, был виден: опечатка в имени репозитория иначе
	// уходит молча.
	ForeignHomes []string
	Findings     []string
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
	homes := map[string]bool{}

	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		for _, co := range ProbeCoordinatesIn(p, docs[p]) {
			c.Coordinates++
			if co.HomeMalformed {
				c.Findings = append(c.Findings, "ДОМ НАЗВАН НЕ ДОМОМ "+co.Doc+":"+
					strconv.Itoa(co.Line)+" — пролёт `"+co.Span+"` несёт приставку, "+
					"которая репозиторием не является. Приставка снимает координату с "+
					"суждения, поэтому её форма закрыта: `владелец/репозиторий:Имя` "+
					"либо `владелец/репозиторий@ревизия:Имя` (ревизия — hex, не короче "+
					"семи знаков). Иначе любой префикс прячет адрес вместо того, чтобы "+
					"назвать дом")
				continue
			}
			if co.Home != "" {
				c.Foreign++
				homes[co.Home] = true
				continue
			}
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
				"в дереве НЕТ. Исходов четыре. Назвать ДОМ, если держатель жив, но живёт в "+
				"другом репозитории: `владелец/репозиторий:"+co.Name+"` — такая координата "+
				"вне суждения этого гейта и попадает в перепись чужих домов. Остальные три: "+
				"назвать преемницу — но только прочитав ЕЁ ТЕЛО, "+
				"потому что живой адрес с ложным содержанием хуже мёртвого: он не краснеет; "+
				"снять координату, написав имя ПРОЗОЙ, — если проба снята вместе с предметом "+
				"либо преемница утверждает ДРУГОЕ (свидетельство круга остаётся, живого адреса "+
				"не заводится); либо — когда правка сделала бы вердикт круга непрослеживаемым — "+
				"завести запись послабления с номером задачи и предикатом снятия")
		}
	}

	c.ForeignHomes = make([]string, 0, len(homes))
	for h := range homes {
		c.ForeignHomes = append(c.ForeignHomes, h)
	}
	sort.Strings(c.ForeignHomes)

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

// OwnHomeOfTree — дом ЭТОГО дерева в форме `владелец/репозиторий`, выведенный из
// пути модуля в `go.mod`.
//
// Нужен НЕ ядру, а гейту: ядро судит поданные значения и про дома знает только
// то, что дом непустой — чужой. Свой дом, названный в приёмке чужим, ядру
// неотличим от настоящего чужого, и именно эту дыру закрывает сторожевая ось
// гейта — она сверяет перепись домов с этим значением.
//
// Путь модуля берётся у `go.mod`, а не собирается литералом: литерал разошёлся бы
// с переименованием репозитория молча.
func OwnHomeOfTree(root string) (string, error) {
	body, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- корень своего дерева
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module ")
		if !ok {
			continue
		}
		seg := strings.Split(strings.TrimSpace(rest), "/")
		if len(seg) < 3 {
			return "", fmt.Errorf("путь модуля %q короче трёх сегментов: дом из него не "+
				"выводится", strings.TrimSpace(rest))
		}
		return strings.Join(seg[len(seg)-2:], "/"), nil
	}
	return "", fmt.Errorf("в %s/go.mod нет строки module: дом дерева не назван", root)
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
