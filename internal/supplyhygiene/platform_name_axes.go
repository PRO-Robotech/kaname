// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_name_axes.go — судья ПЕРЕПИСИ ОСЕЙ: у каждой оси условия «имя
// платформы не остаётся на поверхности службы» назван её держатель в ЭТОМ
// дереве, а ось без держателя держится точным числом остатка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПЕРЕПИСЬ ОСЕЙ, А НЕ ПЕРЕНОС СВОДНОГО ДЕРЖАТЕЛЯ ПЛАТФОРМЫ
//
// Условие П3 предиката готовности (kacho#2076, редакция C) держал сводный
// держатель в дереве платформы. С выносом службы (kacho#2598) он дерева службы
// НЕ ОБХОДИТ: его поверхность — подчарт зонта, наложения значений и контракт,
// приехавший модулем по пину. Его зелёный прогон о дереве службы не говорит
// ничего — даже того, что остаток здесь не вырос.
//
// Перенос отвергнут по трём причинам, каждая измерена:
//
//  1. мир держателя принадлежит платформе: наложения зонта, владелец имён частей
//     продукта, резолв контракта модулем. В этом дереве ни одного из трёх нет;
//  2. поверхностью здесь было бы дерево ЦЕЛИКОМ: 1027 файлов из 3073 несут имя
//     платформы (4500 вхождений обычной формой и 120 диакритической, `6e9b94ab`),
//     и большая их часть — ссылки на задачи трекера, записи замеров в одобренных
//     приёмках и имена соседей. Ведомость решённого остаться пришлось бы собирать
//     заново поимённо, и её истинность проверяет человек, а не прогон;
//  3. держатель платформы обязан остаться: у подчарта и наложений зонта другой
//     владелец и другое дерево. Второй экземпляр того же держателя здесь был бы
//     вторым местом об одном предмете.
//
// Зато у большинства осей в этом дереве УЖЕ есть держатель, и судит он свою ось
// её же семантикой — разбором клейм, рендером ключей, объявлением схемы, — чего
// распознаватель по форме записи не умеет вовсе. Недоставало одного: места, где
// видно, КТО держит каждую ось и что держит ось без держателя.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ
//
// По оси с держателем: держатель ОБЪЯВЛЕН в дереве узлом объявления функции, а не
// упоминанием (имя пробы стоит и в прозе, и в этой переписи — подстрочный разбор
// объявил бы держателя живым по упоминанию о нём), и предмет оси существует.
//
// По оси без держателя: остаток сосчитан ТОЧНО — число вхождений и число файлов.
// Расхождение в любую сторону — находка: вверх — остаток вырос; вниз — перепись
// отстала, и опустить её обязано то же изменение, что остаток снизило. Потолок
// здесь не годится: он не краснеет никогда и прощает вперёд ровно ту находку,
// ради которой ось заведена.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ПЕРЕПИСЬ НЕ СУДИТ — названо, чтобы «зелёная» не читалось шире сделанного
//
//  1. ПОЛНОТУ покрытия оси её держателем. Что держатель судит ровно эту ось, а не
//     её часть, — утверждение человека, записанное строкой оси; перепись
//     проверяет, что держатель есть, а не что он прав;
//  2. вердикт держателя. Он печатается его собственным прогоном, а не здесь:
//     пересказ вердикта был бы вторым местом об одном предмете;
//  3. разбор остатка оси без держателя поимённо. Число включает и то, что снять
//     надо, и то, что снимать нельзя (имя, отрисованное шаблоном фундамента;
//     применённая миграция); строка оси называет состав словами.
package supplyhygiene

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PlatformNameAxis — одна ось условия.
//
// Ровно одно из двух: Holders (держатель в этом дереве) либо Census (точное
// число остатка). Обе пустые и обе заполненные — находка формы.
type PlatformNameAxis struct {
	// Axis — имя оси, как его называет предикат готовности.
	Axis string
	// Holders — имена проб-держателей, объявленных в ЭТОМ дереве.
	Holders []string
	// Judges — что именно судит держатель: узкое утверждение, а не название оси.
	Judges string
	// Subject — координата предмета оси в этом дереве: файл либо каталог.
	Subject string
	// Census — точное число остатка оси без держателя.
	Census *AxisCensus
}

// AxisCensus — перепись остатка оси без держателя.
type AxisCensus struct {
	// Paths — приставки путей, которые обходит перепись. Пробы (`_test.go`)
	// не судятся: они называют имя как предмет своей проверки.
	Paths []string
	// LineHas — если непусто, считаются только строки, несущие хотя бы одну из
	// подстрок (без регистра).
	LineHas []string
	// Token — если задан, считается только вхождение, чей токен ему отвечает.
	Token *regexp.Regexp
	// Occurrences и Files — точные величины остатка.
	Occurrences int
	Files       int
	// Composition — из чего остаток состоит, словами.
	Composition string
	// Owner — чья работа снять остаток.
	Owner string
}

// AxisVerdict — вердикт по одной оси, как его печатает перепись.
type AxisVerdict struct {
	Axis string
	// Held — ось держится держателем, а не числом.
	Held bool
	// Occurrences и Files — фактическая перепись оси без держателя.
	Occurrences int
	Files       int
}

// AxesCensus — объём осмотренного.
type AxesCensus struct {
	// Axes — строк переписи.
	Axes int
	// Held — осей с держателем.
	Held int
	// Counted — осей без держателя, держимых числом.
	Counted int
	// Residue — сумма фактического остатка осей без держателя.
	Residue int
	// Verdicts — по каждой оси, в порядке переписи.
	Verdicts []AxisVerdict
}

// JudgePlatformNameAxes судит перепись осей.
//
// declared — имена функций, ОБЪЯВЛЕННЫХ в дереве; exists — есть ли координата в
// составе дерева; corpus — путь → текст отслеживаемых файлов, по которым
// считается остаток. Все три приходят параметрами: инъекция обязана подать тот
// же судья на синтетике, а не его копию.
func JudgePlatformNameAxes(
	axes []PlatformNameAxis,
	declared map[string]bool,
	exists func(rel string) bool,
	corpus map[string]string,
) (AxesCensus, []string) {
	var (
		census   AxesCensus
		findings []string
		seen     = map[string]bool{}
	)
	census.Axes = len(axes)
	for _, a := range axes {
		switch {
		case strings.TrimSpace(a.Axis) == "":
			findings = append(findings, "строка переписи без имени оси")
			continue
		case seen[a.Axis]:
			findings = append(findings, fmt.Sprintf("ось %q названа дважды: два места об одном "+
				"предмете, и расходится то, которое не считали", a.Axis))
			continue
		}
		seen[a.Axis] = true

		held, counted := len(a.Holders) > 0, a.Census != nil
		if held && counted {
			findings = append(findings, fmt.Sprintf("ось %q: названы и держатель, и число "+
				"остатка — ровно одно из двух, иначе неясно, кто её держит", a.Axis))
			continue
		}
		if !held && !counted {
			findings = append(findings, fmt.Sprintf("ось %q: не названы ни держатель, ни число "+
				"остатка — ось не держится ничем", a.Axis))
			continue
		}
		if strings.TrimSpace(a.Subject) == "" || !exists(a.Subject) {
			findings = append(findings, fmt.Sprintf("ось %q: предмета %q в дереве нет — "+
				"ось перестала быть предметом этого дерева либо координата названа неверно",
				a.Axis, a.Subject))
		}

		if held {
			census.Held++
			census.Verdicts = append(census.Verdicts, AxisVerdict{Axis: a.Axis, Held: true})
			if strings.TrimSpace(a.Judges) == "" {
				findings = append(findings, fmt.Sprintf("ось %q: не сказано, ЧТО судит "+
					"держатель, — «держится» без предмета держания читается шире сделанного",
					a.Axis))
			}
			for _, h := range a.Holders {
				if !declared[h] {
					findings = append(findings, fmt.Sprintf("ось %q: держатель %s не объявлен "+
						"ни одним файлом дерева — ось держится именем, которого нет",
						a.Axis, h))
				}
			}
			continue
		}

		census.Counted++
		c := a.Census
		if strings.TrimSpace(c.Owner) == "" || strings.TrimSpace(c.Composition) == "" {
			findings = append(findings, fmt.Sprintf("ось %q: у остатка не назван владелец "+
				"либо состав — число без них есть отсрочка без ответчика", a.Axis))
		}
		occ, files := countAxisResidue(c, corpus)
		census.Residue += occ
		census.Verdicts = append(census.Verdicts, AxisVerdict{
			Axis: a.Axis, Occurrences: occ, Files: files,
		})
		if occ != c.Occurrences || files != c.Files {
			direction := "вырос"
			if occ < c.Occurrences || (occ == c.Occurrences && files < c.Files) {
				direction = "снизился — перепись отстала, опустите её тем же изменением"
			}
			findings = append(findings, fmt.Sprintf("ось %q: остаток %s: в дереве %d вхождений "+
				"в %d файлах, записано %d в %d", a.Axis, direction, occ, files,
				c.Occurrences, c.Files))
		}
	}
	return census, findings
}

// countAxisResidue — фактический остаток оси без держателя.
func countAxisResidue(c *AxisCensus, corpus map[string]string) (occurrences, files int) {
	paths := make([]string, 0, len(corpus))
	for rel := range corpus {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	for _, rel := range paths {
		if strings.HasSuffix(rel, "_test.go") || !underAny(rel, c.Paths) {
			continue
		}
		n := 0
		lines := strings.Split(corpus[rel], "\n")
		for _, h := range PlatformNameHits(corpus[rel]) {
			if len(c.LineHas) > 0 && !lineHasAny(lines[h.Line-1], c.LineHas) {
				continue
			}
			if c.Token != nil && !c.Token.MatchString(h.Token) {
				continue
			}
			n++
		}
		if n > 0 {
			occurrences += n
			files++
		}
	}
	return occurrences, files
}

func underAny(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if rel == p || strings.HasPrefix(rel, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

func lineHasAny(line string, needles []string) bool {
	low := strings.ToLower(line)
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}
