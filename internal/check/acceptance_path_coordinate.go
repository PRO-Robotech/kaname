// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_path_coordinate.go — гейт: ПУТЬ, названный приёмкой как ПРЕДИКАТ,
// резолвится в дереве службы либо называет свой ДОМ.
//
// Сосед по классу — `acceptance_probe_coordinate.go`: там координата есть ИМЯ
// ПРОБЫ, здесь — ПУТЬ. Предмет один (утверждение, пережившее свой предмет),
// граница разбора — разная, и разница ниже названа целиком, потому что дважды
// она ИНВЕРТИРОВАНА и списать её на небрежность легко.
//
// # Предмет
//
// Приёмка доказывает свои утверждения ПРЕДИКАТОМ — командой, которую читатель
// обязан прогнать сам: `git grep … -- <путь>`. Предикат, чей путь в дереве не
// существует, даёт пустоту НЕ ПОТОМУ, что находок нет, а потому, что читать было
// нечего. «Ноль находок» становится неотличимо от «ноль прочитанного», и
// читатель делает вывод О ДЕРЕВЕ по замеру, который ничего не измерял.
//
// Это тот же класс, что у соседа, но он ТИШЕ. Мёртвое имя пробы обнаруживается
// первым же прогоном (`go test -run` отвечает «no tests to run»). Мёртвый путь
// не отвечает ничем: команда завершается успехом и печатает пустоту — ровно то,
// чего от неё и ждали, когда утверждение было «здесь чисто».
//
// Замер, из которого гейт заведён (`kaname#71`, дерево на `bbd196ea`): путей,
// названных предикатом, — 52, из них не резолвилось **66 вхождений в 16
// документах** по наивному предикату задачи и **192 в 24** по разбору, знающему
// путь-спецификацию в кавычках. Разница — не придирка: она и есть слепая зона
// наивного предиката, а слепая зона проверки не краснеет и не зеленеет.
//
// # ГРАНИЦА РАЗБОРА — названа явно, потому что путь стоит в тексте ТРОЯКО
//
// Один и тот же путь встречается в приёмке в трёх видах, и лишь один из них —
// координата, за которой читатель идёт с командой:
//
//	`git grep -n 'X' -- internal/manifest`   — ПРЕДИКАТ: путь после `--`, СУДИТСЯ
//	`internal/manifest/roles.go:135`         — проза: описание места, НЕ судится
//	`git ls-files 'proto/kacho/cloud/iam/**'` — путь-спец БЕЗ `--`, НЕ судится
//
// ПРОЗА ВНЕ СУЖДЕНИЯ, и это решение, а не недосмотр. Путь в прозе — описание, а
// не адрес для прогона; в корпусе приёмок службы таких вхождений ОДНОГО только
// монорепного корня 992 в 33 документах, и почти все они — исторические
// утверждения о дереве, каким оно было ДО выноса (`kacho#2598`). Судить их
// значило бы требовать переписать свидетельство о прошлом. Число прозаических
// вхождений тем не менее ПЕЧАТАЕТСЯ переписью: слепая зона, которую видно,
// остаток, а не дыра.
//
// ПУТЬ-СПЕЦИФИКАЦИЯ БЕЗ `--` ВНЕ СУЖДЕНИЯ ПО ДРУГОЙ ПРИЧИНЕ, и она несущая: в
// форме `git ls-files <спец>` путь сплошь и рядом есть САМ ПРЕДМЕТ УТВЕРЖДЕНИЯ
// ОБ ОТСУТСТВИИ — «такого корня в дереве нет, → 0». Там нерезолвящийся путь не
// дефект, а ровно то, что доказывают, и находка на нём была бы ложной. Отличить
// «путь мёртв» от «путь назван мёртвым намеренно» можно лишь прочитав НАМЕРЕНИЕ
// соседней прозы, а этого гейт не умеет и обещать не вправе. Замер: в дереве
// таких вхождений 33, из них утверждением об отсутствии — 27. Число печатается.
//
// # ОГОРОЖЕННЫЙ БЛОК КОДА СУДИТСЯ — ИНВЕРСИЯ ОТНОСИТЕЛЬНО СОСЕДА
//
// Сосед пропускает огороженные блоки целиком: имя пробы внутри команды — не
// координата, а часть предиката, и судить его значило бы краснеть на
// собственном объяснении документа.
//
// Здесь наоборот: блок кода — ГЛАВНОЕ место жительства предиката. Приёмка
// выносит команду в блок именно тогда, когда хочет, чтобы её прогнали. Пропусти
// гейт огороженные блоки — и он потерял бы 48 вхождений из 192 (четверть), не
// сказав об этом ничем. Поэтому блок судится, а различение делает не забор, а
// ПОЗИЦИЯ ТОКЕНА: после `--` в строке, несущей `git grep` либо `git ls-files`.
//
// # ПОДСТАНОВОЧНЫЙ ЗНАК: судится ГЛУБОЧАЙШИЙ ПРЕДОК БЕЗ МЕТАСИМВОЛА
//
// `internal/migrations/*.sql` резолвится, если есть КАТАЛОГ `internal/migrations`,
// а не если шаблону что-то соответствует. Различие несущее в обе стороны:
//
//   - шаблон, которому сегодня не соответствует ничто, — ЗАКОННЫЙ вердикт
//     («миграций с такой датой нет»), а не мёртвая координата;
//   - каталог, которого нет, — мёртвая координата, даже когда шаблон выглядит
//     правдоподобно.
//
// Отсюда правило отсечения: берём часть до первого метасимвола и поднимаемся до
// ближайшего `/`. Наивное «часть до звёздочки» ошибается на шаблоне, чей
// метасимвол стоит ВНУТРИ имени файла (`internal/migrations/20260902*`): оно
// объявило бы мёртвым живой каталог. Класс пойман на себе при заведении гейта.
//
// # НАЗВАННЫЙ ДОМ: чужой репозиторий — вне суждения, но НЕ прощён
//
// Форма ВЗЯТА у соседа (`владелец/репозиторий:путь`, необязательно
// `@<ревизия>`), а он взял её у `scripts/docs-gate/check-03-holding-claim-resolves.py`
// воркспейса. Отличие от соседа одно: там дом стоит у ИМЕНИ, здесь — у ПУТИ,
// потому что координата этого гейта и есть путь. Двоеточие не спутать с
// git-формой `<ревизия>:<путь>`: слева от него требуется слэш, которого у
// ревизии не бывает.
//
// Чужой дом ВНЕ суждения по построению: чужого дерева рядом может не быть, а
// сеть в прогоне гейта запрещена. «Вне суждения» отличается от «прощено» тремя
// свойствами, и все три обязательны:
//
//  1. чужая координата СЧИТАЕТСЯ, а её дома ПЕЧАТАЮТСЯ: дом, стоящий в корпусе
//     один раз, тем самым виден — опечатка в имени репозитория не уходит молча;
//  2. приставка, домом НЕ являющаяся (`kacho:internal/x`, `MOD-MF-21:internal/x`),
//     — НАХОДКА. Иначе любой неразобранный префикс снимал бы путь с суждения, и
//     приставка стала бы способом спрятать адрес, а не назвать дом;
//  3. СТОРОЖА живут в гейте, а не здесь: ядро судит поданные значения, и для
//     него всякий непустой дом чужой. Свой дом, названный чужим, ловит гейт.
//
// # ЧЕГО ЭТОТ ГЕЙТ НЕ ДЕЛАЕТ — сказано прямо
//
// Он судит СУЩЕСТВОВАНИЕ пути, а НЕ истинность числа, стоящего рядом с
// предикатом. Путь, приведённый к дереву, делает предикат исполнимым; сойдётся
// ли его вывод с числом, которое приёмка назвала, — вопрос К ЧИСЛУ, и он
// закрывается кругом ревью, а не этой проверкой. Граница честная и она же
// неприятная: живой адрес с ложным содержимым хуже мёртвого, потому что не
// краснеет. Держателя у второй половины сегодня НЕТ, и завести его дороже:
// потребовался бы прогон каждого предиката приёмки на каждом прогоне гейта.
package check

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// PathCoordinateHomeShape — форма НАЗВАННОГО ДОМА: `<владелец>/<репозиторий>` и,
// необязательно, `@<ревизия>`. Ревизия только шестнадцатеричная и не короче семи
// знаков: произвольная строка после `@` сделала бы домом любую опечатку.
var PathCoordinateHomeShape = regexp.MustCompile(
	`^([A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:@([0-9a-fA-F]{7,40}))?$`)

var (
	// pathCoordCommand — строка, несущая команду, чей аргумент после `--` есть
	// путь-спецификация. Обе формы названы: у `git grep` до `--` стоит образец,
	// у `git ls-files` — ничего, и обе кладут пути ПОСЛЕ `--`.
	pathCoordCommand = regexp.MustCompile(`git\s+(?:grep|ls-files)\b`)
	// pathCoordBareSpec — `git ls-files <спец>` БЕЗ `--`: считается, не судится.
	pathCoordBareSpec = regexp.MustCompile(`git\s+ls-files((?:\s+(?:'[^']*'|"[^"]*"|[^\s'"|` + "`" + `]+))+)`)
	// pathCoordToken — один токен пути-спецификации.
	pathCoordToken = `(?:'[^']*'|"[^"]*"|[A-Za-z0-9_][A-Za-z0-9_./*?:@\[\]-]*)`
	// pathCoordRun — пробег путей-спецификаций после `--`. Пробел после `--`
	// обязателен: `--name-only` путь-спецификацией не открывает.
	pathCoordRun   = regexp.MustCompile(`--\s+((?:` + pathCoordToken + `\s*)+)`)
	pathCoordFence = regexp.MustCompile("^\\s*(```|~~~)")
)

// PathCoordinate — одно вхождение путевой координаты.
type PathCoordinate struct {
	// Path — путь-спецификация без приставки дома.
	Path string
	// Home — названный дом `владелец/репозиторий`. Пусто — дом ЭТО дерево.
	Home string
	// Rev — ревизия названного дома, если названа.
	Rev string
	// Span — токен, как он стоит в документе: без него читатель не найдёт строку.
	Span string
	// HomeMalformed — приставка есть, а домом она не является.
	HomeMalformed bool
	Doc           string
	Line          int
}

// PathScanBorders — то, что разбор ВИДЕЛ и НЕ СУДИЛ. Печатается переписью:
// слепая зона, которую видно, — остаток, а не дыра.
type PathScanBorders struct {
	// BareSpec — путей-спецификаций в форме `git ls-files <спец>` без `--`.
	BareSpec int
	// Magic — магических путей-спецификаций (`:!*.md`, `:(glob)…`): не пути.
	Magic int
	// Elided — многоточий-эллипсисов (`…/*.yaml`): не пути, а сокращение прозы.
	Elided int
}

// DeadPathCoordinate — ПОСЛАБЛЕНИЕ: путь, о котором известно, что он не
// резолвится, и чей предмет принадлежит ДРУГОМУ кругу приёмки.
//
// Запись заводится ПО ФАКТУ. Послабление ИСТЕКАЕТ САМО, и оба конца — находка:
// путь стал резолвиться → исключать нечего; путь больше не стоит ни в одном
// документе → исключать нечего.
type DeadPathCoordinate struct {
	Path  string
	Docs  []string
	Issue int
	Note  string
}

// AcceptancePathCoordinateExemptions — ВЕДОМОСТЬ ПУСТА, и это её цель, а не её
// поломка. Заводя запись — назови номер задачи и предикат снятия рядом.
var AcceptancePathCoordinateExemptions []DeadPathCoordinate

// PathCoordinatesIn разбирает документ: возвращает СУДИМЫЕ координаты и то, что
// разбор видел, но судить не стал.
func PathCoordinatesIn(doc, body string) ([]PathCoordinate, PathScanBorders) {
	var found []PathCoordinate
	var b PathScanBorders
	inFence := false
	for lineNo, line := range strings.Split(body, "\n") {
		// Забор считается, но НЕ пропускает: предикат живёт именно в блоке кода.
		if pathCoordFence.MatchString(line) {
			inFence = !inFence
			continue
		}
		if !pathCoordCommand.MatchString(line) {
			continue
		}
		for _, m := range pathCoordBareSpec.FindAllStringSubmatch(line, -1) {
			for _, t := range strings.Fields(m[1]) {
				if strings.HasPrefix(t, "-") {
					continue
				}
				b.BareSpec++
			}
		}
		for _, m := range pathCoordRun.FindAllStringSubmatch(line, -1) {
			for _, t := range strings.Fields(m[1]) {
				co, kind := pathCoordinateOf(t)
				switch kind {
				case pathTokenMagic:
					b.Magic++
				case pathTokenElided:
					b.Elided++
				case pathTokenPath:
					co.Doc, co.Line = doc, lineNo+1
					found = append(found, co)
				}
			}
		}
	}
	return found, b
}

type pathTokenKind int

const (
	pathTokenOther pathTokenKind = iota
	pathTokenPath
	pathTokenMagic
	pathTokenElided
)

// pathCoordinateOf разбирает ОДИН токен пути-спецификации.
func pathCoordinateOf(tok string) (PathCoordinate, pathTokenKind) {
	raw := strings.TrimSpace(tok)
	if len(raw) >= 2 && (raw[0] == '\'' || raw[0] == '"') && raw[len(raw)-1] == raw[0] {
		raw = raw[1 : len(raw)-1]
	}
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "" || strings.HasPrefix(raw, "-"):
		return PathCoordinate{}, pathTokenOther
	case strings.HasPrefix(raw, ":"):
		// Магическая путь-спецификация git: исключение, а не путь.
		return PathCoordinate{}, pathTokenMagic
	case strings.ContainsAny(raw, "…"):
		// Эллипсис прозы (`…/*.yaml`): сокращение, а не адрес.
		return PathCoordinate{}, pathTokenElided
	}
	co := PathCoordinate{Path: raw, Span: tok}
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		head, rest := raw[:i], raw[i+1:]
		m := PathCoordinateHomeShape.FindStringSubmatch(head)
		if m == nil {
			co.HomeMalformed = true
			return co, pathTokenPath
		}
		co.Home, co.Rev, co.Path = m[1], m[2], rest
	}
	return co, pathTokenPath
}

// PathSpecResolves — путь-спецификация резолвится, когда в дереве есть её
// ГЛУБОЧАЙШИЙ ПРЕДОК БЕЗ МЕТАСИМВОЛА.
//
// Судится каталог, а не соответствие шаблону: шаблон, которому сегодня не
// соответствует ничто, есть законный вердикт, а не мёртвый адрес.
func PathSpecResolves(spec string, dirs map[string]bool) bool {
	base := spec
	if i := strings.IndexAny(spec, "*?["); i >= 0 {
		base = spec[:i]
		if j := strings.LastIndexByte(base, '/'); j >= 0 {
			base = base[:j]
		} else {
			base = ""
		}
	}
	base = strings.Trim(base, "/")
	if base == "" || base == "." {
		return true
	}
	return dirs[base]
}

// PathCoordinateCensus — перепись обхода. «Ноль находок» обязано быть отличимо
// от «ноль прочитанного», поэтому объём осмотренного — отдельное утверждение.
type PathCoordinateCensus struct {
	Docs        int
	Tracked     int
	Coordinates int
	Resolved    int
	Exempted    int
	// Foreign — координаты, назвавшие ЧУЖОЙ дом: вне суждения, но в переписи.
	Foreign int
	// RevisionBound — из них связанные РЕВИЗИЕЙ: не проверяемы даже там, где
	// дерево дома есть.
	RevisionBound int
	// ForeignHomes — различные названные дома, по алфавиту.
	ForeignHomes []string
	// Borders — что разбор видел и не судил.
	Borders  PathScanBorders
	Findings []string
}

// JudgePathCoordinates — судящее ядро. Вход подаётся ЗНАЧЕНИЯМИ, а не читается
// из дерева: инъекция обязана уметь дать ему свой вход, не трогая рабочую копию,
// из которой запущена.
func JudgePathCoordinates(docs map[string]string, tracked []string, exemptions []DeadPathCoordinate) PathCoordinateCensus {
	dirs := make(map[string]bool, len(tracked)*2)
	for _, p := range tracked {
		p = strings.Trim(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		dirs[p] = true
		for d := path.Dir(p); d != "." && d != "/" && d != ""; d = path.Dir(d) {
			dirs[d] = true
		}
	}

	exempt := make(map[string]*DeadPathCoordinate, len(exemptions))
	for i := range exemptions {
		exempt[exemptions[i].Path] = &exemptions[i]
	}
	used := make(map[string]bool, len(exemptions))

	c := PathCoordinateCensus{Docs: len(docs), Tracked: len(tracked)}
	homes := map[string]bool{}

	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		coords, b := PathCoordinatesIn(p, docs[p])
		c.Borders.BareSpec += b.BareSpec
		c.Borders.Magic += b.Magic
		c.Borders.Elided += b.Elided
		for _, co := range coords {
			c.Coordinates++
			if co.HomeMalformed {
				c.Findings = append(c.Findings, "ДОМ НАЗВАН НЕ ДОМОМ "+co.Doc+":"+
					strconv.Itoa(co.Line)+" — токен `"+co.Span+"` несёт приставку, которая "+
					"репозиторием не является. Приставка снимает путь с суждения, поэтому её "+
					"форма закрыта: `владелец/репозиторий:путь` либо "+
					"`владелец/репозиторий@ревизия:путь` (ревизия — hex, не короче семи "+
					"знаков). Иначе любой префикс прячет адрес вместо того, чтобы назвать дом")
				continue
			}
			if co.Home != "" {
				c.Foreign++
				if co.Rev != "" {
					c.RevisionBound++
				}
				homes[co.Home] = true
				continue
			}
			if PathSpecResolves(co.Path, dirs) {
				c.Resolved++
				continue
			}
			if e, ok := exempt[co.Path]; ok {
				c.Exempted++
				used[e.Path] = true
				continue
			}
			c.Findings = append(c.Findings, "МЁРТВЫЙ ПУТЬ ПРЕДИКАТА "+co.Doc+":"+
				strconv.Itoa(co.Line)+" — приёмка доказывает утверждение командой по пути `"+
				co.Path+"`, а такого корня в дереве НЕТ. Предикат по несуществующему пути "+
				"даёт пустоту ПО ПОСТРОЕНИЮ: «ноль находок» неотличимо от «ноль "+
				"прочитанного», и читатель делает вывод О ДЕРЕВЕ по замеру, который ничего "+
				"не измерял. Исходов три. Привести путь к дереву — если предмет переехал "+
				"вместе со службой. Назвать ДОМ, если предмет остался в другом репозитории: "+
				"`владелец/репозиторий:"+co.Path+"` — такой путь вне суждения этого гейта и "+
				"попадает в перепись чужих домов. Переписать предикат на координату с "+
				"ПРОИЗВОДИТЕЛЕМ — путь модуля берётся пином из `go.mod` "+
				"(`go list -m -f '{{.Dir}}' <модуль>`), а не выписывается. Ослабить "+
				"утверждение, чтобы предикат «проходил», исходом НЕ является")
		}
	}

	c.ForeignHomes = make([]string, 0, len(homes))
	for h := range homes {
		c.ForeignHomes = append(c.ForeignHomes, h)
	}
	sort.Strings(c.ForeignHomes)

	// Второй конец самоистечения: послабление, которому нечего исключать.
	for _, e := range exemptions {
		if used[e.Path] {
			continue
		}
		why := "путь больше не стоит предикатом ни в одной приёмке"
		if PathSpecResolves(e.Path, dirs) {
			why = "путь снова резолвится в дереве"
		}
		c.Findings = append(c.Findings, "ПОСЛАБЛЕНИЕ БЕЗ ПРЕДМЕТА `"+e.Path+"` — "+why+
			". Запись снимается тем же изменением: послабление, которому нечего исключать, "+
			"достаётся следующему читателю и прощает уже другое")
	}
	return c
}

// TrackedPathsOfTree — отслеживаемые пути дерева. Перечень ВЫВОДИТСЯ обходом
// индекса git, а не выписывается: рукописный список разошёлся бы с деревом молча.
func TrackedPathsOfTree(root string) ([]string, error) {
	all, err := treecorpus.Under(root)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(all))
	for _, abs := range all {
		rel := strings.TrimPrefix(strings.TrimPrefix(abs, root), "/")
		if rel == "" {
			continue
		}
		out = append(out, rel)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("в %s нет ни одного отслеживаемого пути: резолвить не с чем", root)
	}
	return out, nil
}
