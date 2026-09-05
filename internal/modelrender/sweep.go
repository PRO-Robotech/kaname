// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/pkg/modulemanifest"
)

// sweep.go — обход ЗАКРЫТОГО НАБОРА модулей и сверка порождённого с каноном
// (Н-02, Н-05, Н-06 приёмки; сценарии B-06, B-08; инъекции C-08, C-09).
//
// # Перечень модулей задаёт НАБОР, а принадлежность блока — ТАБЛИЦА. Имя не задаёт ничего
//
// Обратный порядок («сверяем модули, объявленные манифестами») при нуле манифестов
// вырождается в тождественную истину, а при частичном обходе — в зелёный вердикт
// над непрочитанным. Состояние «манифестов меньше, чем модулей» есть ШТАТНОЕ
// состояние миграции, а не переходный миг.
//
// Счёт по префиксу имени типа ошибается в ОБЕ стороны сразу и это замер, а не
// вкус: модуль `iam` теряется целиком (`account` и `project` префикса не несут), а
// модуль балансировки канон зовёт `nlb_*`, тогда как набор — `loadbalancer`, и
// `module: nlb` загрузчик ОТВЕРГАЕТ. Под предикатом по префиксу сверка этого
// модуля не совпала бы НИ РАЗУ и отняла бы девять живых прав, выглядя рабочей.
//
// # Исходов ТРИ, и «частично» не является четвёртым
//
//	0  сверено всё объявленное  — у каждого модуля набора манифест, все сверки прошли
//	1  находка                  — любой повод перечня §2 п. 7 приёмки (перечень там ОДИН)
//	2  VOID                     — сверять нечего НИ ДЛЯ ОДНОГО модуля
//
// VOID в успех НЕ ЗАСЧИТЫВАЕТСЯ и из вердикта НЕ ВЫЧИТАЕТСЯ: «зелёный под
// послаблением» неотличим от настоящего зелёного ПО КОДУ ВОЗВРАТА, а VOID отличим
// машинно.
//
// # Ведомость разрешает ПОЗАПИСНО и с номером, никогда огульно
//
// Модуль, чей манифест ещё не приехал, стоит записью с номером задачи. Огульного
// «идёт миграция — проходим» не существует: у него нет предиката снятия, и оно не
// истекло бы НИКОГДА. Запись, которой больше нечего прощать (манифест приехал), —
// НАХОДКА, а не тишина.
const (
	// SweepOK — сверено всё объявленное.
	SweepOK = 0
	// SweepFinding — находка: любой повод перечня §2 п. 7 приёмки
	// `model-generated-from-manifest.md`.
	//
	// Перечень здесь НЕ воспроизводится и не сокращается до пары примеров.
	// Прежняя редакция называла два повода из перечисленных нормой поимённо и
	// пережила решение, которым перечень был сведён: второе место об одном
	// предмете расходится с первым молча, и расходится в сторону, где читатель
	// достраивает недостающее сам (задача #1856).
	SweepFinding = 1
	// SweepVoid — сверять нечего ни для одного модуля.
	//
	// Отдельное значение, а не SweepOK: оболочка читает КОД, и «нечего» не вправе
	// выглядеть успехом.
	SweepVoid = 2
)

// Side — какая сторона сверки оказалась богаче. Два исхода означают РАЗНОЕ для
// арендатора и чинятся разными правками, поэтому различаются в тексте (§2 п. 3).
type Side int

const (
	// SideNone — расхождение не про блоки (нет манифеста, ведомость без предмета).
	SideNone Side = iota
	// SideRenderedBeyondCanon — порождено сверх канона: РАСШИРЯЕТ доступ.
	SideRenderedBeyondCanon
	// SideCanonBeyondRendered — канон сверх порождённого: ТЕРЯЕТ доступ.
	SideCanonBeyondRendered
)

// String называет сторону словами вызывающего, а не номером.
func (s Side) String() string {
	switch s {
	case SideRenderedBeyondCanon:
		return "порождено сверх канона"
	case SideCanonBeyondRendered:
		return "канон сверх порождённого"
	default:
		// Печатается у находки о блоке, когда ни одна сторона не богаче:
		// объявлено одно и то же, отличается правая часть определения. У находок
		// о модуле целиком сторона не печатается вовсе (см. Finding.String).
		return "ни одна сторона не богаче"
	}
}

// Waiver — запись ведомости послаблений: модуль набора, чей манифест ещё не приехал.
type Waiver struct {
	// Module — модуль закрытого набора.
	Module string
	// Issue — номер задачи, под которую выдано послабление. Запись без номера
	// есть послабление без предиката снятия: оно не истечёт никогда.
	Issue int
}

// Census — объём осмотренного. «Ноль находок» обязано быть отличимо от «ноль
// прочитанного», поэтому величин ПЯТЬ, а не одна: одна скрывает ровно тот случай,
// ради которого обход заведён.
type Census struct {
	// ModulesInSet — модулей в закрытом наборе платформы.
	ModulesInSet int
	// ManifestsFound — манифестов найдено под корнем.
	ManifestsFound int
	// BlocksCompared — блоков сверено побайтово.
	BlocksCompared int
	// BytesCompared — байт сверено (единица A).
	BytesCompared int
	// BlocksOutsideModules — блоков канона вне всякого модуля; прирост — находка.
	BlocksOutsideModules int
	// BlocksOwned — блоков канона, ПРИНАДЛЕЖАЩИХ модулям набора по закрытой
	// таблице. Знаменатель для «сверено M»: без него «сверено 0» неотличимо от
	// «сверять было нечего».
	BlocksOwned int
	// Waived — модулей, прощённых ведомостью позаписно.
	Waived int
}

// String печатает перепись словами: перечень величин, читаемый человеком в логе
// прогона. Печатается ВСЕГДА, включая VOID, — иначе «ноль находок» неотличимо от
// «ноль прочитанного».
func (c Census) String() string {
	return fmt.Sprintf(
		"модулей набора %d · манифестов найдено %d · прощено ведомостью %d · "+
			"блоков сверено %d из %d принадлежащих модулям · байт сверено %d · "+
			"блоков вне модулей %d",
		c.ModulesInSet, c.ManifestsFound, c.Waived,
		c.BlocksCompared, c.BlocksOwned, c.BytesCompared, c.BlocksOutsideModules)
}

// Finding — находка обхода, названная стороной и координатой.
type Finding struct {
	// Module — модуль закрытого набора, к которому находка относится.
	Module string
	// Type — тип модели, если находка про блок; пусто, если про модуль целиком.
	Type string
	// Side — какая сторона богаче; SideNone, когда находка не про блоки.
	Side Side
	// Detail — что именно неверно, словами, с первой расходящейся строкой.
	Detail string
}

// String — одна строка отчёта.
func (f Finding) String() string {
	if f.Type == "" {
		return fmt.Sprintf("модуль %s: %s", f.Module, f.Detail)
	}
	return fmt.Sprintf("модуль %s, тип %s [%s]: %s", f.Module, f.Type, f.Side, f.Detail)
}

// Sweep обходит закрытый набор модулей от корня дерева root и сверяет
// порождённое из манифестов с каноном.
//
// # Путь канона НЕ является параметром — это свойство ПОДПИСИ (§2 п. 2, A-03)
//
// Второй операнд сверки резолвится обходом вверх ОТ КОРНЯ ДЕРЕВА по постоянному
// относительному пути (authzplan). Подменить канон снимком, лежащим рядом со
// сверщиком, невозможно не по запрету, а потому что ПРЕДЪЯВИТЬ ЕГО НЕЧЕМ:
// у Sweep нет параметра, куда такой путь встал бы. Держит это компилятор, а не гейт.
//
// Прототип этой задачи был зелен ровно потому, что сверялся со снимком, который
// нёс два снятых отношения (`define use`, снятое #1115): в дереве их НОЛЬ, в
// снимке — два. Параметризуемый путь канона вернул бы тот же дефект первой же
// правкой.
func Sweep(resources []catalog.ResourceRow, root string, waivers []Waiver) (Census, []Finding, int) {
	// Набор модулей ВЫВОДИТСЯ из тех же строк ресурсов, которые обход и сверяет,
	// а не спрашивается у второго источника (#1927). Так перепись не может
	// разойтись с осмотренным: модуль без единой строки ресурса обходить нечем,
	// а строка ресурса без модуля в наборе невыразима by construction.
	modules := modulesOf(resources)
	census := Census{ModulesInSet: len(modules)}
	var findings []Finding

	_, dsl, err := authzplan.ResolveCanonicalModelFrom(root)
	if err != nil {
		return census, []Finding{{Detail: "канон не резолвится: " + err.Error()}}, SweepFinding
	}
	canon := make(map[string]Block)
	for _, b := range SplitCanon(dsl) {
		canon[b.Type] = b
	}
	census.BlocksOutsideModules = len(TypesOutsideModules(resources, dsl))

	// Ожидаемое выводится ОДИН раз на обход: OwnedTypes перечитывает канон, и
	// второй вызов на тот же модуль дал бы тот же ответ дороже.
	owned := make(map[string][]string, len(modules))
	for _, module := range modules {
		owned[module] = OwnedTypes(resources, dsl, module)
		census.BlocksOwned += len(owned[module])
	}

	// Корень открывается ОДИН раз на весь обход и служит ГРАНИЦЕЙ чтения обоим
	// читателям манифеста — тому, что ищет их, и тому, что сверяет блоки.
	// Путь им приносит обход, а между записью каталога и открытием лежит окно:
	// в нём любой сегмент подменяется ссылкой наружу, и чтение ПО ИМЕНИ уходит
	// за корень, не заметив этого. Через os.Root каждый сегмент разрешает ядро
	// относительно корня, поэтому граница держится построением, а не тем, что
	// читатель о ней помнит.
	treeRoot, oerr := os.OpenRoot(root)
	if oerr != nil {
		return census, []Finding{{Detail: "корень обхода не открыт: " + oerr.Error()}}, SweepFinding
	}
	defer func() { _ = treeRoot.Close() }()

	found, unparsable, ferr := findManifests(treeRoot, root)
	if ferr != nil {
		return census, []Finding{{Detail: "обход дерева отказал: " + ferr.Error()}}, SweepFinding
	}
	// unusableFor — модули, чей манифест ЛЕЖИТ и негоден. Объявление «не засчитан
	// НИ модулем, НИ его отсутствием» исполняется обеими половинами: в `found`
	// такой документ не попадает (первая), и модуль по нему непокрытым не
	// объявляется (вторая, #2045).
	unusableFor := make(map[string]struct{}, len(unparsable))
	for _, u := range unparsable {
		if u.Module != "" {
			unusableFor[u.Module] = struct{}{}
		}
		findings = append(findings, Finding{Module: u.Module, Detail: fmt.Sprintf(
			"%s: %s — %v; документ назвался манифестом и манифестом не стал, поэтому он не "+
				"засчитан НИ модулем, НИ его отсутствием; форму судит "+
				"`make -C services/iam module-manifest-check`", u.Cause, u.Path, u.Err)})
	}

	// Ведомость судится ДО обхода: запись без номера и запись на модуль вне
	// набора не имеют предмета независимо от того, что лежит в дереве.
	known := domain.ModuleSetOf(modules...)
	waived := make(map[string]Waiver, len(waivers))
	for _, w := range waivers {
		switch {
		case !known.IsKnownModule(w.Module):
			findings = append(findings, Finding{Module: w.Module, Detail: fmt.Sprintf(
				"запись ведомости на модуль вне закрытого набора платформы: обход его не обходит, " +
					"и прощать ей нечего")})
		case w.Issue == 0:
			findings = append(findings, Finding{Module: w.Module, Detail: fmt.Sprintf(
				"запись ведомости без номера задачи: послабление без предиката снятия не истечёт " +
					"НИКОГДА — назовите номер")})
		default:
			waived[w.Module] = w
		}
	}

	for _, module := range modules {
		path, ok := found[module]
		if !ok {
			// Манифест модуля лежит и негоден: он уже назван своей находкой с
			// СОБСТВЕННОЙ причиной. Объявить модуль непокрытым значило бы послать
			// читателя заводить документ, который написан (#2045).
			if _, unusable := unusableFor[module]; unusable {
				continue
			}
			switch w, forgiven := waived[module]; {
			case forgiven:
				census.Waived++
			default:
				_ = w
				findings = append(findings, Finding{Module: module, Detail: fmt.Sprintf(
					"модуль закрытого набора без манифеста и без записи ведомости: блоки канона " +
						"этого модуля остались бы непрочитанными при зелёном вердикте")})
			}
			continue
		}
		census.ManifestsFound++
		if _, forgiven := waived[module]; forgiven {
			findings = append(findings, Finding{Module: module, Detail: fmt.Sprintf(
				"запись ведомости пережила свой предмет: манифест приехал (%s), прощать нечего — "+
					"снимите запись", path)})
		}
		fs, cmp := compareModule(treeRoot, root, module, path, canon, owned[module])
		findings = append(findings, fs...)
		census.BlocksCompared += cmp.BlocksCompared
		census.BytesCompared += cmp.BytesCompared
	}

	switch {
	case len(findings) > 0:
		return census, findings, SweepFinding
	case census.BlocksCompared == 0:
		return census, nil, SweepVoid
	default:
		return census, nil, SweepOK
	}
}

// compareModule разбирает манифест модуля, порождает блоки его ресурсов и сверяет
// каждый с каноном ПОБАЙТОВО, а затем спрашивает ОБРАТНОЕ: не остался ли блок
// канона, принадлежащий этому модулю, не порождённым ничем.
//
// # Обратный вопрос — не симметрия, а единственное место, где ловится ПРИЗНАК #1089
//
// Сверка «по ресурсам манифеста» о том, чего в манифесте НЕТ, не спрашивает
// вовсе. Значит блок, дописанный в канон РУКОЙ у модуля, чей манифест приехал, не
// встречает ни одной проверки: ни этой (её обход до него не доходит), ни B-06 (тип
// принадлежит модулю, а не остатку вне модулей), ни B-08 (манифест у модуля есть).
// Это третье состояние, и оно молчало.
//
// Сторона у такой находки — «канон сверх порождённого»: право есть в модели и не
// имеет источника в манифесте. Перегенерация из манифеста ОТНЯЛА БЫ его, и потому
// исход именно находка, а не умолчание.
func compareModule(treeRoot *os.Root, root, module, path string,
	canon map[string]Block, owned []string) ([]Finding, Census) {
	var findings []Finding
	var census Census

	// Тот же читатель и та же граница, что у поиска: путь принёс обход, и
	// читать его ПО ИМЕНИ нельзя по той же причине (окно между записью
	// каталога и открытием). Вторая реализация чтения разошлась бы с первой
	// молча — обе дают «прочитано» на честном дереве.
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		return []Finding{{Module: module, Detail: "путь манифеста не приведён к корню: " +
			relErr.Error()}}, census
	}
	raw, err := manifest.ReadUnderRoot(treeRoot, filepath.ToSlash(rel))
	if err != nil {
		return []Finding{{Module: module, Detail: "манифест не прочитан: " + err.Error()}}, census
	}
	// Референт — КАНОН: существование типа судит эта самая функция ниже
	// («манифест порождает тип, которого в каноне НЕТ»), и спросить о нём
	// загрузчика значило бы спросить у закрытой таблицы, которую из этих же
	// манифестов и порождают (задача #1930).
	m, err := manifest.LoadWithReferent(raw, manifest.ReferentCanon)
	if err != nil {
		return []Finding{{Module: module, Detail: "манифест не разобран: " + err.Error()}}, census
	}

	for i := range m.Resources {
		r := m.Resources[i]
		rendered, err := Render(r)
		if err != nil {
			findings = append(findings, Finding{Module: module, Type: r.ObjectType,
				Detail: "ресурс не отрендерен: " + err.Error()})
			continue
		}
		block, ok := canon[r.ObjectType]
		if !ok {
			findings = append(findings, Finding{Module: module, Type: r.ObjectType,
				Side:   SideRenderedBeyondCanon,
				Detail: "манифест порождает тип, которого в каноне НЕТ — это лишнее право"})
			continue
		}
		if !bytes.Equal(rendered, block.Body) {
			findings = append(findings, Finding{Module: module, Type: r.ObjectType,
				Side:   sideOf(rendered, block.Body),
				Detail: firstDivergence(rendered, block.Body)})
			continue
		}
		census.BlocksCompared++
		census.BytesCompared += len(block.Body)
	}

	declared := make(map[string]struct{}, len(m.Resources))
	for i := range m.Resources {
		declared[m.Resources[i].ObjectType] = struct{}{}
	}
	for _, typ := range owned {
		if _, ok := declared[typ]; ok {
			continue
		}
		findings = append(findings, Finding{Module: module, Type: typ,
			Side: SideCanonBeyondRendered,
			Detail: "блок канона принадлежит этому модулю по закрытой таблице, а ресурса, " +
				"порождающего его, в манифесте НЕТ: перегенерация отняла бы это право"})
	}
	return findings, census
}

// sideOf называет, какая сторона богаче, и судит по ИМЕНАМ ОПРЕДЕЛЕНИЙ, а не по
// числу строк.
//
// Сторона есть утверждение о правах арендатора, а не украшение отчёта:
// «порождено сверх канона» читается как РАСШИРЯЕТ доступ, «канон сверх
// порождённого» — как ТЕРЯЕТ его, и чинятся эти два разными правками.
//
// # Число строк на этот вопрос не отвечает — и лжёт на самом частом расхождении
//
// Здесь стоял счёт строк с ветвью `default`, отдававшей «порождено сверх канона»
// при РАВНОМ числе. Между тем самый частый вид расхождения строк не добавляет и
// не убавляет: те же определения, другая правая часть — сужённые субъекты, иной
// якорь, переименованный ярус. Замер собственной пробой: манифест, СУЖАЮЩИЙ
// субъекты ярусов, порождает блок беднее канона, а вывод объявлял его богаче, то
// есть посылал чинить в обратную сторону.
//
// Поэтому судятся МНОЖЕСТВА имён `define`. Имя, которое несёт только порождённое,
// — право, которого в модели нет; только канон — право, которое перегенерация
// отняла бы. Оба сразу — обе находки, и названа опасная: расширение. Ни одного —
// стороны равны, и это говорится прямо; координату при этом всё равно называет
// первая расходящаяся строка.
func sideOf(rendered, canon []byte) Side {
	r, c := definitionNames(rendered), definitionNames(canon)
	extraInRendered, extraInCanon := false, false
	for name := range r {
		if _, ok := c[name]; !ok {
			extraInRendered = true
		}
	}
	for name := range c {
		if _, ok := r[name]; !ok {
			extraInCanon = true
		}
	}
	switch {
	case extraInRendered:
		return SideRenderedBeyondCanon
	case extraInCanon:
		return SideCanonBeyondRendered
	default:
		return SideNone
	}
}

// definitionNames — имена отношений блока: то, ЧТО объявлено, отдельно от того,
// КАК объявлено. Расхождение правой части сторону не меняет.
func definitionNames(block []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range bytes.Split(block, []byte("\n")) {
		body := bytes.TrimSpace(line)
		if !bytes.HasPrefix(body, []byte("define ")) {
			continue
		}
		name, _, ok := bytes.Cut(bytes.TrimPrefix(body, []byte("define ")), []byte(":"))
		if !ok {
			continue
		}
		out[string(bytes.TrimSpace(name))] = struct{}{}
	}
	return out
}

// firstDivergence называет ПЕРВУЮ расходящуюся строку и её номер: отказ, не
// называющий координаты, заставляет искать её глазами в блоке на сорок строк.
func firstDivergence(rendered, canon []byte) string {
	r := bytes.Split(rendered, []byte("\n"))
	c := bytes.Split(canon, []byte("\n"))
	for i := 0; i < len(r) || i < len(c); i++ {
		var rl, cl string
		if i < len(r) {
			rl = string(r[i])
		}
		if i < len(c) {
			cl = string(c[i])
		}
		if rl != cl {
			return fmt.Sprintf("строка %d: порождено %q, канон %q", i+1, rl, cl)
		}
	}
	return "блоки расходятся, а построчно совпадают — расхождение в завершающих байтах"
}

// findManifests — модуль → путь его манифеста под корнем, и ОТДЕЛЬНО пути тех
// документов, которые манифестом назвались и не разобрались.
//
// Манифестом считается файл с базовым именем РОВНО `manifest.yaml`; модуль берётся
// из разобранной оболочки документа, а НЕ из имени каталога: имя каталога не
// является объявлением модуля, и судить по нему значило бы завести второй словарь.
//
// # Негодный документ НЕ является отсутствующим документом
//
// Здесь стояло обратное — «он попадёт находкой у своего модуля, когда обход дойдёт
// до него по имени каталога». По имени каталога не ходит НИЧТО: обход относит
// документ к модулю по разобранной оболочке, а у неразобранного её нет. Цена
// расхождения комментария с кодом измерена собственной пробой: негодный манифест
// молча читался как отсутствующий, ведомость прощала модуль по записи «манифест
// ещё не приехал», и блоки модуля оставались непрочитанными при исходе, который
// находкой не был. Ведомость при этом не самоистекала бы НИКОГДА: манифест не
// засчитан, значит прощать ей на вид есть что.
//
// Форму документа здесь никто не судит второй раз — это предмет одного
// исполнителя (`make -C services/iam module-manifest-check`). Здесь он лишь не
// вправе быть засчитан ни модулем, ни его отсутствием.
// unusableManifest — документ, назвавшийся манифестом и манифестом не ставший.
//
// Причин ТРИ, и они означают разное: путь не приведён к корню обхода (наша
// ошибка) · файл не прочитан (документа по имени нет либо он недоступен) ·
// документ не разобран (текст есть, форма негодна). Прежде они сваливались в
// одну корзину строк, ошибка КАЖДОЙ выбрасывалась, а печаталось по ним одно
// сообщение, утверждавшее одну конкретную причину — «модуля не объявил», — в
// общем случае неверную (задача #1905).
//
// Ошибка носится САМА, а не пересказывается: пересказ есть второе место об одном
// предмете, и расходится он молча.
//
// # Границы доказанного, названные честно
//
// Производителя красного имеют ДВЕ причины из трёх: «не прочитан» и «не
// разобран». Приведение пути к корню обхода отказать здесь не может — путь
// приходит от обхода ТОГО ЖЕ корня, — поэтому ветвь оборонительная и пробы у неё
// нет. Это сказано, а не выдано за проверенное: молчание пробы, которой нет,
// неотличимо от молчания пробы, которая не падает.
type unusableManifest struct {
	Path string
	// Module — модуль, который документ ОБЪЯВИЛ, либо пусто, если не объявил
	// (или объявить не мог: документ не прочитан). Снимается тем же читателем
	// оболочки, что и у обхода манифестов (`manifest.PeekModule`), а не своим:
	// вторая реализация разошлась бы с первой молча.
	//
	// Пустое значение здесь означает «приписать НЕ К ЧЕМУ», и тогда «модуль без
	// манифеста» остаётся верным. Различение несущее: без него починка #2045
	// выродилась бы в замалчивание непокрытого модуля.
	Module string
	Cause  string
	Err    error
}

func findManifests(treeRoot *os.Root, root string) (map[string]string, []unusableManifest, error) {
	out := map[string]string{}
	var unparsable []unusableManifest

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch name := d.Name(); {
			case path != root && len(name) > 1 && name[0] == '.':
				return filepath.SkipDir
			case name == "node_modules" || name == "vendor" || name == "dist" || name == "build":
				return filepath.SkipDir
			}
			return nil
		}
		// Имя берётся у ЕДИНСТВЕННОГО объявления, а не пишется здесь: голый
		// литерал был третьей копией одного соглашения, и разошёлся бы он МОЛЧА —
		// обход перестал бы находить часть манифестов, не дав ни одной находки
		// (задача #1934).
		if d.Name() != modulemanifest.FileName {
			return nil
		}
		// Непрочитанный документ уходит в ТУ ЖЕ корзину, что и неразобранный, и
		// по той же причине: он назвался манифестом и манифестом не стал,
		// значит не вправе быть засчитан НИ модулем, НИ его отсутствием. Обрыв
		// всего обхода на одном файле дал бы вместо этого перепись, которой
		// нет вовсе, — а «ноль прочитанного» неотличимо от «ноль находок».
		// Читатель — общий с обходом проверки: вторая реализация разошлась бы
		// с первой молча.
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			unparsable = append(unparsable, unusableManifest{Path: path,
				Cause: "путь манифеста не приведён к корню обхода", Err: relErr})
			return nil
		}
		raw, rerr := manifest.ReadUnderRoot(treeRoot, filepath.ToSlash(rel))
		if rerr != nil {
			unparsable = append(unparsable, unusableManifest{Path: path,
				Cause: "манифест не прочитан", Err: rerr})
			return nil
		}
		m, lerr := manifest.LoadWithReferent(raw, manifest.ReferentCanon)
		if lerr != nil {
			// Документ прочитан, значит оболочку снять ЕСТЬ С ЧЕГО: имя модуля
			// берётся у него самого, и негодный документ перестаёт читаться как
			// отсутствующий (#2045). Отказ загрузчика при этом остаётся находкой —
			// приписан он или нет.
			unparsable = append(unparsable, unusableManifest{Path: path,
				Module: manifest.PeekModule(raw),
				Cause:  "манифест не разобран", Err: lerr})
			return nil
		}
		out[m.Module] = path
		return nil
	})
	sort.Slice(unparsable, func(i, j int) bool { return unparsable[i].Path < unparsable[j].Path })
	return out, unparsable, err
}

// modulesOf — РАЗЛИЧНЫЕ модули строк ресурсов, отсортированно.
//
// Обход берёт набор здесь, а не у второго источника: строки приходят
// параметром — той же левой стороной паритета, из которой посеян каталог, — и
// вывести набор из них значит сделать перепись `ModulesInSet` утверждением о
// ТОМ ЖЕ множестве, которое обход и сверяет. Второй источник разошёлся бы с
// первым молча, и разошёлся бы ровно в сторону «модуль есть, а сверять у него
// нечего».
func modulesOf(resources []catalog.ResourceRow) []string {
	seen := make(map[string]struct{}, 8)
	for _, r := range resources {
		if r.Module == "" {
			continue
		}
		seen[r.Module] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
