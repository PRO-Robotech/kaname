// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package roleexport

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// classfit.go — СТАДИЯ 1: класс, объявленный разделом `resources`, обязан
// удовлетворять гейт своего действия (приёмка §3.6 п. 3 и п. 6, MOD-RL-22).
//
// # Почему эта стадия первая, и почему это не порядок чтения файла
//
// Она решает, ЧТО ТАКОЕ класс. Пока она красна, вопрос «полон ли поимённый
// перечень» (MOD-RL-18) и «названо ли непригодное» (MOD-RL-19) не имеет
// определённого множества, по которому считается: полнота считается по классу, и
// если класс объявлен не тем, чем его понимает гейт, «полный» перечень окажется
// неполным по факту. Порядок объявлен в `Check` — то есть в той функции, через
// которую идут ОБА вызывающих, — а не в команде обхода дерева: проверка порядка,
// живущая у вызывающего, не защищает второго.
//
// # Принадлежность классу — ПЕРЕСЕЧЕНИЕ, и полу-предиката не бывает
//
// Действие принадлежит классу `C` на ресурсе `R`, если оно (а) ПОМЕЧЕНО классом
// `C` в разделе `resources` И (б) правило с классом `C` УДОВЛЕТВОРЯЕТ его гейт.
// Без (а) класс перестал бы быть тем, что автор объявил, и эта стадия стала бы
// беспредметной; без (б) вернулось бы молчаливое расширение, ради запрета
// которого §3.6 и написан.
//
// # Исходов ДВА, и различает их ПОЧИНИМОСТЬ
//
//	отношение гейта производимо правилом роли, а классу не соответствует
//	    → ОТКАЗ; чинится объектной формой `{name: X, class: C}`
//	отношение гейта не производимо правилом роли ни при каком классе
//	    → ПОМЕТКА «непригодно для роли», не отказ
//
// Разница не косметическая. Раздел `resources` ПОРОЖДАЕТСЯ из аннотаций
// контрактов (исход B эпика #1087), поэтому отказ на непроизводимое действие не
// имел бы адресата: автор манифеста его не писал и снять не может. Это была бы
// объявленная и неисполнимая возможность внутри проверки, заведённой против
// ровно этого класса. Отказ по такому действию наступает позже и по другой
// единице — когда роль НАЗОВЁТ его поимённо (MOD-RL-19).
//
// # Освобождённое действие НЕ СУДИТСЯ и четвёртой ветвью предиката не является
//
// `required_relation` пуст — гейта нет вовсе, действие получает всякий
// аутентифицированный, а не участник роли. Класс объявлен не неверно: у класса
// просто нет предмета. Зачесть освобождённое в пригодные значило бы требовать
// от перечня имени того, чего право не даёт.
//
// # Тип объекта берётся у ЗАКРЫТОЙ ТАБЛИЦЫ, а не у записи манифеста
//
// Предикат отвечает на вопрос «пишет ли правило роли ТОТ кортеж, который
// спрашивает гейт», а кортеж строит эмиттер, резолвя тип таблицей `authzmap` —
// не ключом `objectType` записи. Читай проверка объявление манифеста, неверное
// объявление меняло бы вердикт о том, что эмиттер производит на самом деле, и
// проверка утверждала бы о манифесте вместо продукта. Согласие двух написаний —
// отдельный предмет: ключ `objectType` уже сверяется загрузчиком с той же
// таблицей на членство (`ErrObjectTypeUnknown`), но не на то, что это тип ИМЕННО
// ЭТОГО ресурса.
//
// Сверка эта с задачи #1930 условлена РЕФЕРЕНТОМ: в проходе, ПОРОЖДАЮЩЕМ
// таблицу, её не происходит вовсе (`manifest.ReferentCanon`) — судить вход своим
// продуктом значит спрашивать у ответа. На предикат ниже это не влияет ни в одну
// сторону: он читает таблицу САМ и о том, спрашивал ли её загрузчик, не знает.

var (
	// ErrDeclaredClassDoesNotSatisfyGate — объявленный класс действия не
	// удовлетворяет его гейт, при том что гейт производим правилом роли: класс
	// назван не тем, чем его понимает проверка доступа.
	ErrDeclaredClassDoesNotSatisfyGate = errors.New(
		"roleexport: объявленный класс действия не удовлетворяет его гейт")
)

// NoteKind — вид пометки. Пометка НЕ отказ: она называет состояние, за которое
// автор манифеста не отвечает, и молчать о котором нельзя.
type NoteKind int

const (
	// NoteUnsuitableForRole — гейт действия спрашивает пару, непроизводимую
	// правилом роли модуля ни при каком классе.
	NoteUnsuitableForRole NoteKind = iota + 1
	// NoteActionUnknownToCatalog — каталог прав не знает такого действия у
	// этого ресурса: класс сверить не с чем.
	NoteActionUnknownToCatalog
	// NoteActionExemptFromGate — у действия нет гейта вовсе.
	NoteActionExemptFromGate
)

// String — имя вида пометки словами: число в отчёте читателю ничего не говорит.
func (k NoteKind) String() string {
	switch k {
	case NoteUnsuitableForRole:
		return "непригодно для роли"
	case NoteActionUnknownToCatalog:
		return "каталог такого действия не знает"
	case NoteActionExemptFromGate:
		return "освобождено от гейта"
	default:
		return fmt.Sprintf("вид пометки %d", int(k))
	}
}

// Note — состояние действия, о котором обязано быть сказано вслух, но которое
// отказом не является.
type Note struct {
	Kind     NoteKind
	Module   string
	Resource string
	Verb     string
	Class    string
	// Relation и Object — пара гейта. Пусты у несопоставленного действия:
	// сверять не с чем.
	Relation string
	Object   string
	Detail   string
}

func (n Note) String() string { return n.Detail }

// ClassFinding — отказ стадии 1.
//
// Координаты лежат отдельными полями, а не только в тексте: вызывающий вправе
// пересчитать находки по ресурсу и по классу, не разбирая прозу.
type ClassFinding struct {
	Kind     error
	Module   string
	Resource string
	Verb     string
	// Class — класс, ОБЪЯВЛЕННЫЙ манифестом (тот, что неверен).
	Class string
	// Relation и Object — пара, которую спрашивает гейт.
	Relation string
	Object   string
	Detail   string
}

func (f ClassFinding) Error() string { return f.Detail }

// Unwrap отдаёт вид находки, чтобы errors.Is отвечал по сентинелу.
func (f ClassFinding) Unwrap() error { return f.Kind }

// ClassCensus — объём осмотренного стадией 1.
//
// Состояний ПЯТЬ, и они печатаются порознь: сумма скрыла бы перенос действия из
// одного состояния в другое — ровно то, что случилось с самим замером приёмки,
// когда освобождённое зачли в удовлетворяющие.
type ClassCensus struct {
	// ActionsAttributed — действий каталога, привязанных к ресурсам модулей.
	ActionsAttributed int
	// ResourcesRead — записей раздела `resources` осмотрено.
	ResourcesRead int
	// VerbsRead — действий раздела осмотрено. ЕДИНИЦА этой стадии.
	VerbsRead int
	// ClassSatisfies — объявленный класс удовлетворяет гейт.
	ClassSatisfies int
	// Findings — отказов: класс не тот, но гейт производим.
	Findings int
	// Unsuitable — непригодных для роли: гейт непроизводим ни при каком классе.
	Unsuitable int
	// Exempt — освобождённых от гейта: не судятся.
	Exempt int
	// Unmatched — каталог такого действия не знает: сверять не с чем.
	Unmatched int
	// UnmatchedAuthored — из них НА АВТОРСКИХ ресурсах (`producer: authored`).
	//
	// Печатается рядом с `Unmatched`, а не вместо него, и не сливается в сумму:
	// у этих двух популяций РАЗНОЕ продолжение. Несопоставленное действие
	// порождённого ресурса судит сверка соединения (`CheckActionLinkage`) и там
	// это ОТКАЗ; авторский ресурс её популяции не принадлежит вовсе, и по нему
	// не будет ни отказа, ни второго слова. Одно число из двух этого различия не
	// показывает, а «ноль ложных обещаний» становится неотличимо от «ноль
	// осмотренных» (задача #1935).
	UnmatchedAuthored int
	// ResourcesWithBaseRoles — ресурсов, объявивших базовые ярусные роли.
	ResourcesWithBaseRoles int
	// BaseRoleTiersDerived — ярусов, ВЫВЕДЕННЫХ из этих объявлений.
	//
	// Печатается рядом с числом ресурсов, а не вместо него: приёмка `#1090`
	// меряет здесь именно расхождение — наивный вывод даёт тридцать ярусов при
	// живых восемнадцати, и одно число из двух этого расхождения не покажет.
	// Величина наблюдаема у инструмента, поэтому неверно расставленный признак
	// виден числом, а не только чтением манифеста.
	BaseRoleTiersDerived int
	// InternalVerbs — действий, объявленных на ВНУТРЕННЕЙ плоскости.
	InternalVerbs int
}

// Summary — перепись строкой. Печатается ВСЕГДА: молчание проверки, не
// прочитавшей ни одного действия, неотличимо от молчания проверившей все.
func (c ClassCensus) Summary() string {
	return fmt.Sprintf(
		"действий каталога %d · ресурсов манифеста %d · действий раздела %d · "+
			"класс удовлетворяет %d · отказов %d · непригодно для роли %d · "+
			"освобождено %d · не сопоставлено %d (из них авторских %d) · "+
			"ресурсов с базовыми ярусами %d · "+
			"ярусов выведено %d · действий внутренней плоскости %d",
		c.ActionsAttributed, c.ResourcesRead, c.VerbsRead,
		c.ClassSatisfies, c.Findings, c.Unsuitable, c.Exempt, c.Unmatched,
		c.UnmatchedAuthored,
		c.ResourcesWithBaseRoles, c.BaseRoleTiersDerived, c.InternalVerbs)
}

// CheckResourceClasses судит объявленный класс каждого действия раздела
// `resources` против гейта того же действия в каталоге прав.
//
// Находки собираются ВСЕ: названная первая заставила бы автора чинить их по
// одной, по прогону на каждую, и скрыла бы, сколько их всего.
func CheckResourceClasses(facts VerbFacts, m *manifest.Manifest, actions []Action) ([]error, []Note, ClassCensus) {
	census := ClassCensus{ActionsAttributed: len(actions)}
	if m == nil {
		return nil, nil, census
	}

	byKey := make(map[string]Action, len(actions))
	for _, a := range actions {
		byKey[a.Module+"."+a.Resource+"."+a.Verb] = a
	}

	var faults []error
	var notes []Note
	for i := range m.Resources {
		r := &m.Resources[i]
		census.ResourcesRead++
		if tiers := r.BaseRoleTiers(); len(tiers) > 0 {
			census.ResourcesWithBaseRoles++
			census.BaseRoleTiersDerived += len(tiers)
		}
		fgaType, _ := authzmap.ObjectType(m.Module, r.Name)
		for _, v := range r.Verbs {
			census.VerbsRead++
			if v.Internal {
				census.InternalVerbs++
			}
			note, fault := judgeVerb(facts, m.Module, r.Name, fgaType,
				r.Producer == "authored", v, byKey, &census)
			if note != nil {
				notes = append(notes, *note)
			}
			if fault != nil {
				faults = append(faults, fault)
			}
		}
	}
	return faults, notes, census
}

// unmatchedSequel — ЧТО БУДЕТ с несопоставленным действием дальше. Ответ зависит
// от `producer` записи, и различитель у пометки под рукой — это ключ той же
// записи манифеста, которую она судит.
//
// # Почему безусловное обещание было ложью на четверти дерева
//
// Пометка обещала читателю, что несопоставленное действие осудит сверка
// соединения (`CheckActionLinkage`), — безусловно. Её популяция ограничена
// `producer: derived`, и это записанное РЕШЕНИЕ, а не упущение: у авторского
// ресурса записи каталога нет by construction, поэтому требовать от него пары
// значило бы требовать того, чего не бывает (linkage.go, §«Популяция
// ограничена…»).
//
// Замер на `release/modules-6`, единица — пометка одного действия: пометок
// печаталось 4, и ВСЕ ЧЕТЫРЕ приходились на авторский `registry.repositories`,
// то есть обещали отказ, которого не будет. Доля ложных — 4 из 4.
//
// Половинчатая правда здесь хуже равномерной ошибки: на порождённом ресурсе
// обещание сбывается, доверие к пометке заслужено — и тратится оно ровно на том
// случае, где она лжёт. Читатель шёл к выводу сверки соединения, видел «без
// записи каталога 0 · вне популяции 1» и заключал одно из двух неверных: что
// пометка ошибочна вообще либо что соседняя сверка сломана. Верный вывод
// («ресурс авторский, пары от него не требуют») из вывода прогона не следовал
// ни одной строкой.
//
// Класс — гипотеза о МЕХАНИЗМЕ: посылка о том, как устроен чужой механизм, взята
// из его назначения, а не из его кода (задача #1935).
func unmatchedSequel(authored bool) string {
	if authored {
		return "Второго слова по нему НЕ БУДЕТ: сверка соединения " +
			"(CheckActionLinkage) авторские ресурсы (`producer: authored`) не судит — " +
			"записи каталога у них нет by construction, и пары от них не требуют. " +
			"Действие остаётся объявленным и негейтящимся; чинится это записью " +
			"каталога у ресурса либо снятием действия из раздела"
	}
	return "Судит несопоставленное действие сверка соединения " +
		"(CheckActionLinkage), и там это ОТКАЗ: она же называет написание, " +
		"которого ждёт каталог"
}

// judgeVerb — вердикт по ОДНОМУ действию раздела; счётчики переписи двигает
// он же, чтобы состояние и его учёт нельзя было рассогласовать.
//
// Возвращает ПОМЕТКУ и ОТКАЗ; ровно одно из двух непусто, а на удовлетворяющем
// классе — оба пусты.
func judgeVerb(facts VerbFacts, module, resource, fgaType string, authored bool,
	v manifest.Verb, byKey map[string]Action, census *ClassCensus) (*Note, error) {

	class := declaredClass(v)
	a, ok := byKey[module+"."+resource+"."+v.Name]
	if !ok {
		census.Unmatched++
		if authored {
			census.UnmatchedAuthored++
		}
		return &Note{
			Kind: NoteActionUnknownToCatalog, Module: module, Resource: resource,
			Verb: v.Name, Class: class,
			Detail: fmt.Sprintf(
				"ресурс %q модуля %q: каталог прав не знает действия %q — класс %q сверить "+
					"не с чем, и по ЭТОЙ оси действие выведено из всех трёх проверок. Здесь "+
					"это пометка, а не отказ: предмет стадии — соответствие КЛАССА гейту, а "+
					"гейта нет. %s",
				resource, module, v.Name, class, unmatchedSequel(authored)),
		}, nil
	}
	if a.Exempt() {
		census.Exempt++
		return &Note{
			Kind: NoteActionExemptFromGate, Module: module, Resource: resource,
			Verb: v.Name, Class: class,
			Detail: fmt.Sprintf(
				"ресурс %q модуля %q: действие %q освобождено от проверки доступа "+
					"(`required_relation` записи каталога пуст) — его получает всякий "+
					"аутентифицированный, а не участник роли. Класс %q объявлен не неверно: "+
					"у класса просто нет предмета, и правом это действие не выдаётся. "+
					"Назвав его в праве роли, автор не получит ни отказа, ни расширения",
				resource, module, v.Name, class),
		}, nil
	}
	if Produces(facts, class, fgaType, a.Relation, a.Object) {
		census.ClassSatisfies++
		return nil, nil
	}
	if fitting := classesSatisfying(facts, a, fgaType); len(fitting) > 0 {
		census.Findings++
		return nil, ClassFinding{
			Kind: ErrDeclaredClassDoesNotSatisfyGate, Module: module, Resource: resource,
			Verb: v.Name, Class: class, Relation: a.Relation, Object: a.Object,
			Detail: mismatchDetail(module, resource, v.Name, class, a, fitting),
		}
	}
	census.Unsuitable++
	return &Note{
		Kind: NoteUnsuitableForRole, Module: module, Resource: resource,
		Verb: v.Name, Class: class, Relation: a.Relation, Object: a.Object,
		Detail: unsuitableDetail(module, resource, v.Name, class, fgaType, a),
	}, nil
}

// declaredClass — класс, объявленный записью действия.
//
// Загрузчик восстанавливает класс короткой формы у себя (единственным вызовом
// правила «класс из имени»), поэтому здесь он уже проставлен. Запасной путь
// оставлен ради вызывающего, собравшего манифест в памяти минуя загрузку, и он
// зовёт ТО ЖЕ правило — второго объявления не заводится.
func declaredClass(v manifest.Verb) string {
	if v.Class != "" {
		return v.Class
	}
	if class, ok := manifest.ClassOfCanonicalVerb(v.Name); ok {
		return class
	}
	return v.Name
}

// classesSatisfying — классы, при которых правило роли ПИШЕТ тот кортеж,
// который спрашивает гейт этого действия.
//
// Словарь-кандидат — набор глаголов ТИПА плюс закрытый набор классов действия:
// первый несёт глаголы, объявленные именно этим типом, второй — `create`, у
// которого пообъектного отношения нет вовсе и который покрывает действие
// ярусом. Ни один из двух здесь не переобъявляется.
func classesSatisfying(facts VerbFacts, a Action, fgaType string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range append(facts.VerbsOfType(fgaType), manifest.CanonicalVerbs()...) {
		if seen[c] {
			continue
		}
		seen[c] = true
		if Produces(facts, c, fgaType, a.Relation, a.Object) {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// mismatchDetail — отказ целиком.
//
// Четыре вещи обязательны, и каждая закрывает свой промах: ЧТО объявлено · ЧЕГО
// требует гейт (пара, а не имя) · ПОЧЕМУ объявленное не годится · ЧЕМ чинится.
// Отказ без починки отправляет автора манифеста искать опечатку у себя.
func mismatchDetail(module, resource, verb, class string, a Action, fitting []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ресурс %q модуля %q: действие %q объявлено классом %q, "+
		"а его гейт спрашивает %s на объекте %q (запись каталога %s). ",
		resource, module, verb, class, a.Relation, a.Object, a.FQN)
	fmt.Fprintf(&b, "Правило роли с классом %q такого кортежа не пишет ни при каком "+
		"написании, поэтому участник роли метод не вызовет, а роль будет выглядеть "+
		"действующей. ", class)
	fmt.Fprintf(&b, "Гейт удовлетворяет класс %s. ", strings.Join(quoted(fitting), " либо "))
	fmt.Fprintf(&b, "Починка: объявить действие объектной формой "+
		"{name: %s, class: %s}.", verb, fitting[0])
	return b.String()
}

// unsuitableDetail — пометка «непригодно для роли» целиком.
//
// Она обязана сказать ТРИ вещи: какую пару спрашивает гейт, почему правило роли
// её не пишет и что отказ по этому действию наступит позже и по другой единице.
// Без третьего автор прочтёт пометку как находку и пойдёт чинить то, чего не
// писал.
func unsuitableDetail(module, resource, verb, class, fgaType string, a Action) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ресурс %q модуля %q: действие %q гейтится %s на объекте %q "+
		"(запись каталога %s). ", resource, module, verb, a.Relation, a.Object, a.FQN)
	switch {
	case fgaType == "":
		fmt.Fprintf(&b, "У пары (%q, %q) нет типа объекта в закрытой таблице модели прав — "+
			"пообъектного указателя на такой ресурс не пишет никто. ", module, resource)
	case authzmap.IsHierarchyScopeType(a.Object):
		b.WriteString("Это ярус ОБЛАСТИ: его кортеж пишет только ярусная роль платформы " +
			"на самой области, а правило-содержимое модуля на объект области не пишет " +
			"ничего. Имя отношения здесь ни при чём — различает ОБЪЕКТ: то же имя на " +
			"объекте типа ресурса производимо. ")
	default:
		b.WriteString("Это прямой userset на объекте, которого правило роли модуля не " +
			"адресует: оно материализует кортежи только на объекте своего типа. ")
	}
	fmt.Fprintf(&b, "Поэтому действие выведено из класса %q: правом роли оно не выдаётся "+
		"ни для полноты перечня, ни для покрытия. ", class)
	b.WriteString("Это НЕ отказ — раздел `resources` порождается из аннотаций контрактов, " +
		"и снять действие автор манифеста не может. Отказ наступит, только если роль " +
		"НАЗОВЁТ это действие поимённо (MOD-RL-19), и годный способ выдать его — не " +
		"роль модуля.")
	return b.String()
}

// quoted — имена в кавычках, чтобы перечень читался как перечень.
func quoted(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, fmt.Sprintf("%q", n))
	}
	return out
}

// Report — вердикт обеих стадий вместе с тем, ИСПОЛНЯЛАСЬ ли вторая.
//
// Третье поле здесь несущее: «стадия 2 молчит» и «стадия 2 не исполнялась» —
// разные вещи, и второе не вычитается из вердикта и не зачитывается в успех.
type Report struct {
	// Faults — отказы обеих стадий; при красной первой — только её.
	Faults []error
	// Notes — пометки стадии 1.
	Notes []Note
	// Classes — перепись стадии 1.
	Classes ClassCensus
	// Rules — перепись стадии 2; нулевая, когда стадия не исполнялась.
	Rules Census
	// RulesJudged — исполнялась ли стадия 2.
	RulesJudged bool
	// Named — перепись стадии 3 (названное вхождение, MOD-RL-19); нулевая,
	// когда стадия не исполнялась.
	Named NamedCensus
	// Export — перепись стадии 4 (полнота поимённого перечня, MOD-RL-18).
	Export ExportCensus
	// NamedJudged — исполнялись ли стадии 3 и 4. Отдельно от `RulesJudged`:
	// «стадия молчит» и «стадия не исполнялась» — разные вещи, и вторая не
	// вычитается из вердикта и не зачитывается в успех.
	NamedJudged bool
}

// Summary — перепись обеих стадий строкой, с прямым указанием на неисполненную.
func (r Report) Summary() string {
	if !r.RulesJudged {
		return r.Classes.Summary() + " | правила ролей: проверка НЕ ИСПОЛНЯЛАСЬ — " +
			"стадия «класс удовлетворяет гейт» красна, и множество, по которому " +
			"считается полнота, ещё не определено"
	}
	if !r.NamedJudged {
		return r.Classes.Summary() + " | правила ролей: " + r.Rules.Summary() +
			" | поимённая форма: проверка НЕ ИСПОЛНЯЛАСЬ — стадия классов правил красна, " +
			"и класс, по которому считается полнота, ещё не определён"
	}
	return r.Classes.Summary() + " | правила ролей: " + r.Rules.Summary() +
		" | " + r.Named.Summary() + " | " + r.Export.Summary()
}

// Check — ЧЕТЫРЕ стадии в ОБЪЯВЛЕННОМ порядке (§3.6 п. 6, MOD-RL-22 Then):
// класс действия → класс правила → НАЗВАННОЕ → ПОЛНОТА названного.
//
// Порядок и замыкание живут ЗДЕСЬ, а не у вызывающего: проверка порядка,
// написанная в команде обхода дерева, не защищала бы второго вызывающего той же
// связки, а «валидирует команду» верно лишь для того пути, который до неё
// доходит.
//
// # Почему названное и его полнота идут ПОСЛЕ, а не рядом
//
// Обе считаются ПО КЛАССУ: пригодность названного действия и полнота перечня
// определены относительно класса, объявленного разделом `resources`. Пока стадия
// 1 красна, класс объявлен не тем, чем его понимает проверка доступа, и «полный»
// перечень оказался бы неполным по факту. Пока красна стадия 2, у роли есть
// пустое право, и вердикт о полноте соседнего был бы вердиктом о роли, которая и
// так не экспортируется.
func Check(facts VerbFacts, m *manifest.Manifest, actions []Action) Report {
	faults, notes, classes := CheckResourceClasses(facts, m, actions)
	rep := Report{Faults: faults, Notes: notes, Classes: classes}
	if len(faults) > 0 {
		return rep
	}
	ruleFaults, ruleCensus := CheckRoleRules(facts, m, actions)
	rep.Faults = append(rep.Faults, ruleFaults...)
	rep.Rules = ruleCensus
	rep.RulesJudged = true
	if len(ruleFaults) > 0 {
		return rep
	}
	namedFaults, namedCensus := CheckNamedVerbs(facts, m, actions)
	rep.Faults = append(rep.Faults, namedFaults...)
	rep.Named = namedCensus
	rep.NamedJudged = true
	if len(namedFaults) > 0 {
		// Полнота перечня, часть которого непригодна, считалась бы по классу,
		// содержащему то, что правом не выдаётся: отказ назвал бы автору
		// недостающие имена, дописать которые он всё равно не вправе.
		return rep
	}
	_, exportFaults, exportCensus := ExportRoleRules(facts, m, actions)
	rep.Faults = append(rep.Faults, exportFaults...)
	rep.Export = exportCensus
	return rep
}
