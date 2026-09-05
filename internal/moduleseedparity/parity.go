// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package moduleseedparity — сверка раздела `seed` манифеста модуля с ЖИВОЙ
// базой (задача #1891, вторая половина её предиката).
//
// # Сверяются ВСЕ ЧЕТЫРЕ подраздела; наружу выведена только НЕВЫРАЗИМОСТЬ
//
// Раздел несёт четыре подраздела — служебные записи, группы, выдачи и
// вступления, — и сверка судит каждый. Из-под вердикта выведена не половина
// раздела, а один ВИД строки: тот, который форма манифеста выразить не может.
//
// Вид назван и ВЫВОДИТСЯ из самой формы, а не объявлен списком: у выдачи есть
// ключ `roleId` и нет ни одного ключа для ОТНОШЕНИЯ, поэтому выдача отношением
// необъявима ни при каком написании; группа необъявима по следствию — валидатор
// связности требует, чтобы заведённая группа была названа выдачей манифеста
// (`ErrGroupNeverGranted`), а такой выдачи у неё нет. Разбор и исходы — #1936.
//
// Невыразимое НЕ ОТБРАСЫВАЕТСЯ молча: [Compare] возвращает его отдельным
// перечнем, потребитель печатает каждую строку по имени, а перепись называет
// его числом. Появится у выдачи ключ отношения — проба предпосылки
// (`TestBindingFormStillCannotExpressARelationGrant`) покраснеет и потребует
// расширить сверку. Ведомости прощённых у гейта нет: прощать нечего, пока форма
// не изменилась, и прощение не понадобится, когда изменится.
//
// # Число границы считается ПО ВЛАДЕЛЬЦУ, и это не педантизм
//
// Здесь стояло одно число на все живые строки — «выдач живых 8, из них
// выразимых формой 0», — и оно складывало два разных предмета. Строка без
// модуля-владельца (`kacho-api-gateway`, `kacho-bootstrap-admin`, `user:*`,
// владельческая привязка системного аккаунта) манифестом МОДУЛЯ невыразима
// by construction: объявлять её некому, и её отсутствие среди объявленного —
// верно, а не пробел. Пробел — только строка, у которой владелец ЕСТЬ, а формы
// нет; таких из восьми **две** (`kacho-compute` и `kacho-vpc` → `system_viewer`).
// Перепись поэтому печатает по каждому подразделу четыре величины: живых ·
// без модуля-владельца · с владельцем · из них формой невыразимых.
//
// # Владелец живой строки выводится ИМЕНЕМ, а не приписывается
//
// Служебная запись модуля названа `kacho-<служба>`; служба переводится в модуль
// закрытого набора платформы (`pkg/platformmodules`). Запись, чьё имя этому не
// отвечает (`kacho-api-gateway`, `kacho-bootstrap-admin`), манифестом модуля
// невыразима by construction — у неё нет модуля-владельца, — и считается
// отдельно. Иначе её отсутствие среди объявленных читалось бы как неполнота.
package moduleseedparity

import (
	"fmt"
	"sort"
	"strings"
)

// ServiceAccount — служебная запись: то, что сверяется, и ничего сверх.
// Идентификатор сюда НЕ входит: живой его производит выражение внутри миграции
// (`'sva' || substr(md5(name), 1, 17)`), то есть он есть частность записи, а не
// то, что объявляет манифест. Сверять по нему значило бы требовать от манифеста
// воспроизвести случайность.
type ServiceAccount struct {
	Account     string
	Name        string
	Description string
}

func (s ServiceAccount) String() string {
	return fmt.Sprintf("%s/%s %q", s.Account, s.Name, s.Description)
}

// Join — вступление служебной записи в чужую группу. Обе стороны адресуются
// ПАРОЙ (аккаунт, имя): так они уникальны в продукте.
type Join struct {
	AccountName  string
	SAName       string
	GroupAccount string
	GroupName    string
}

func (j Join) String() string {
	return fmt.Sprintf("%s/%s → %s/%s", j.AccountName, j.SAName, j.GroupAccount, j.GroupName)
}

// Group — группа, заводимая установкой модуля.
type Group struct {
	Account     string
	Name        string
	Description string
}

func (g Group) String() string {
	return fmt.Sprintf("%s/%s %q", g.Account, g.Name, g.Description)
}

// Binding — выдача, которую делает установка модуля.
//
// Вид субъекта пишется по-МАНИФЕСТНОМУ (`serviceAccount`, `group`): второе
// написание того же предмета разошлось бы с первым, поэтому перевод живой
// строки (`service_account`) делается ОДИН раз, на чтении, а не по месту
// сравнения.
//
// Якорь области хранится в точечной форме (`iam.cluster`) — так его пишет
// манифест, и так же переводится живая пара `resource_type`/`resource_id`.
type Binding struct {
	SubjectType string
	SubjectName string
	// RoleID — выдача РОЛЬЮ: единственная форма, которую манифест умеет
	// объявить.
	RoleID string
	// Relation — выдача ОТНОШЕНИЕМ. Ключа для неё у формы манифеста нет ни
	// одного, поэтому строка с непустым Relation невыразима by construction
	// (#1936). Поле здесь ради того, чтобы это было ВИДНО, а не выпадало из
	// чтения молча.
	Relation  string
	ScopeType string
	ScopeID   string
}

func (b Binding) String() string {
	granted := "роль " + b.RoleID
	if b.Relation != "" {
		granted = "отношение " + b.Relation
	}
	return fmt.Sprintf("%s %s → %s на %s/%s", b.SubjectType, b.SubjectName, granted, b.ScopeType, b.ScopeID)
}

// ЗДЕСЬ СТОЯЛ ПРЕДИКАТ `ExpressibleByForm` — он СНЯТ ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ
// (#1936).
//
// Предикат отвечал «умеет ли форма манифеста объявить эту выдачу» и был выведен
// из формы: ключ роли у неё был, ключа отношения не было ни одного. Он сам
// объявлял своё истечение — «появится ключ, и предикат обязан быть снят вместе
// с ней», — ключ появился (`grantedRelation`), и предикат снят, а не приведён к
// тождественному «да». Тождественное «да» осталось бы ветвью, которая ничего не
// решает, и следующий читатель искал бы у неё смысл.
//
// Вместе с ним сняты `SplitBindings`, `SplitGroups` и перечень `Inexpressible`:
// у них не осталось предмета — невыразимого вида строки больше нет. Оставить их
// значило бы держать исключение, которому нечего исключать, и оно не истекло бы
// уже никогда.

// ModuleState — обе стороны сверки по одному модулю.
//
// Живые строки приходят сюда УЖЕ отнесёнными к модулю-владельцу: строки без
// владельца сверке не подлежат и считаются переписью отдельно.
type ModuleState struct {
	Module          string
	ManifestFile    string
	DeclaredSA      []ServiceAccount
	LiveSA          []ServiceAccount
	DeclaredGroup   []Group
	LiveGroup       []Group
	DeclaredBinding []Binding
	LiveBinding     []Binding
	DeclaredJoin    []Join
	LiveJoin        []Join
}

// Subsection — перепись одного подраздела посева.
//
// Величин ТРИ, и ни одну нельзя выбросить, не потеряв различия, ради которого
// перепись и печатается: `Live` отвечает, читалось ли вообще что-то;
// `Ownerless` отделяет невыразимое by construction (объявлять некому) от
// пробела; `Owned` называет предмет сверки. Одно число вместо трёх скрывало бы
// ровно тот случай, ради которого граница названа.
//
// ЧЕТВЁРТАЯ величина здесь была — `Inexpressible`, «та часть предмета, которой
// форма не умеет», — и снята вместе со своим предметом (#1936): форма научилась
// выражать выдачу отношением, невыразимого вида строки не осталось. Величина,
// тождественно равная нулю, перепись не уточняет, а разбавляет: читатель ищет у
// неё смысл и не находит.
type Subsection struct {
	Declared  int
	Live      int
	Ownerless int
	Owned     int
}

func (s Subsection) String() string {
	return fmt.Sprintf("объявлено %d · живых %d · без модуля-владельца %d · с владельцем %d",
		s.Declared, s.Live, s.Ownerless, s.Owned)
}

// Census — объём осмотренного. Печатается ВСЕГДА и ДО вердикта: «находок ноль»
// обязано быть отличимо от «прочитано ноль».
type Census struct {
	Manifests int
	SA        Subsection
	Groups    Subsection
	Bindings  Subsection
	Joins     Subsection
}

func (c Census) String() string {
	return fmt.Sprintf(
		"манифестов %d\n    служебные записи: %s\n    группы:           %s\n"+
			"    выдачи:           %s\n    вступления:       %s",
		c.Manifests, c.SA, c.Groups, c.Bindings, c.Joins)
}

// Result — исход сверки.
//
// Перечень ОДИН. Их было два, и различие было несущим: расхождение чинилось
// правкой манифеста, невыразимое — правкой ФОРМЫ, разными людьми в разных
// изменениях, и сложить их значило бы требовать от автора манифеста починить
// то, чего он написать не может.
//
// Второй перечень снят вместе со своим предметом (#1936): форма научилась
// выражать выдачу отношением, и строк, которых автор написать не может, не
// осталось. Держать пустой перечень значило бы держать исключение, которому
// нечего исключать, — оно не истекло бы уже никогда.
type Result struct {
	// Findings — расхождения объявленного с живым. Гейт на них падает.
	Findings []string
}

// Compare сравнивает объявленное с живым по каждому модулю.
//
// Расхождение называется В ОБЕ СТОРОНЫ: строка живая и не объявленная —
// манифест неполон; объявленная и не живая — манифест обещает то, чего
// установка не завела. Второе не мягче первого: применитель, когда он появится,
// заведёт по объявлению.
//
// Обход ОДИН: перечни находок и невыразимого производятся вместе, поэтому
// вызывающий не может прочитать один и забыть про другой.
func Compare(states []ModuleState) Result {
	var res Result
	for _, st := range states {
		res.Findings = append(res.Findings, diffSet(st,
			"служебная запись ЖИВЁТ и не объявлена",
			"служебная запись ОБЪЯВЛЕНА и не живёт",
			keysOfSA(st.DeclaredSA), keysOfSA(st.LiveSA))...)
		res.Findings = append(res.Findings, diffSet(st,
			"вступление ЖИВЁТ и не объявлено",
			"вступление ОБЪЯВЛЕНО и не живёт",
			keysOfJoin(st.DeclaredJoin), keysOfJoin(st.LiveJoin))...)

		res.Findings = append(res.Findings, diffSet(st,
			"выдача ЖИВЁТ и не объявлена",
			"выдача ОБЪЯВЛЕНА и не живёт",
			keysOfBinding(st.DeclaredBinding), keysOfBinding(st.LiveBinding))...)

		res.Findings = append(res.Findings, diffSet(st,
			"группа ЖИВЁТ и не объявлена",
			"группа ОБЪЯВЛЕНА и не живёт",
			keysOfGroup(st.DeclaredGroup), keysOfGroup(st.LiveGroup))...)
	}
	sort.Strings(res.Findings)
	return res
}

// diffSet — обе стороны одного подраздела. Формулировки передаются целиком, а
// не склеиваются из имени подраздела: «запись» и «вступление» разного рода, и
// склейка дала бы отказ, который читается как опечатка в самом гейте.
func diffSet(st ModuleState, liveOnly, declaredOnly string, declared, live map[string]string) []string {
	var findings []string
	for k, text := range live {
		if _, ok := declared[k]; !ok {
			findings = append(findings, fmt.Sprintf("модуль %s (%s): %s: %s",
				st.Module, st.ManifestFile, liveOnly, text))
		}
	}
	for k, text := range declared {
		if _, ok := live[k]; !ok {
			findings = append(findings, fmt.Sprintf("модуль %s (%s): %s: %s",
				st.Module, st.ManifestFile, declaredOnly, text))
		}
	}
	return findings
}

func keysOfSA(in []ServiceAccount) map[string]string {
	out := map[string]string{}
	for _, s := range in {
		out[strings.Join([]string{s.Account, s.Name, s.Description}, "\x00")] = s.String()
	}
	return out
}

func keysOfJoin(in []Join) map[string]string {
	out := map[string]string{}
	for _, j := range in {
		out[strings.Join([]string{j.AccountName, j.SAName, j.GroupAccount, j.GroupName}, "\x00")] = j.String()
	}
	return out
}

// SubjectTypeGroup / SubjectTypeServiceAccount — написание вида субъекта,
// принятое МАНИФЕСТОМ. Живая строка переводится в него ОДИН раз, на чтении:
// второе написание того же предмета разошлось бы с первым молча.
const (
	SubjectTypeGroup          = "group"
	SubjectTypeServiceAccount = "serviceAccount"
)

func keysOfBinding(in []Binding) map[string]string {
	out := map[string]string{}
	for _, b := range in {
		out[strings.Join([]string{b.SubjectType, b.SubjectName, b.RoleID, b.Relation, b.ScopeType, b.ScopeID}, "\x00")] = b.String()
	}
	return out
}

func keysOfGroup(in []Group) map[string]string {
	out := map[string]string{}
	for _, g := range in {
		out[strings.Join([]string{g.Account, g.Name, g.Description}, "\x00")] = g.String()
	}
	return out
}
