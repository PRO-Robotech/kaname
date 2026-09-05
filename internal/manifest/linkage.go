// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// linkage.go — СВЯЗНОСТЬ манифеста: то, что форма выразить не способна
// (приёмка §2.3, §5.4, §5.7; сценарии MOD-MF-13…16 и 23…26).
//
// Форма отвечает на вопрос «так ли написано», связность — на вопрос «есть ли у
// написанного предмет». Разделение не стилистическое, оно измерено: схема на
// трёх свойствах выдач МОЛЧИТ (роль вне перечня ролей · субъект вне посева ·
// группа без выдачи), а на четвёртом краснеет ложным диагнозом — говорит о
// лишнем свойстве там, где предмет в типе ключа.
//
// # Правило `joins` ДРУГОЕ, и это по построению, а не по недосмотру
//
// Вступают в ЧУЖУЮ группу, объявленную другим манифестом: членство заявляет
// вступающий, а владелец группы своих потребителей не знает и знать не должен.
// Поэтому требовать присутствия группы вступления в `seed.groups` НЕЛЬЗЯ —
// требование покраснело бы на настоящем манифесте vpc, чья единственная группа
// вступления (`module-quota-readers`) посевом не заводится. Проверено прогоном
// валидатора черновика: «ВЕРДИКТ: целостно» при `вступлений 1`.
//
// Асимметрия — именно в ГРУППЕ. Служебная запись вступления, наоборот, обязана
// быть заведена этим же посевом: вступает СВОЯ личность модуля, чужую он
// вписать не вправе.
//
// # Почему находки собираются ВСЕ, а не первая
//
// Назвав первую, валидатор заставил бы автора манифеста чинить их по одной, по
// прогону на каждую, и скрыл бы, сколько их всего. Тот же довод, по которому
// checkStringKeys собирает каждый ключ-нестроку.
//
// # Почему отказ называет ПУТЬ и СТРОКУ
//
// «Связность нарушена» — не отказ, а его отсутствие: читатель идёт искать
// вручную. Путь (`seed.accessBindings[1].roleId`) адресует место в структуре,
// номер строки — в документе; вместе они находят предмет без чтения кода
// загрузчика.

// Виды находок различаются не ради красоты: «роль не объявлена», «субъект не
// заведён», «группа ничего не несёт», «сторона адресована не парой» чинятся
// разными правками, и вызывающий (цель сборки, читающая дерево) вправе их
// различать.
var (
	// ErrRoleNotDeclared — выдача ссылается на роль, которой манифест не
	// объявляет. Форма идентификатора при этом годна — схема тут молчит.
	ErrRoleNotDeclared = errors.New("manifest: accessBinding grants a role the manifest does not declare")
	// ErrSubjectNotSeeded — субъект выдачи не заведён ЭТИМ ЖЕ посевом.
	ErrSubjectNotSeeded = errors.New("manifest: accessBinding subject is not seeded by this manifest")
	// ErrGroupNeverGranted — заведённая группа не названа ни в одной выдаче:
	// объявление без следствия, право, за которым никто не отвечает.
	ErrGroupNeverGranted = errors.New("manifest: seeded group is granted nothing")
	// ErrJoinServiceAccountNotSeeded — вступает запись, которой посев не
	// заводит. Симметричного отказа по ГРУППЕ вступления не существует и не
	// должно: она чужая by construction.
	ErrJoinServiceAccountNotSeeded = errors.New("manifest: join service account is not seeded by this manifest")
	// ErrJoinReasonMissing — вступление не говорит, зачем оно. Членство без
	// причины некому снять: следующий не знает, действует ли ещё основание.
	ErrJoinReasonMissing = errors.New("manifest: join does not say why")
	// ErrRefNotAPair — сторона вступления адресована не парой (аккаунт, имя).
	ErrRefNotAPair = errors.New("manifest: reference is not a pair (account, name)")
	// ErrBindingIncomplete — выдача не назвала, ЧТО она выдаёт, ГДЕ и НА ЧТО.
	// Форм выдачи ДВЕ и они взаимоисключающи (`roleId` либо `grantedRelation`);
	// сверх ровно одной из них выдача обязана назвать `scopeType`, `scopeId` и
	// `target`. Без любого из этих ключей выдача неисполнима, а не «частична».
	ErrBindingIncomplete = errors.New("manifest: accessBinding is incomplete")
	// ErrRelationNotDeclared — выдача называет отношение, которого канон модели
	// прав у типа якоря не объявляет. Отличается от ErrRelationComputed: там
	// отношение есть и выдать его напрямую нечем, здесь его нет вовсе.
	ErrRelationNotDeclared = errors.New("manifest: accessBinding grants a relation the canon does not declare")
	// ErrRelationComputed — отношение объявлено ВЫЧИСЛЯЕМЫМ: прямых записей
	// субъекта у него нет, значит выдать его напрямую нечем. Свой вид, а не
	// «вид получателя не принят»: схлопнув их, судья назвал бы неверный предмет,
	// и автор чинил бы получателя там, где чинить надо выбор отношения.
	ErrRelationComputed = errors.New("manifest: accessBinding grants a computed relation")
	// ErrRelationRecipientKind — объявление отношения не принимает получателя
	// названного вида. Судится по канону, а не по второму перечню.
	ErrRelationRecipientKind = errors.New("manifest: relation does not admit this recipient kind")
	// ErrBindingAnchor — выдача посева объявлена не на кластерном singleton'е.
	//
	// Вид называет ВЫДАЧУ, а не форму выдачи: якорь есть свойство самой выдачи,
	// и обе её формы — роль и отношение — судятся им одинаково (#1953). Прежнее
	// имя (`ErrRelationAnchor`) и его оговорка «выдачи ролью не касается» были
	// верны ровно до этой работы и стали бы ложью, пережившей свой предмет.
	ErrBindingAnchor = errors.New("manifest: seed access binding is anchored outside the cluster singleton")
	// ЗДЕСЬ СТОЯЛ ErrCanonUnparsed — сигнал «канон модели прав не разобрался».
	// Он снят ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ (#2002): загрузчик больше не добывает
	// модель сам, поэтому состояния «пошли за моделью и не получили её» у него
	// не существует ни при каком входе. Модель либо внесена вызывающим и
	// разобрана им, либо не внесена — и тогда об объявлении отношения не
	// утверждается ничего.
	//
	// Оставленный сигнал был бы вариантом, которого код никогда не производит:
	// он документировал бы контракт, не имеющий входа, и следующий читатель
	// чинил бы под него ветку, которой нет.
	// ErrSeededSubjectIncomplete — заведомая запись посева не назвала себя
	// целиком: имя, аккаунт либо назначение. Отдельный вид от связности:
	// связность спрашивает, есть ли у названного предмет, а здесь предмет ещё
	// не назван.
	ErrSeededSubjectIncomplete = errors.New("manifest: seeded subject is incomplete")
)

// minJoinReasonRunes — предел длины причины вступления, объявленный схемой
// (`why.minLength: 12`).
//
// Меряется в ЗНАКАХ, а не в байтах, и это не педантизм: причина здесь пишется
// по-русски, кириллический знак весит два байта, и проверка по `len` пропустила
// бы вдвое более короткую причину, чем латинская. Расхождение тихое — оба
// варианта выглядят работающими на английском входе.
const minJoinReasonRunes = 12

// minProseRunes — предел длины прозы, которую манифест АВТОРствует: описание
// группы, описание служебной записи, причина устаревания глагола и предикат его
// снятия. Объявлен схемой (`minLength: 16`) у всех четырёх сразу.
//
// # Назначения роли здесь БОЛЬШЕ НЕТ, и это не послабление, а другой предмет
//
// Пятым полем стояло `roles[].description`, и предел был для него негоден по
// ОБЕИМ причинам, ради которых предел вообще заводят (#1904). Разбор и
// доказательство живым набором — `roles.go` §«Назначение роли судится
// НАЛИЧИЕМ»; здесь названо только то, чем эти четыре от него отличаются:
// каждое из них манифест ПИШЕТ ВПЕРВЫЕ. Группы и служебной записи, о которых
// идёт речь, до применения манифеста не существует, у глагола нет ни причины,
// ни предиката снятия, пока их не назвали. Автору ничто не мешает написать их
// как следует, и предел поднимает пол.
//
// У назначения роли писатель ПРЕДШЕСТВУЮЩИЙ — применённая миграция, — а
// применитель кладёт объявленное ДОСЛОВНО поверх живой строки. Манифест там не
// авторствует, а переписывает, и предел не поднимает пол, а запрещает переписать.
//
// # Почему предел повторён здесь, а не выведен из схемы
//
// Схема — файл JSON за границей `internal`, и разбирать его на пути загрузки
// значило бы поставить чтение чужого документа в тракт, который обязан работать
// без него. Расхождение при этом невозможно МОЛЧА: перепись требовательности
// (`requiredness_internal_test.go`) портит вход РОВНО ДО объявленной схемой
// границы и требует отказа, поэтому смена предела в схеме краснит гейт в тот же
// прогон. Два места об одном предмете здесь держит проверка, а не обещание.
//
// # Почему предел вообще есть, а не «лишь бы непусто»
//
// Пустое описание и описание в один знак различаются только на вид: оба не
// отвечают на вопрос, ради которого поле заведено, — выдавать ли эту роль,
// зачем эта группа, под что эта личность. Предел не делает прозу хорошей, он
// отсекает отписку, поставленную ради прохождения проверки.
const minProseRunes = 16

// proseShorterThan — проза короче предела, считая ЗНАКАМИ, а не байтами.
//
// Знаками, потому что проза здесь пишется по-русски, кириллический знак весит
// два байта, и проверка по `len` пропустила бы вдвое более короткий текст, чем
// латинский. Расхождение тихое: на английском входе оба варианта выглядят
// работающими. Тот же довод уже записан у причины вступления.
func proseShorterThan(s string, bound int) bool {
	return utf8.RuneCountInString(strings.TrimSpace(s)) < bound
}

// seedableSubjectTypes — виды субъектов, которые посев модуля ЗАВОДИТ.
//
// Человека (`user`) установка модуля не заводит ни при каком входе, поэтому
// субъект-человек посевом не заведён — тот же отказ MOD-MF-14, а не второе
// правило. Пропустить его молча значило бы завести вид субъекта, для которого
// проверка не делает ничего: типовая опечатка в имени уехала бы в выдачу.
// Кроме того, право на многих выдаётся ГРУППЕ, а не перечислением людей
// (`data-integrity.md` §B18) — поимённой выдаче человека при установке модуля
// предмета нет.
var seedableSubjectTypes = []string{"group", "serviceAccount"}

// LinkageCensus — объём, осмотренный валидатором связности.
//
// «Ноль находок» обязано быть отличимо от «ноль прочитанного»: валидатор, не
// заглянувший ни в одну выдачу, молчит ровно так же уверенно, как проверивший
// все. Обе величины по оси ролей печатаются РЯДОМ (сверено X из Y) — одно число
// скрыло бы ровно тот случай, ради которого перепись заведена.
type LinkageCensus struct {
	// BindingsRead — выдач прочитано.
	BindingsRead int
	// SubjectsResolved — субъектов разрешено: найдены среди заведённых посевом.
	SubjectsResolved int
	// GroupsDeclared — групп заведено посевом.
	GroupsDeclared int
	// JoinsRead — вступлений прочитано.
	JoinsRead int
	// RoleRefsRead — ссылок на роль прочитано.
	RoleRefsRead int
	// RoleRefsChecked — из них сверено с объявленными ролями.
	RoleRefsChecked int
	// RolesDeclared — объявлял ли манифест раздел ролей вообще.
	RolesDeclared bool
	// RelationGrantsRead — выдач ОТНОШЕНИЕМ прочитано.
	RelationGrantsRead int
	// RelationGrantsJudged — из них суждено против ВНЕСЁННОЙ модели.
	//
	// Две величины стоят рядом намеренно. Модель вносит вызывающий (#2002), и на
	// пути старта она не вносится вовсе — там существование судит композиция,
	// у которой ответ авторитетен. Одно число скрыло бы ровно этот случай: ноль
	// суждённых читался бы как «сверили и не нашли расхождений», тогда как он
	// означает «не сверяли, и это решено».
	RelationGrantsJudged int
}

// String — перепись одной строкой; её печатает потребитель загрузчика.
func (c LinkageCensus) String() string {
	s := fmt.Sprintf(
		"выдач прочитано %d · субъектов разрешено %d · групп заведено %d · вступлений прочитано %d · roleId сверено %d из %d · выдач отношением суждено %d из %d",
		c.BindingsRead, c.SubjectsResolved, c.GroupsDeclared, c.JoinsRead, c.RoleRefsChecked, c.RoleRefsRead,
		c.RelationGrantsJudged, c.RelationGrantsRead)
	if !c.RolesDeclared {
		// Ноль сверенных обязан объяснять СЕБЯ: иначе он читается как «сверили
		// и не нашли расхождений». Раздел `roles` описан загрузчиком (#1778),
		// поэтому единственная причина здесь — автор его не объявил.
		s += " — раздел roles манифестом не объявлен"
	}
	return s
}

// roleIDs — идентификаторы ролей, объявленные манифестом.
//
// Состояний ТРИ, а не два: раздел не объявлен · объявлен и пуст · объявлен с
// перечнем. Первое означает «сверять не с чем», второе — «автор сказал, что
// ролей у него нет», и всякая выдача тогда ссылается в пустоту. Схлопни их в
// одно — и правило замолчит ровно там, где автор ошибся: написал пустой раздел
// и раздал права.
type roleIDs struct {
	declared bool
	ids      map[string]struct{}
}

// rolesNotDeclared — раздел ролей манифестом не объявлен.
func rolesNotDeclared() roleIDs { return roleIDs{} }

// rolesDeclared — раздел объявлен; перечень может быть и пустым.
func rolesDeclared(ids ...string) roleIDs {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return roleIDs{declared: true, ids: set}
}

func (r roleIDs) has(id string) bool {
	_, ok := r.ids[id]
	return ok
}

// list — объявленные роли перечнем, для текста отказа: автор обязан узнать не
// только что ошибся, но и чем это чинится.
func (r roleIDs) list() string {
	if len(r.ids) == 0 {
		return "перечень пуст"
	}
	out := make([]string, 0, len(r.ids))
	for id := range r.ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// docCoord — координата места в документе: путь по структуре и номер строки.
type docCoord struct {
	path string
	line int
}

// linkFault — одна находка связности.
type linkFault struct {
	kind   error
	coord  docCoord
	detail string
}

func (f linkFault) Error() string {
	if f.coord.line > 0 {
		return fmt.Sprintf("%s: %s (line %d): %s", f.kind, f.coord.path, f.coord.line, f.detail)
	}
	return fmt.Sprintf("%s: %s: %s", f.kind, f.coord.path, f.detail)
}

// Unwrap — чтобы вызывающий различал ВИД находки (errors.Is), а не разбирал
// прозу сообщения.
func (f linkFault) Unwrap() error { return f.kind }

// locate — путь и номер строки места, адресованного шагами: строка — ключ
// отображения, целое — индекс списка.
//
// Если шаг не разрешается (ключа нет вовсе — а это и есть случай «не сказано,
// зачем вступаем»), строка берётся у ближайшего разрешённого предка: указать на
// отсутствующий ключ нечем, а на вступление, где его не хватает, — есть.
func locate(doc *yaml.Node, steps ...any) docCoord {
	n := doc
	c := docCoord{}
	if n != nil {
		c.line = n.Line
	}
	for _, step := range steps {
		switch v := step.(type) {
		case string:
			if c.path == "" {
				c.path = v
			} else {
				c.path += "." + v
			}
			n = mapValue(n, v)
		case int:
			c.path += fmt.Sprintf("[%d]", v)
			n = seqItem(n, v)
		}
		if n != nil {
			c.line = n.Line
		}
	}
	return c
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func seqItem(n *yaml.Node, i int) *yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode || i < 0 || i >= len(n.Content) {
		return nil
	}
	return n.Content[i]
}

// validateSeedLinkage — валидатор связности. Возвращает перепись всегда и
// перечень находок, если они есть.
//
// Порядок обхода — порядок документа: выдачи (роль, затем субъекты) · группы ·
// вступления. Он детерминирован, поэтому отказ на одном и том же документе
// читается одинаково от прогона к прогону.
func validateSeedLinkage(m *Manifest, doc *yaml.Node, roles roleIDs, oracle RelationOracle) (LinkageCensus, []error) {
	census := LinkageCensus{RolesDeclared: roles.declared}
	if m == nil || m.Seed == nil {
		return census, nil
	}
	seed := m.Seed
	census.BindingsRead = len(seed.AccessBindings)
	census.GroupsDeclared = len(seed.Groups)
	census.JoinsRead = len(seed.Joins)

	// Субъект выдачи адресуется ОДНИМ именем: поля аккаунта у него нет вовсе —
	// он называет то, что завёл этот же посев, а посев весь лежит в одном
	// аккаунте своего модуля. Асимметрия с парой у вступлений — свойство
	// данных, а не разных правил: вступление адресует ЧУЖУЮ сторону, и один
	// аккаунт там не подразумевается.
	seededAccounts := namesOfServiceAccounts(seed.ServiceAccounts)
	seededGroups := namesOfGroups(seed.Groups)

	var faults []error
	grantedGroups := map[string]struct{}{}

	for i, b := range seed.AccessBindings {
		// Полнота выдачи судится ДО связности, и порядок здесь содержателен:
		// «роль не объявлена» о ПУСТОМ идентификаторе отправило бы автора
		// сверять перечень ролей, тогда как роль он просто не назвал. Отказ
		// обязан называть поле и правило, а не ближайшее следствие.
		// Форма выдачи судится ОТДЕЛЬНО от остальных ключей: их у неё две, они
		// взаимоисключающи, и «названы обе» есть находка, а не отсутствие
		// ключа. Прежде здесь стояло требование именно `roleId` — довод «выдача
		// не сказала, ЧТО она выдаёт» остался верным, а требование стало
		// однобоким (#1936).
		faults = append(faults, validateGrantForm(doc, i, b)...)

		// Якорь судится ПО ЗНАЧЕНИЮ и ОДНИМ судьёй на обе формы выдачи: он есть
		// свойство самой выдачи, а не того, чем она наделяет (#1953). Тип
		// объекта разбирается здесь один раз и отдаётся канону ниже — второго
		// резолва того же значения в дереве нет.
		anchorObjectType, anchorUsable, anchorFaults := validateGrantAnchor(doc, i, b)
		faults = append(faults, anchorFaults...)

		for _, need := range []struct{ key, value, why string }{
			{"scopeType", b.ScopeType, "выдача не сказала, на каком ярусе она действует"},
			{"scopeId", b.ScopeID, "выдача не сказала, на каком объекте яруса она действует"},
			{"target", b.Target, "выдача не сказала, распространяется ли она на весь ярус либо на перечень объектов"},
		} {
			if strings.TrimSpace(need.value) != "" {
				continue
			}
			faults = append(faults, linkFault{
				kind:  ErrBindingIncomplete,
				coord: locate(doc, "seed", "accessBindings", i),
				detail: fmt.Sprintf("seed.accessBindings[%d].%s: ключ не назван — %s",
					i, need.key, need.why),
			})
		}

		faults = append(faults, validateBindingTarget(doc, i, b, bindingResourcesDeclared(doc, i))...)

		census.RoleRefsRead++
		if roles.declared && b.RoleID != "" {
			census.RoleRefsChecked++
			if !roles.has(b.RoleID) {
				faults = append(faults, linkFault{
					kind:  ErrRoleNotDeclared,
					coord: locate(doc, "seed", "accessBindings", i, "roleId"),
					detail: fmt.Sprintf("роль %q манифестом не объявлена; объявлены: %s",
						b.RoleID, roles.list()),
				})
			}
		}

		// seededSubjects — номера субъектов, которых этот же посев ЗАВОДИТ.
		// Только они доходят до канона: вид, посевом не заводимый (человек),
		// отвергается ниже, и назвать канон его виновником значило бы отправить
		// автора чинить не то — канон человека как раз принимает. Порядок двух
		// проверок объявлен здесь, а не выведен из порядка чтения полей.
		var seededSubjects []int

		for j, s := range b.Subjects {
			if s.Type == "group" {
				grantedGroups[s.Name] = struct{}{}
			}
			coord := locate(doc, "seed", "accessBindings", i, "subjects", j)
			switch {
			case !contains(seedableSubjectTypes, s.Type):
				faults = append(faults, linkFault{
					kind:  ErrSubjectNotSeeded,
					coord: coord,
					detail: fmt.Sprintf(
						"субъект вида %q посев модуля не заводит: он заводит %s; выдача такому субъекту заводится не установкой модуля",
						s.Type, strings.Join(seedableSubjectTypes, " и ")),
				})
			case s.Type == "group" && !hasName(seededGroups, s.Name):
				faults = append(faults, linkFault{
					kind:  ErrSubjectNotSeeded,
					coord: coord,
					detail: fmt.Sprintf("группы %q не заводит seed.groups; заведены: %s",
						s.Name, listOrEmpty(seededGroups)),
				})
			case s.Type == "serviceAccount" && !hasName(seededAccounts, s.Name):
				faults = append(faults, linkFault{
					kind:  ErrSubjectNotSeeded,
					coord: coord,
					detail: fmt.Sprintf("записи %q не заводит seed.serviceAccounts; заведены: %s",
						s.Name, listOrEmpty(seededAccounts)),
				})
			default:
				census.SubjectsResolved++
				seededSubjects = append(seededSubjects, j)
			}
		}

		// Канон спрашивается ПОСЛЕДНИМ и только у формы отношения: у формы роли
		// предмета нет — роль раздаёт глаголы своими правилами.
		//
		// Непригодный якорь канон не спрашивает: тип объекта, у которого
		// спрашивать, даёт именно он. Спросить всё равно значило бы выдать
		// второй отказ за одну ошибку — и отправить автора чинить отношение
		// там, где неверен якорь.
		if strings.TrimSpace(b.GrantedRelation) != "" {
			census.RelationGrantsRead++
			if oracle != nil {
				census.RelationGrantsJudged++
			}
		}
		if anchorUsable {
			faults = append(faults, validateRelationGrant(doc, i, b, anchorObjectType, seededSubjects, oracle)...)
		}
	}

	for i, sa := range seed.ServiceAccounts {
		faults = append(faults, validateSeededProse(doc, "serviceAccounts", i,
			sa.Name, sa.Account, sa.Description,
			"под что ИМЕННО эта личность модуля")...)
	}

	for i, g := range seed.Groups {
		faults = append(faults, validateSeededProse(doc, "groups", i,
			g.Name, g.Account, g.Description,
			"кого эта группа собирает и зачем")...)
	}

	for i, g := range seed.Groups {
		if _, ok := grantedGroups[g.Name]; ok {
			continue
		}
		faults = append(faults, linkFault{
			kind:  ErrGroupNeverGranted,
			coord: locate(doc, "seed", "groups", i),
			detail: fmt.Sprintf(
				"группа %q заведена и не названа ни в одной выдаче: имя без предмета — "+
					"выдайте ей роль либо отношение в seed.accessBindings, либо не заводите",
				g.Name),
		})
	}

	for i, j := range seed.Joins {
		faults = append(faults, validateJoin(doc, i, j, seededAccounts)...)
	}
	return census, faults
}

// Виды выдачи по охвату. Перечень закрыт схемой (`target.enum`); здесь названы
// оба, потому что правило о перечне объектов зависит от того, КОТОРЫЙ выбран.
const (
	bindingTargetAllInScope = "allInScope"
	bindingTargetResources  = "resources"
)

// bindingResourcesDeclared — назван ли ключ `resources` у выдачи В ДОКУМЕНТЕ.
//
// Состояний ТРИ, а не два, и различает их присутствие самого ключа: «не назван»
// значит «выдача на весь ярус», «назван и пуст» — «автор сказал, что объектов
// нет», и тогда выдача не покрывает НИ ОДНОГО объекта при действующей на вид
// привязке. Схлопни их в одно — и правило замолчит ровно там, где автор ошибся.
// Тот же довод, по которому перечень ролей читается из разобранного документа.
func bindingResourcesDeclared(doc *yaml.Node, i int) bool {
	seed := mapValue(doc, "seed")
	if seed == nil {
		return false
	}
	return mapValue(seqItem(mapValue(seed, "accessBindings"), i), "resources") != nil
}

// validateBindingTarget — охват выдачи и перечень объектов согласованы, а сам
// перечень назвал каждый объект парой (тип, идентификатор).
//
// Правило ОДНО на оба вида охвата намеренно: «перечень обязателен при
// `resources`» и «перечень не читается при `allInScope`» суть две половины
// одного утверждения, и разведённые по разным местам они разошлись бы на первом
// же уточнении — тот самый класс «два правила об одном поле».
func validateBindingTarget(doc *yaml.Node, i int, b AccessBinding, declared bool) []error {
	var faults []error
	switch {
	case declared && len(b.Resources) == 0:
		faults = append(faults, linkFault{
			kind:  ErrBindingIncomplete,
			coord: locate(doc, "seed", "accessBindings", i, "resources"),
			detail: fmt.Sprintf("seed.accessBindings[%d].resources: перечень назван и пуст — "+
				"выдача не покрывает НИ ОДНОГО объекта; привязка при этом создаётся и выглядит "+
				"действующей, а доступа не даёт", i),
		})
	case b.Target == bindingTargetResources && !declared:
		faults = append(faults, linkFault{
			kind:  ErrBindingIncomplete,
			coord: locate(doc, "seed", "accessBindings", i, "target"),
			detail: fmt.Sprintf("seed.accessBindings[%d]: охват назван %q, а перечня объектов нет — "+
				"выдаче не на что распространяться", i, bindingTargetResources),
		})
	case b.Target == bindingTargetAllInScope && declared:
		faults = append(faults, linkFault{
			kind:  ErrBindingIncomplete,
			coord: locate(doc, "seed", "accessBindings", i, "resources"),
			detail: fmt.Sprintf("seed.accessBindings[%d]: охват назван %q — выдача покрывает весь "+
				"ярус и БУДУЩИЕ объекты тоже, поэтому перечень при нём не читает никто; "+
				"написанный, он утверждает сужение, которого не будет", i, bindingTargetAllInScope),
		})
	}

	for j, res := range b.Resources {
		for _, need := range []struct{ key, value, why string }{
			{"type", res.Type, "не сказано, объект какого типа выдаётся"},
			{"id", res.ID, "не назван неизменяемый идентификатор объекта; имя внешней адресации " +
				"не несёт и меняется свободно, поэтому выдача по имени пережила бы переименование молча"},
		} {
			if strings.TrimSpace(need.value) != "" {
				continue
			}
			faults = append(faults, linkFault{
				kind:  ErrBindingIncomplete,
				coord: locate(doc, "seed", "accessBindings", i, "resources", j),
				detail: fmt.Sprintf("seed.accessBindings[%d].resources[%d].%s: ключ не назван — %s",
					i, j, need.key, need.why),
			})
		}
	}
	return faults
}

// validateSeededProse — заводимая посевом запись назвала себя целиком.
//
// Служебная запись и группа судятся ОДНИМ правилом намеренно: это однородные
// вещи, и разное требование к однородным вещам само по себе расхождение —
// ровно то, что уже сказано комментарием фикстуры про `description`. Второе
// правило для второй записи разошлось бы с первым на первом же уточнении.
func validateSeededProse(doc *yaml.Node, section string, i int,
	name, account, description, purpose string) []error {
	var faults []error
	for _, need := range []struct{ key, value, why string }{
		{"name", name, "запись не назвала себя: по имени её адресуют выдачи и вступления"},
		{"account", account, "не сказано, в каком аккаунте запись заводится"},
	} {
		if strings.TrimSpace(need.value) != "" {
			continue
		}
		faults = append(faults, linkFault{
			kind:   ErrSeededSubjectIncomplete,
			coord:  locate(doc, "seed", section, i),
			detail: fmt.Sprintf("seed.%s[%d].%s: %s", section, i, need.key, need.why),
		})
	}
	if proseShorterThan(description, minProseRunes) {
		faults = append(faults, linkFault{
			kind:  ErrSeededSubjectIncomplete,
			coord: locate(doc, "seed", section, i),
			detail: fmt.Sprintf("seed.%s[%d].description: %d знаков, требуется не менее %d — "+
				"описание отвечает на вопрос, %s; следующий, кто увидит запись, "+
				"иначе не узнает, снимать её или оставить",
				section, i, utf8.RuneCountInString(strings.TrimSpace(description)),
				minProseRunes, purpose),
		})
	}
	return faults
}

// validateJoin — одно вступление: обе стороны парой · СВОЯ запись · причина.
//
// Членства группы в посеве здесь НЕ требуется — и это самая важная строка
// файла: группа чужая by construction (см. шапку). Проверяется у неё только
// адресуемость парой.
func validateJoin(doc *yaml.Node, i int, j Join, seededAccounts []string) []error {
	var faults []error

	saComplete, saFaults := checkRefIsAPair(doc, i, "serviceAccount", j.ServiceAccount)
	faults = append(faults, saFaults...)
	_, groupFaults := checkRefIsAPair(doc, i, "group", j.Group)
	faults = append(faults, groupFaults...)

	// Неполную сторону не сверяют с посевом: сверять нечего, а второй отказ об
	// одном и том же месте заставил бы чинить дважды.
	if saComplete && !hasPair(seededAccounts, j.ServiceAccount) {
		faults = append(faults, linkFault{
			kind:  ErrJoinServiceAccountNotSeeded,
			coord: locate(doc, "seed", "joins", i, "serviceAccount"),
			detail: fmt.Sprintf(
				"вступает запись (account %s, name %s), которой не заводит seed.serviceAccounts; заведены: %s. Вступает СВОЯ личность модуля — чужую он вписать не вправе",
				j.ServiceAccount.Account, j.ServiceAccount.Name, listOrEmpty(seededAccounts)),
		})
	}

	switch reason := strings.TrimSpace(j.Why); {
	case reason == "":
		faults = append(faults, linkFault{
			kind:   ErrJoinReasonMissing,
			coord:  locate(doc, "seed", "joins", i),
			detail: "не назван ключ `why`: членство без причины некому снять — следующий не знает, действует ли ещё основание",
		})
	case utf8.RuneCountInString(reason) < minJoinReasonRunes:
		faults = append(faults, linkFault{
			kind:  ErrJoinReasonMissing,
			coord: locate(doc, "seed", "joins", i, "why"),
			detail: fmt.Sprintf(
				"причина %q короче объявленного предела: знаков %d, требуется %d",
				reason, utf8.RuneCountInString(reason), minJoinReasonRunes),
		})
	}
	return faults
}

// checkRefIsAPair — сторона вступления адресуется ПАРОЙ (аккаунт, имя): так она
// уникальна в продукте (`groups_account_name_unique`,
// `service_accounts_account_name_unique`). Одно имя не адресует, а «модуль/имя»
// смешивало бы того, кто завёл, с тем, где лежит.
//
// Сторона, записанная одной строкой, до сюда не доходит вовсе: строка на месте
// отображения не ложится на объявленный тип, и отказ приходит из разбора,
// называя номер строки (приёмка §2.7).
func checkRefIsAPair(doc *yaml.Node, i int, side string, ref SubjectRef) (bool, []error) {
	var missing []string
	if ref.Account == "" {
		missing = append(missing, "`account`")
	}
	if ref.Name == "" {
		missing = append(missing, "`name`")
	}
	if len(missing) == 0 {
		return true, nil
	}
	return false, []error{linkFault{
		kind:  ErrRefNotAPair,
		coord: locate(doc, "seed", "joins", i, side),
		detail: fmt.Sprintf(
			"у стороны %s не назван ключ %s: сторона адресуется парой (account, name), одно имя не адресует",
			side, strings.Join(missing, " и ")),
	}}
}

func namesOfServiceAccounts(list []ServiceAccount) []string {
	out := make([]string, 0, len(list))
	for _, sa := range list {
		out = append(out, sa.Account+"/"+sa.Name)
	}
	return out
}

func namesOfGroups(list []Group) []string {
	out := make([]string, 0, len(list))
	for _, g := range list {
		out = append(out, g.Account+"/"+g.Name)
	}
	return out
}

// hasName — есть ли среди заведённых запись с таким именем, независимо от
// аккаунта: субъект выдачи аккаунта не называет вовсе.
func hasName(seeded []string, name string) bool {
	for _, s := range seeded {
		if _, got, ok := strings.Cut(s, "/"); ok && got == name {
			return true
		}
	}
	return false
}

// hasPair — есть ли среди заведённых запись, адресованная ЭТОЙ парой.
func hasPair(seeded []string, ref SubjectRef) bool {
	return contains(seeded, ref.Account+"/"+ref.Name)
}

func listOrEmpty(seeded []string) string {
	if len(seeded) == 0 {
		return "ни одной"
	}
	return strings.Join(seeded, ", ")
}
