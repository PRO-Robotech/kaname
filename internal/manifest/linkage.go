// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
)

// minJoinReasonRunes — предел длины причины вступления, объявленный схемой
// (`why.minLength: 12`).
//
// Меряется в ЗНАКАХ, а не в байтах, и это не педантизм: причина здесь пишется
// по-русски, кириллический знак весит два байта, и проверка по `len` пропустила
// бы вдвое более короткую причину, чем латинская. Расхождение тихое — оба
// варианта выглядят работающими на английском входе.
const minJoinReasonRunes = 12

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
}

// String — перепись одной строкой; её печатает потребитель загрузчика.
func (c LinkageCensus) String() string {
	s := fmt.Sprintf(
		"выдач прочитано %d · субъектов разрешено %d · групп заведено %d · вступлений прочитано %d · roleId сверено %d из %d",
		c.BindingsRead, c.SubjectsResolved, c.GroupsDeclared, c.JoinsRead, c.RoleRefsChecked, c.RoleRefsRead)
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
func validateSeedLinkage(m *Manifest, doc *yaml.Node, roles roleIDs) (LinkageCensus, []error) {
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
		census.RoleRefsRead++
		if roles.declared {
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
			}
		}
	}

	for i, g := range seed.Groups {
		if _, ok := grantedGroups[g.Name]; ok {
			continue
		}
		faults = append(faults, linkFault{
			kind:  ErrGroupNeverGranted,
			coord: locate(doc, "seed", "groups", i),
			detail: fmt.Sprintf(
				"группа %q заведена и не названа ни в одной выдаче: имя без предмета — выдайте ей роль в seed.accessBindings либо не заводите",
				g.Name),
		})
	}

	for i, j := range seed.Joins {
		faults = append(faults, validateJoin(doc, i, j, seededAccounts)...)
	}
	return census, faults
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
