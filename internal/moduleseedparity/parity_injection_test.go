// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Инъекция сверки посева: доказательство, что она СПОСОБНА упасть и способна
// смолчать.
//
// Вход синтетический и подаётся Diff напрямую: вердикт сверки есть свойство
// пары «объявлено / живёт», и он не должен зависеть ни от состояния базы, ни от
// сегодняшнего содержимого манифестов. Каждая ось — В ОБЕ СТОРОНЫ; законный
// близнец стоит ПЕРВЫМ, иначе отрицание зеленело бы на сверке, находящей
// расхождение в любом входе.
package moduleseedparity_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/moduleseedparity"
)

func injSA(desc string) moduleseedparity.ServiceAccount {
	return moduleseedparity.ServiceAccount{Account: "kacho-system", Name: "kacho-demo", Description: desc}
}

func injJoin(groupAccount, group string) moduleseedparity.Join {
	return moduleseedparity.Join{
		AccountName: "kacho-system", SAName: "kacho-demo",
		GroupAccount: groupAccount, GroupName: group,
	}
}

func injState(declaredSA, liveSA []moduleseedparity.ServiceAccount,
	declaredJoin, liveJoin []moduleseedparity.Join,
) moduleseedparity.ModuleState {
	return moduleseedparity.ModuleState{
		Module: "demo", ManifestFile: "services/demo/manifest.yaml",
		DeclaredSA: declaredSA, LiveSA: liveSA,
		DeclaredJoin: declaredJoin, LiveJoin: liveJoin,
	}
}

// Законный близнец: объявленное сходится с живым по обеим осям.
func TestInjectionSeedParityAgreeingStateIsSilent(t *testing.T) {
	sa := []moduleseedparity.ServiceAccount{injSA("Module SA: kacho-demo")}
	joins := []moduleseedparity.Join{injJoin("kacho-system", "module-quota-readers")}
	findings := moduleseedparity.Compare([]moduleseedparity.ModuleState{injState(sa, sa, joins, joins)}).Findings
	require.Emptyf(t, findings,
		"согласованное состояние даёт находки — отрицание зеленело бы на всём сломанном: %v", findings)
}

// Пустое с ОБЕИХ сторон — тоже согласие: модуль без посева законен.
func TestInjectionSeedParityEmptyBothSidesIsSilent(t *testing.T) {
	require.Empty(t, moduleseedparity.Compare([]moduleseedparity.ModuleState{injState(nil, nil, nil, nil)}).Findings)
}

func TestInjectionSeedParityLiveRowNotDeclaredIsAFinding(t *testing.T) {
	live := []moduleseedparity.ServiceAccount{injSA("Module SA: kacho-demo")}
	findings := moduleseedparity.Compare([]moduleseedparity.ModuleState{injState(nil, live, nil, nil)}).Findings
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "служебная запись ЖИВЁТ и не объявлена")
	require.Contains(t, findings[0], "kacho-demo")
	require.Contains(t, findings[0], "services/demo/manifest.yaml")
}

// Обратная сторона: обещанное и не заведённое — тоже находка, и не мягче.
func TestInjectionSeedParityDeclaredRowNotLiveIsAFinding(t *testing.T) {
	declared := []moduleseedparity.ServiceAccount{injSA("Module SA: kacho-demo")}
	findings := moduleseedparity.Compare([]moduleseedparity.ModuleState{injState(declared, nil, nil, nil)}).Findings
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "служебная запись ОБЪЯВЛЕНА и не живёт")
}

// Сверка идёт по НАЗНАЧЕНИЮ тоже, а не по одному имени: применитель кладёт
// объявленное дословно поверх живой строки, поэтому расхождение прозы есть
// переписывание того, что уже действует.
func TestInjectionSeedParityDescriptionIsPartOfTheComparison(t *testing.T) {
	findings := moduleseedparity.Compare([]moduleseedparity.ModuleState{injState(
		[]moduleseedparity.ServiceAccount{injSA("почти то же самое")},
		[]moduleseedparity.ServiceAccount{injSA("Module SA: kacho-demo")},
		nil, nil)}).Findings
	require.Len(t, findings, 2, "расхождение прозы обязано быть названо с обеих сторон: %v", findings)
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "ЖИВЁТ и не объявлена")
	require.Contains(t, joined, "ОБЪЯВЛЕНА и не живёт")
}

func TestInjectionSeedParityLiveJoinNotDeclaredIsAFinding(t *testing.T) {
	live := []moduleseedparity.Join{injJoin("kacho-system", "module-relation-writers")}
	findings := moduleseedparity.Compare([]moduleseedparity.ModuleState{injState(nil, nil, nil, live)}).Findings
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "вступление ЖИВЁТ и не объявлено")
	require.Contains(t, findings[0], "module-relation-writers")
}

// Сторона вступления адресуется ПАРОЙ (аккаунт, имя): один аккаунт не
// подразумевается, и подмена аккаунта обязана быть находкой.
func TestInjectionSeedParityJoinComparesThePairNotJustTheName(t *testing.T) {
	findings := moduleseedparity.Compare([]moduleseedparity.ModuleState{injState(nil, nil,
		[]moduleseedparity.Join{injJoin("другой-аккаунт", "module-quota-readers")},
		[]moduleseedparity.Join{injJoin("kacho-system", "module-quota-readers")})}).Findings
	require.Len(t, findings, 2, "подмена аккаунта группы не замечена: %v", findings)
}

// Находка называет МОДУЛЬ: перечень из десяти строк без имени владельца
// нечитаем, и читать его перестанут.
func TestInjectionSeedParityFindingNamesTheModule(t *testing.T) {
	findings := moduleseedparity.Compare([]moduleseedparity.ModuleState{
		injState(nil, []moduleseedparity.ServiceAccount{injSA("Module SA: kacho-demo")}, nil, nil),
		{Module: "second", ManifestFile: "services/second/manifest.yaml",
			LiveJoin: []moduleseedparity.Join{injJoin("kacho-system", "g")}},
	}).Findings
	require.Len(t, findings, 2)
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "модуль demo")
	require.Contains(t, joined, "модуль second")
}

// --- Подразделы `groups` и `accessBindings` -----------------------------------
//
// До этой правки оба лежали ВНЕ вердикта, а граница объяснялась одним числом на
// все живые строки. Число складывало невыразимое by construction (строка без
// модуля-владельца — объявлять её некому) с настоящим пробелом (владелец есть,
// формы нет). Оси ниже разделяют это по каждому подразделу и в обе стороны.

func injBindingRole(role string) moduleseedparity.Binding {
	return moduleseedparity.Binding{
		SubjectType: "serviceAccount", SubjectName: "kacho-demo",
		RoleID: role, ScopeType: "iam.cluster", ScopeID: "cluster_root",
	}
}

func injBindingRelation(relation string) moduleseedparity.Binding {
	return moduleseedparity.Binding{
		SubjectType: "serviceAccount", SubjectName: "kacho-demo",
		Relation: relation, ScopeType: "iam.cluster", ScopeID: "cluster_root",
	}
}

func injGroupBinding(role, group string) moduleseedparity.Binding {
	return moduleseedparity.Binding{
		SubjectType: "group", SubjectName: group,
		RoleID: role, ScopeType: "iam.cluster", ScopeID: "cluster_root",
	}
}

// injGroupRelationBinding — та же выдача группе, но ОТНОШЕНИЕМ. Прежде форма
// манифеста такого ключа не несла, и обе строки выводились из-под вердикта;
// после #1936 они судятся наравне с прочими.
func injGroupRelationBinding(relation, group string) moduleseedparity.Binding {
	b := injGroupBinding("", group)
	b.Relation = relation
	return b
}

func injGroup(name, description string) moduleseedparity.Group {
	return moduleseedparity.Group{Account: "kacho-system", Name: name, Description: description}
}

func injBindState(declared, live []moduleseedparity.Binding) moduleseedparity.ModuleState {
	return moduleseedparity.ModuleState{
		Module: "demo", ManifestFile: "services/demo/manifest.yaml",
		DeclaredBinding: declared, LiveBinding: live,
	}
}

// Законный близнец подраздела выдач: объявленное сходится с живым.
func TestInjectionSeedParityAgreeingBindingsAreSilent(t *testing.T) {
	b := []moduleseedparity.Binding{injBindingRole("demo.viewer")}
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{injBindState(b, b)})
	require.Emptyf(t, res.Findings, "согласованные выдачи дали находки: %v", res.Findings)
}

// Законный близнец ВТОРОЙ формы: согласованная выдача ОТНОШЕНИЕМ так же молчит.
//
// Парная к [TestInjectionSeedParityLiveRelationBindingNotDeclaredIsAFinding]:
// без неё отрицание ниже зеленело бы на сверке, объявляющей находкой всякую
// выдачу отношением.
func TestInjectionSeedParityAgreeingRelationBindingsAreSilent(t *testing.T) {
	b := []moduleseedparity.Binding{injBindingRelation("system_viewer")}
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{injBindState(b, b)})
	require.Emptyf(t, res.Findings,
		"согласованная выдача ОТНОШЕНИЕМ дала находки: %v", res.Findings)
}

func TestInjectionSeedParityLiveRoleBindingNotDeclaredIsAFinding(t *testing.T) {
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{
		injBindState(nil, []moduleseedparity.Binding{injBindingRole("demo.viewer")})})
	require.Lenf(t, res.Findings, 1,
		"живая выдача РОЛЬЮ выразима формой — её отсутствие среди объявленных есть пробел: %v", res.Findings)
	require.Contains(t, res.Findings[0], "выдача ЖИВЁТ и не объявлена")
	require.Contains(t, res.Findings[0], "demo.viewer")
	require.Contains(t, res.Findings[0], "services/demo/manifest.yaml")
}

// Обратная сторона: обещанное и не заведённое — тоже находка.
func TestInjectionSeedParityDeclaredBindingNotLiveIsAFinding(t *testing.T) {
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{
		injBindState([]moduleseedparity.Binding{injBindingRole("demo.viewer")}, nil)})
	require.Len(t, res.Findings, 1)
	require.Contains(t, res.Findings[0], "выдача ОБЪЯВЛЕНА и не живёт")
}

// Сверяется ТО, ЧТО выдано, а не один субъект: два права одному субъекту —
// разные выдачи, и подмена права обязана быть названа с обеих сторон.
func TestInjectionSeedParityBindingComparesWhatIsGranted(t *testing.T) {
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{injBindState(
		[]moduleseedparity.Binding{injBindingRole("demo.editor")},
		[]moduleseedparity.Binding{injBindingRole("demo.viewer")})})
	require.Lenf(t, res.Findings, 2, "подмена роли не замечена: %v", res.Findings)
}

// НЕСУЩЕЕ, и утверждение здесь ПЕРЕВЕРНУЛОСЬ вместе со своим предметом (#1936).
//
// Прежде проба требовала, чтобы живая выдача ОТНОШЕНИЕМ не была находкой, а
// попадала в отдельный названный перечень: автор манифеста написать её не мог, и
// требовать этого было нельзя. Форма научилась — значит написать её теперь
// можно, и её отсутствие среди объявленных есть ПРОБЕЛ, ровно как у выдачи ролью.
//
// Проба не снята, а переведена на признак, который дерево производит: снять её
// значило бы потерять наблюдение ровно там, где оно впервые стало возможным.
func TestInjectionSeedParityLiveRelationBindingNotDeclaredIsAFinding(t *testing.T) {
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{
		injBindState(nil, []moduleseedparity.Binding{injBindingRelation("system_viewer")})})
	require.Lenf(t, res.Findings, 1,
		"живая выдача ОТНОШЕНИЕМ теперь выразима формой — её отсутствие среди объявленных "+
			"есть пробел: %v", res.Findings)
	require.Contains(t, res.Findings[0], "выдача ЖИВЁТ и не объявлена")
	require.Contains(t, res.Findings[0], "system_viewer")
	require.Contains(t, res.Findings[0], "модуль demo")
}

// Группа модуля, наделённая выразимой выдачей, сверяется как всё прочее.
func TestInjectionSeedParityLiveGroupNotDeclaredIsAFinding(t *testing.T) {
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{{
		Module: "demo", ManifestFile: "services/demo/manifest.yaml",
		LiveGroup:   []moduleseedparity.Group{injGroup("demo-readers", "читатели демо-модуля")},
		LiveBinding: []moduleseedparity.Binding{injGroupBinding("demo.viewer", "demo-readers")},
	}})
	joined := strings.Join(res.Findings, "\n")
	require.Contains(t, joined, "группа ЖИВЁТ и не объявлена")
	require.Contains(t, joined, "demo-readers")
}

func TestInjectionSeedParityDeclaredGroupNotLiveIsAFinding(t *testing.T) {
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{{
		Module: "demo", ManifestFile: "services/demo/manifest.yaml",
		DeclaredGroup: []moduleseedparity.Group{injGroup("demo-readers", "читатели демо-модуля")},
	}})
	require.Len(t, res.Findings, 1)
	require.Contains(t, res.Findings[0], "группа ОБЪЯВЛЕНА и не живёт")
}

// Группа, наделённая ТОЛЬКО отношением, судится наравне с прочими — и это второе
// утверждение, перевернувшееся вместе с предметом (#1936).
//
// Прежде она была необъявима ПО СЛЕДСТВИЮ: валидатор связности требует, чтобы
// заведённая группа была названа выдачей манифеста, а выдачи отношением у формы
// не было. Необъявимость группы была следствием правила о выдаче, а не своим
// правилом, — поэтому она и снялась вместе с ним, без единой правки о группах.
func TestInjectionSeedParityGroupGrantedOnlyByRelationIsJudgedLikeTheRest(t *testing.T) {
	res := moduleseedparity.Compare([]moduleseedparity.ModuleState{{
		Module: "demo", ManifestFile: "services/demo/manifest.yaml",
		LiveGroup: []moduleseedparity.Group{injGroup("module-quota-readers", "читатели пределов")},
		LiveBinding: []moduleseedparity.Binding{
			injGroupRelationBinding("quota_reader", "module-quota-readers")},
	}})
	joined := strings.Join(res.Findings, "\n")
	require.Lenf(t, res.Findings, 2,
		"объявить обе строки теперь можно, значит обе необъявленные суть пробел: %v", res.Findings)
	require.Contains(t, joined, "группа ЖИВЁТ и не объявлена")
	require.Contains(t, joined, "выдача ЖИВЁТ и не объявлена")
	require.Contains(t, joined, "module-quota-readers")
}
