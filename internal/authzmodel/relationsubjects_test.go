// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// relationsubjects_test.go — доказательство того, что чтение допустимых видов
// получателя ОТВЕЧАЕТ ПО ОБЪЯВЛЕНИЮ, а не по написанию записи.
//
// Пробы перенесены сюда вместе с самим чтением (задача продукта #1936, приёмка
// `module-manifest-relation-grant.md` §3.5). Прежде оно жило в пакете сверки
// посева и было заведено ради ПРОБЫ ПРЕДПОСЫЛКИ, которую та же задача снимает
// вместе с её предметом; оставить чтение там значило бы держать читатель в
// пакете, у которого предмета не осталось.
//
// # Почему синтетический канон, а не только вшитый
//
// У правила две стороны, и живого входа есть только одна: отношения, которое
// принимает членство группы и НЕ принимает служебную запись, на кластерном
// якоре сегодня нет. Доказать, что судья отвечает «не принимает» там, где не
// принимает, можно лишь каноном, поданным текстом. Вшитый канон при этом тоже
// спрашивается — иначе пробы доказывали бы свойство разбора, а не свойство
// продукта.
//
// # Что здесь уже ошибалось, и потому проверяется дословно
//
// Прежнее чтение сравнивало запись со СТРОКОЙ `group#member` и потому читало
// `group#member with <условие>` как «членство НЕ принимается» — отвечая уверенно
// и неверно. Направление ошибки было худшим из двух: судья оставался ЗЕЛЁНЫМ, а
// проба предпосылки, обещавшая сказать о смене канона сама, на такой форме
// молчала бы.
package authzmodel_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmodel"
)

// synthetic — канон, поданный текстом. Связный: тип субъекта объявлен, у
// отношений есть термы. Прежнее чтение отвечало уверенно и по входу, каноном НЕ
// являющемуся, — а его собственная фикстура таким входом и была.
const synthetic = `model
  schema 1.1

type user

type service_account

type group
  relations
    define member: [user, service_account]

condition mfa_fresh(x: int) {
  x > 0
}

type demo
  relations
    define plain: [user, service_account]
    define with_group: [service_account, group#member]
    define conditioned_group: [group#member with mfa_fresh]
    define conditioned_other: [user with mfa_fresh, service_account]
    define group_wildcard: [group:*]
    define computed: plain
`

func mustParse(t *testing.T, dsl string) *authzmodel.Plans {
	t.Helper()
	p, err := authzmodel.New(dsl)
	require.NoError(t, err, "синтетический канон обязан разбираться — иначе пробы ниже вакуумны")
	return p
}

// ── законный близнец первым: судья умеет сказать «принимает» ────────────────

func TestRelationSubjectsAdmitsPlainKinds(t *testing.T) {
	d, ok := mustParse(t, synthetic).RelationSubjects("demo", "plain")
	require.True(t, ok, "объявленное отношение обязано находиться")
	require.True(t, d.Direct, "у отношения с прямыми записями Direct обязан быть true")
	require.True(t, d.AcceptsKind(authzmodel.KindUser))
	require.True(t, d.AcceptsKind(authzmodel.KindServiceAccount))
	require.False(t, d.AcceptsKind(authzmodel.KindGroup),
		"членства группы это объявление не несёт — «принимает» здесь было бы вымыслом")
}

func TestRelationSubjectsAdmitsGroupMember(t *testing.T) {
	d, ok := mustParse(t, synthetic).RelationSubjects("demo", "with_group")
	require.True(t, ok)
	require.True(t, d.AcceptsKind(authzmodel.KindGroup))
	require.True(t, d.AcceptsKind(authzmodel.KindServiceAccount))
	require.False(t, d.AcceptsKind(authzmodel.KindUser))
}

// ── условие сужает КОГДА, а не отменяет ЧТО ────────────────────────────────

// TestRelationSubjectsSeesGroupMemberCarryingACondition — ровно тот вход, на
// котором прежнее чтение отвечало неверно и молчало.
func TestRelationSubjectsSeesGroupMemberCarryingACondition(t *testing.T) {
	d, ok := mustParse(t, synthetic).RelationSubjects("demo", "conditioned_group")
	require.True(t, ok)
	require.Truef(t, d.AcceptsKind(authzmodel.KindGroup),
		"условие сужает, КОГДА членство действует, и не отменяет того, ЧТО это членство; "+
			"записи объявления: %v", d.Accepts)
}

// TestRelationSubjectsConditionOnAnotherSubjectDoesNotAdmitGroup — обратная
// сторона: условие у ЧУЖОЙ записи членства группы не заводит.
func TestRelationSubjectsConditionOnAnotherSubjectDoesNotAdmitGroup(t *testing.T) {
	d, ok := mustParse(t, synthetic).RelationSubjects("demo", "conditioned_other")
	require.True(t, ok)
	require.False(t, d.AcceptsKind(authzmodel.KindGroup))
	require.True(t, d.AcceptsKind(authzmodel.KindUser),
		"положительный контроль: запись с условием остаётся записью своего вида")
}

// ── подстановка называет ТИП и членством не является ───────────────────────

func TestRelationSubjectsGroupWildcardIsNotGroupMember(t *testing.T) {
	d, ok := mustParse(t, synthetic).RelationSubjects("demo", "group_wildcard")
	require.True(t, ok)
	require.Falsef(t, d.AcceptsKind(authzmodel.KindGroup),
		"`group:*` называет тип субъекта и членством не является; записи: %v", d.Accepts)
}

// ── три ответа остаются различимы ──────────────────────────────────────────

// TestRelationSubjectsComputedRelationIsNotJudgedSilently — «прямых субъектов
// нет вовсе» отличается от «есть, вида не принимает». Схлопнув их, судья назвал
// бы неверный предмет.
func TestRelationSubjectsComputedRelationIsNotJudgedSilently(t *testing.T) {
	d, ok := mustParse(t, synthetic).RelationSubjects("demo", "computed")
	require.Truef(t, ok, "вычисляемое отношение ОБЪЯВЛЕНО — «не нашёл» здесь было бы третьим ответом не о том")
	require.Falsef(t, d.Direct,
		"у вычисляемого отношения прямых записей нет; записи: %v", d.Accepts)
	require.Empty(t, d.Accepts)
}

func TestRelationSubjectsUnknownTypeIsNotFound(t *testing.T) {
	_, ok := mustParse(t, synthetic).RelationSubjects("no_such_type", "plain")
	require.False(t, ok)
}

func TestRelationSubjectsUnknownRelationIsNotFound(t *testing.T) {
	_, ok := mustParse(t, synthetic).RelationSubjects("demo", "no_such_relation")
	require.False(t, ok)
}

// TestRelationSubjectsSameNameOnAnotherTypeDoesNotSubstitute — ответ даётся по
// объявлению СВОЕГО типа: `member` объявлен у `group` и не объявлен у `demo`.
func TestRelationSubjectsSameNameOnAnotherTypeDoesNotSubstitute(t *testing.T) {
	p := mustParse(t, synthetic)
	_, okDemo := p.RelationSubjects("demo", "member")
	require.False(t, okDemo, "одноимённое отношение соседнего типа судьёй не является")

	_, okGroup := p.RelationSubjects("group", "member")
	require.True(t, okGroup, "положительный контроль: у своего типа оно находится")
}

// TestNewRefusesACanonItCannotParse — непонятое НЕ пропускается: вход, каноном
// не являющийся, даёт ошибку, а не пустую модель, которая отвечала бы «такого
// отношения нет» на всякий вопрос.
func TestNewRefusesACanonItCannotParse(t *testing.T) {
	_, err := authzmodel.New("это не модель прав, а просто текст\n")
	require.Error(t, err)
}

// ── вшитый канон: свойство ПРОДУКТА, а не только разбора ───────────────────

// TestRelationSubjectsOnTheEmbeddedCanon — на вшитом каноне обе ветви правила о
// получателе имеют ЖИВОЙ вход, и это не синтетика.
//
// Проба намеренно НЕ пиннит перечень отношений кластера числом: он растёт с
// продуктом, и число устарело бы молча. Пиннится ровно то, на чём стоит решение
// задачи #1936.
func TestRelationSubjectsOnTheEmbeddedCanon(t *testing.T) {
	p, err := authzmodel.Shared()
	require.NoError(t, err)

	viewer, ok := p.RelationSubjects("cluster", "system_viewer")
	require.True(t, ok)
	require.True(t, viewer.Direct)
	require.Truef(t, viewer.AcceptsKind(authzmodel.KindServiceAccount),
		"на этом стоит объявимость двух живых строк посева; записи: %v", viewer.Accepts)
	require.Falsef(t, viewer.AcceptsKind(authzmodel.KindGroup),
		"на этом стоит довод, что путь «через группу» для этих строк неисполним; записи: %v",
		viewer.Accepts)

	quota, ok := p.RelationSubjects("cluster", "quota_reader")
	require.True(t, ok)
	require.Truef(t, quota.AcceptsKind(authzmodel.KindGroup),
		"вторая ветвь правила обязана иметь живой вход, иначе отказ по группе вакуумен; записи: %v",
		quota.Accepts)

	names, ok := p.RelationNames("cluster")
	require.True(t, ok)
	require.Contains(t, names, "system_viewer")
	require.Contains(t, names, "quota_reader")
	require.Contains(t, names, "any_admin")
	t.Logf("перепись: отношений у типа cluster прочитано %d: %v", len(names), names)
}
