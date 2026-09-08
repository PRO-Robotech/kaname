// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// excluding_from_an_account_injection_test.go — доказательство, что соседний
// гейт СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// # Предикат — ТОТ ЖЕ, а не копия
//
// Опыт зовёт `inspectExclusionPair` — ровно ту функцию, что зовёт гейт. Именно
// поэтому предикат вынесен из тела гейта: копия доказывала бы, что работает
// копия.
//
// # Плеч у опыта ДВА, потому что у гейта два источника
//
// Гейт судит по МОДЕЛИ (круг держателей) и по КАТАЛОГУ (объект решения и имя
// отношения). Инъекция только в модель оставила бы половину утверждений без
// опыта — ту самую, которая закрывает возвращение решения на строку личности.
// Поэтому здесь правится и текст модели, и разобранные записи каталога, и оба
// плеча проходят через один предикат.
//
// # ИНЪЕКЦИЯ ИДЁТ ПО ТИПУ, А НЕ ПО ПОДСТРОКЕ
//
// `define editor:` стоит в модели у многих типов. Замена по подстроке попала бы
// в первый попавшийся, опыт ставился бы над чужим типом, и зелёный результат
// читался бы как доказательство. `replaceDefineInType` сужает замену блоком типа
// и требует ровно одного попадания.
//
// # Осей ЧЕТЫРЕ, по числу утверждений гейта
//
//	I.   решение уезжает на СТРОКУ ЛИЧНОСТИ  — возвращается класс #1102;
//	II.  пара схлопывается в ОДНО отношение  — «согласны» становится тавтологией;
//	III. круг исключения СУЖАЕТСЯ            — вводить можно, выводить нельзя;
//	IV.  распорядитель аккаунта теряет право — действие есть, адресата нет.
package authzmap_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
)

const (
	exclusionRelation = "member_remover"
	exclusionType     = "account"

	// exclusionInjectedNarrowed — ось III: исключение сужено до делегированного
	// администратора, приглашение осталось на `editor`. Форма настоящая: `admin`
	// — существующий ярус этого же типа.
	exclusionInjectedNarrowed = "define member_remover: admin"
	// exclusionInjectedCloudOnly — ось IV: у аккаунта права не остаётся вовсе,
	// исключать может только облако. Форма настоящая: так объявлены соседи на
	// строке личности (`record_writer`, `identity_suspender`).
	exclusionInjectedCloudOnly = "define member_remover: super_admin"
)

func exclusionCleanCanonical(t *testing.T) string {
	t.Helper()
	path, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmptyf(t, dsl, "канонический файл модели пуст: %s", path)
	clean := string(dsl)
	require.NotContainsf(t, clean, exclusionInjectedNarrowed,
		"предпосылка опыта: в %s суженной формы быть не должно — иначе «краснеет после "+
			"инъекции» краснело бы и без неё", path)
	return clean
}

func exclusionInjected(t *testing.T, clean, define string) *authzplan.Model {
	t.Helper()
	text := replaceDefineInType(t, clean, exclusionType, "define "+exclusionRelation+":", define)
	require.Containsf(t, text, define, "инъекция %q не внеслась — опыт не поставлен", define)
	m, err := authzplan.ParseModel(text)
	require.NoErrorf(t, err, "инъекция обязана оставаться разбираемой моделью")
	return m
}

// TestExcludingFromAnAccountGate_InjectionCutsBothWays — четыре оси, обе стороны.
func TestExcludingFromAnAccountGate_InjectionCutsBothWays(t *testing.T) {
	clean := exclusionCleanCanonical(t)
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)

	catalog := catalogByFQN(t)
	admission, ok := catalog[accountAdmissionRPC]
	require.Truef(t, ok, "каталог не знает %s", accountAdmissionRPC)
	exclusion, ok := catalog[accountExclusionRPC]
	require.Truef(t, ok, "каталог не знает %s", accountExclusionRPC)

	// ── сторона 1: на чистом дереве предикат молчит по всем осям ──────────────
	base := inspectExclusionPair(t, cleanModel, admission, exclusion)
	require.Equal(t, "account", base.ExclusionType,
		"на дереве без дефекта решение принимается не на аккаунте — опыт ставится не над тем")
	require.False(t, base.SameRelationName,
		"на дереве без дефекта пара выражена одним отношением — тогда её согласие тавтологично")
	require.Positive(t, base.AccountLevel,
		"на дереве без дефекта у исключения нет источников на самом аккаунте")
	require.True(t, base.HasCloud, "на дереве без дефекта надзор облака не найден источником")
	require.True(t, base.CirclesEqual,
		"на дереве без дефекта круги приглашения и исключения не равны — опыт ставится не над тем")

	// ── ось I: решение уезжает на строку личности (плечо КАТАЛОГА) ────────────
	// Здесь стоял глагол `v_delete` типа `iam_user` — он снят вместе со своим
	// предметом (#1189), и ссылка на него перестала бы КОМПИЛИРОВАТЬСЯ: краснел бы
	// разбор, а не предикат. Взято отношение, которым решение о строке личности
	// принимается НА САМОМ ДЕЛЕ (`identity_remover`, #1131), — то есть инъекция стала
	// не только живучей, но и правдоподобнее: ровно так выглядел бы возврат класса
	// #1102, где исключение из аккаунта гейтили распоряжением глобальной строкой.
	onIdentity := inspectExclusionPair(t, cleanModel, admission,
		catalogGate{relation: "identity_remover", objectType: "iam_user"})
	require.Equalf(t, "iam_user", onIdentity.ExclusionType,
		"инъекция не внеслась: объект решения остался %s", onIdentity.ExclusionType)
	require.Falsef(t, onIdentity.CirclesEqual,
		"ось I не поймана предикатом: решение принимается про ГЛОБАЛЬНУЮ строку личности, а "+
			"круги всё равно объявлены равными — тогда возвращение класса #1102 прошло бы молча")

	// ── ось II: пара схлопнулась в одно отношение (плечо КАТАЛОГА) ────────────
	sameName := inspectExclusionPair(t, cleanModel, admission,
		catalogGate{relation: admission.relation, objectType: admission.objectType})
	require.Truef(t, sameName.SameRelationName,
		"инъекция не внеслась: имена отношений остались разными")
	require.Truef(t, sameName.CirclesEqual,
		"ось II обязана менять РОВНО одно утверждение: круги при тождестве равны by "+
			"construction — и это ровно то, чем тавтология опасна")

	// ── ось III: круг исключения сужен (плечо МОДЕЛИ) ─────────────────────────
	narrowed := inspectExclusionPair(t, exclusionInjected(t, clean, exclusionInjectedNarrowed),
		admission, exclusion)
	require.Falsef(t, narrowed.CirclesEqual,
		"инъекция %q не поймана: исключение сужено до делегированного администратора, "+
			"приглашение осталось шире — аккаунт снова копит людей, которых не может убрать, "+
			"а предикат молчит.\nприглашение: %v\nисключение:  %v",
		exclusionInjectedNarrowed, sortedKeys(narrowed.Admission), sortedKeys(narrowed.Exclusion))
	require.Positivef(t, narrowed.AccountLevel,
		"ось III обязана менять РОВНО одно утверждение: источники на самом аккаунте здесь "+
			"остаются (сужение идёт ВНУТРИ аккаунта, а не за его пределы)")
	require.Truef(t, narrowed.HasCloud,
		"ось III обязана менять РОВНО одно утверждение: надзор облака здесь остаётся")

	// ── ось IV: у аккаунта права не осталось (плечо МОДЕЛИ) ───────────────────
	cloudOnly := inspectExclusionPair(t, exclusionInjected(t, clean, exclusionInjectedCloudOnly),
		admission, exclusion)
	require.Zerof(t, cloudOnly.AccountLevel,
		"инъекция %q не поймана: у исключения не осталось источников на самом аккаунте — "+
			"действие заведено, а распорядителю аккаунта не досталось, — а предикат молчит.\n"+
			"Источники: %v", exclusionInjectedCloudOnly, sortedKeys(cloudOnly.Exclusion))
	require.Truef(t, cloudOnly.HasCloud,
		"ось IV обязана оставить надзор облака: иначе краснели бы два утверждения сразу, и "+
			"опыт не различал бы, какое именно")

	t.Logf("опыт: осей проверено 4 (две правят каталог, две — модель) · на чистом дереве "+
		"источников исключения %d, из них на самом аккаунте %d",
		len(base.Exclusion), base.AccountLevel)
}

// TestExcludingFromAnAccountInjection_IsScopedToTheTypeNotTheSubstring — опыт
// над самим опытом: замена сужена блоком типа, а не первой подходящей строкой.
func TestExcludingFromAnAccountInjection_IsScopedToTheTypeNotTheSubstring(t *testing.T) {
	clean := exclusionCleanCanonical(t)

	const shared = "define editor:"
	require.Greaterf(t, strings.Count(clean, shared), 1,
		"предпосылка опыта: объявление %q обязано встречаться у НЕСКОЛЬКИХ типов, иначе он не "+
			"отличает сужение по типу от замены по подстроке", shared)

	const injected = "define editor: [user]"
	text := replaceDefineInType(t, clean, exclusionType, shared, injected)
	require.Equalf(t, 1, strings.Count(text, injected),
		"инъекция внеслась %d раз(а) — сужение блоком типа не работает",
		strings.Count(text, injected))

	m, err := authzplan.ParseModel(text)
	require.NoError(t, err)

	touched, err := m.Compile(exclusionType, "editor")
	require.NoError(t, err)
	require.Lenf(t, sourcesOf(t, touched), 1,
		"опыт не тронул тип %s — замена ушла в другой блок", exclusionType)

	// Соседний тип с тем же объявлением НЕ тронут: у проекта `editor` шире одного
	// источника, и остаться он обязан таким же.
	untouched, err := m.Compile("project", "editor")
	require.NoError(t, err)
	require.Greaterf(t, len(sourcesOf(t, untouched)), 1,
		"замена задела соседний тип project — сужение по типу не состоялось, и всякий "+
			"«зелёный» результат опыта выше ничего не доказывает")

	t.Logf("перепись: объявление %q встречается в модели %d раз(а); после сужения по типу "+
		"инъекция внеслась 1 раз", shared, strings.Count(clean, shared))
}
