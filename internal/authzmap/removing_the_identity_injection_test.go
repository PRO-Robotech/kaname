// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// removing_the_identity_injection_test.go — доказательство, что соседний гейт
// СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Зелёный гейт означает одно из двух: свойство держится либо предикат ослеп. По
// прочтении эти два состояния неотличимы, поэтому здесь ставится опыт.
//
// # Предикат — ТОТ ЖЕ, а не копия
//
// Опыт зовёт `inspectCredentialRelation` — ровно ту функцию, что зовёт гейт.
// Копия предиката доказывала бы, что работает копия: разойдясь с оригиналом, она
// разошлась бы молча и именно там, где расхождение не видно.
//
// # ИНЪЕКЦИЯ ИДЁТ ПО ТИПУ, А НЕ ПО ПОДСТРОКЕ
//
// Это не стилистика, а условие годности опыта. Одинаковые строки `define v_*`
// стоят в модели у ДЕСЯТКОВ типов, и текстовая замена попала бы в первый
// попавшийся — то есть опыт ставился бы над чужим типом, инъекция «не ловилась»
// бы гейтом, и зелёный результат читался бы как доказательство. Здесь
// используется `replaceDefineInType`, который сужает замену блоком типа и
// ТРЕБУЕТ ровно одного попадания; что он действительно сужает, доказано
// отдельным опытом ниже — инъекция ставится в НЕУНИКАЛЬНОЕ по дереву объявление,
// и проверяется, что соседний тип не тронут.
//
// # Вход НАСТОЯЩИЙ, а не синтетика
//
// Каждая ось возвращает форму, которая в этом дереве РЕАЛЬНО стояла либо реально
// стоит у соседа. Модель из трёх строк доказала бы, что предикат работает на
// синтетике.
//
// # Осей ЧЕТЫРЕ, потому что утверждений у гейта четыре
//
//	I.   прежняя ширина      — источники уровня аккаунта ВОЗВРАЩАЮТСЯ и НАЗЫВАЮТСЯ;
//	II.  прямой список       — отношение становится ВЫДАВАЕМЫМ;
//	III. без `subject`       — самоудаление пропадает;
//	IV.  без надзора облака  — чужую строку не удалить никому.
package authzmap_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
)

const (
	// removalRelation / removalType — предмет опыта. Литерал здесь законен и
	// нужен: опыт РЕДАКТИРУЕТ текст модели, а редактировать можно только
	// названное. Гейт рядом имени не знает — он спрашивает его у каталога.
	removalRelation = "identity_remover"
	removalType     = "iam_user"

	// removalInjectedWidth — форма, стоявшая здесь до #1131: `Delete` гейтился
	// ГЛАГОЛОМ типа (`v_delete`), и прежнее состояние возвращается его объявлением.
	//
	// Здесь стояло дословное `define identity_remover: v_delete`, и эта форма УМЕРЛА
	// вместе со своим предметом: глагол снят с типа (#1189), поэтому ссылка на него
	// перестаёт разбираться — краснел бы РАЗБОР, а не предикат, и опыт молча
	// перестал бы что-либо доказывать (`testing.md` §«Фикстура пробы, привязанная к
	// снимаемому предмету, истекает вместе с ним»).
	//
	// Взамен подставляется то, ВО ЧТО этот глагол разворачивался — его объявление
	// дословно, как оно стояло у типа. Ширина та же: прямой список субъектов делает
	// отношение ВЫДАВАЕМЫМ, а `super_admin` (= `admin from account`) приносит
	// источники уровня аккаунта. Форма живёт независимо от набора глаголов типа и
	// поэтому переживёт следующее его сужение.
	removalInjectedWidth = "define identity_remover: [user, service_account, group#member] or super_admin"
	// removalInjectedGrantable — сегодняшняя форма плюс прямой список субъектов:
	// круг держателей внешне тот же, но отношение становится ВЫДАВАЕМЫМ.
	removalInjectedGrantable = "define identity_remover: [user, service_account, group#member] or subject or super_admin from account"
	// removalInjectedNoSelf — сужение, забывшее самоудаление. Форма настоящая:
	// ровно так объявлены соседи по строке личности (`record_writer`,
	// `identity_suspender`), и для НИХ она верна — самоснятие запрета не бывает.
	removalInjectedNoSelf = "define identity_remover: super_admin from account"
	// removalInjectedNoCloud — сужение, забывшее надзор облака. Форма настоящая:
	// так объявлен `token_issuer`.
	removalInjectedNoCloud = "define identity_remover: subject"
)

// removalCleanCanonical — канонический текст модели плюс проверка предпосылки.
func removalCleanCanonical(t *testing.T) string {
	t.Helper()
	path, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmptyf(t, dsl, "канонический файл модели пуст: %s", path)
	clean := string(dsl)
	require.NotContainsf(t, clean, removalInjectedWidth,
		"предпосылка опыта: в %s прежней формы быть не должно — иначе «краснеет после инъекции» "+
			"ничего не доказывает, оно краснело бы и без неё", path)
	return clean
}

func removalInjected(t *testing.T, clean, define string) *authzplan.Model {
	t.Helper()
	text := replaceDefineInType(t, clean, removalType, "define "+removalRelation+":", define)
	require.Containsf(t, text, define, "инъекция %q не внеслась — опыт не поставлен", define)
	m, err := authzplan.ParseModel(text)
	require.NoErrorf(t, err, "инъекция обязана оставаться разбираемой моделью, иначе краснеет "+
		"разбор, а не предикат")
	return m
}

// TestRemovingTheIdentityGate_InjectionCutsBothWays — четыре оси, обе стороны.
func TestRemovingTheIdentityGate_InjectionCutsBothWays(t *testing.T) {
	clean := removalCleanCanonical(t)
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)

	// ── сторона 1: на чистом дереве предикат молчит по всем осям ──────────────
	base := inspectCredentialRelation(t, cleanModel, removalType, removalRelation)
	require.Emptyf(t, base.AccountLevel,
		"на дереве без дефекта предикат называет источники уровня аккаунта %v — значит он "+
			"утверждает не то, что измеряет", planSourceNames(base.AccountLevel))
	require.False(t, base.Grantable, "на дереве без дефекта отношение объявлено выдаваемым")
	require.True(t, base.HasSelf, "на дереве без дефекта сам человек не найден источником")
	require.True(t, base.HasCloud, "на дереве без дефекта надзор облака не найден источником")
	require.ElementsMatch(t, identityRemovalSources(), keysOf(base.Sources),
		"на дереве без дефекта круг держателей не равен объявленному — опыт ставится не над тем")

	// ── ось I: прежняя ширина возвращается ────────────────────────────────────
	wide := inspectCredentialRelation(t, removalInjected(t, clean, removalInjectedWidth),
		removalType, removalRelation)
	require.NotEmptyf(t, wide.AccountLevel,
		"инъекция %q не поймана: прежняя форма вернулась, а предикат молчит", removalInjectedWidth)
	names := planSourceNames(wide.AccountLevel)
	require.Containsf(t, names, "факт account#admin",
		"находка не НАЗЫВАЕТ делегированного распорядителя аккаунта — перечень: %v", names)
	require.Containsf(t, names, "факт account#owner",
		"находка не НАЗЫВАЕТ владельца аккаунта — перечень: %v", names)
	require.Truef(t, wide.Grantable,
		"прежняя форма обязана быть и ВЫДАВАЕМОЙ: глагол типа несёт прямой список субъектов, "+
			"и реконсайлер материализует его на строке приглашённого")

	// ── ось II: отношение становится выдаваемым ───────────────────────────────
	grantable := inspectCredentialRelation(t, removalInjected(t, clean, removalInjectedGrantable),
		removalType, removalRelation)
	require.Truef(t, grantable.Grantable,
		"инъекция %q не поймана: у отношения появился прямой список субъектов — то есть право "+
			"стереть личность можно ВРУЧИТЬ, — а предикат молчит", removalInjectedGrantable)
	require.Emptyf(t, grantable.AccountLevel,
		"ось II обязана менять РОВНО одно утверждение: источников уровня аккаунта здесь не "+
			"появляется (%v)", planSourceNames(grantable.AccountLevel))

	// ── ось III: самоудаление пропало ─────────────────────────────────────────
	noSelf := inspectCredentialRelation(t, removalInjected(t, clean, removalInjectedNoSelf),
		removalType, removalRelation)
	require.Falsef(t, noSelf.HasSelf,
		"инъекция %q не поймана: сужение отняло у человека право удалить самого себя, а предикат "+
			"молчит", removalInjectedNoSelf)
	require.Truef(t, noSelf.HasCloud,
		"ось III обязана менять РОВНО одно утверждение: надзор облака здесь остаётся")

	// ── ось IV: надзор облака пропал ──────────────────────────────────────────
	noCloud := inspectCredentialRelation(t, removalInjected(t, clean, removalInjectedNoCloud),
		removalType, removalRelation)
	require.Falsef(t, noCloud.HasCloud,
		"инъекция %q не поймана: чужую строку личности стало не удалить НИКОМУ, а предикат молчит",
		removalInjectedNoCloud)
	require.Truef(t, noCloud.HasSelf,
		"ось IV обязана менять РОВНО одно утверждение: сам человек здесь остаётся")

	t.Logf("опыт: осей проверено 4 · на чистом дереве источников %d (уровня аккаунта %d) · "+
		"по оси прежней ширины найдено %d: %v",
		len(base.Sources), len(base.AccountLevel), len(wide.AccountLevel), names)
}

// TestRemovingTheIdentityInjection_IsScopedToTheTypeNotTheSubstring — опыт над
// самим опытом.
//
// Замена по подстроке дала бы ЛОЖНО-ЗЕЛЁНЫЙ результат: объявление глагола стоит в
// модели у десятков типов, и текстовая правка попала бы в первый попавшийся —
// значит гейт «не поймал бы» инъекцию просто потому, что её поставили не туда.
// Здесь берётся заведомо НЕУНИКАЛЬНОЕ объявление и утверждается, что тронут
// ровно один тип.
//
// Неуникальным свидетелем стоял `define v_delete:` — он ушёл вместе со своим
// предметом (#1189: глагол снят с `iam_user`). Взят `define v_list:`: он объявлен и
// у подопытного, и у соседа, и НИ У ОДНОГО из них не несёт `subject` — значит
// утверждение «после инъекции самочтение появилось» не выполняется до неё.
func TestRemovingTheIdentityInjection_IsScopedToTheTypeNotTheSubstring(t *testing.T) {
	clean := removalCleanCanonical(t)

	const shared = "define v_list:"
	require.Greaterf(t, strings.Count(clean, shared), 1,
		"предпосылка опыта: объявление %q обязано встречаться у НЕСКОЛЬКИХ типов, иначе он не "+
			"отличает сужение по типу от замены по подстроке", shared)

	const injected = "define v_list: [user] or subject"
	text := replaceDefineInType(t, clean, removalType, shared, injected)
	require.Equalf(t, 1, strings.Count(text, injected),
		"инъекция внеслась %d раз(а) — сужение блоком типа не работает",
		strings.Count(text, injected))

	m, err := authzplan.ParseModel(text)
	require.NoError(t, err)

	// Тронут ИМЕННО `iam_user`.
	touched := inspectCredentialRelation(t, m, removalType, "v_list")
	require.Truef(t, touched.HasSelf,
		"опыт не тронул тип %s — замена ушла в другой блок", removalType)

	// Соседний тип с тем же объявлением НЕ тронут.
	untouched := inspectCredentialRelation(t, m, "iam_group", "v_list")
	require.Falsef(t, untouched.HasSelf,
		"замена задела соседний тип iam_group — сужение по типу не состоялось, и всякий "+
			"«зелёный» результат опыта выше ничего не доказывает")

	t.Logf("перепись: объявление %q встречается в модели %d раз(а); после сужения по типу "+
		"инъекция внеслась 1 раз", shared, strings.Count(clean, shared))
}
