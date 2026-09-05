// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reading_a_persons_session_history_injection_test.go — доказательство, что
// соседний гейт СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Зелёный гейт означает одно из двух: свойство держится либо предикат ослеп. По
// прочтении эти два состояния неотличимы, поэтому здесь ставится опыт.
//
// # Предикаты — ТЕ ЖЕ, а не копии
//
// Опыт зовёт `inspectCredentialRelation` (круг одного отношения) и
// `identitySideCircles` (согласие двух сторон личности) — ровно те функции, что
// зовёт гейт. Копия предиката доказывала бы, что работает копия: разойдясь с
// оригиналом, она разошлась бы молча и именно там, где расхождение не видно.
//
// # ИНЪЕКЦИЯ ИДЁТ ПО ТИПУ, А НЕ ПО ПОДСТРОКЕ
//
// Это не стилистика, а условие годности опыта. Одинаковые строки `define
// v_list:` стоят в модели у ДЕСЯТКОВ типов, и текстовая замена попала бы в
// первый попавшийся — то есть опыт ставился бы над чужим типом, инъекция «не
// ловилась» бы гейтом, и зелёный результат читался бы как доказательство. Здесь
// используется `replaceDefineInType`, который сужает замену блоком типа и
// ТРЕБУЕТ ровно одного попадания. Что он действительно сужает — доказано
// отдельно, `TestSessionHistoryInjection_IsScopedToTheTypeNotTheSubstring`: там
// инъекция ставится в неуникальное объявление и проверяется, что соседний тип
// не тронут.
//
// # Вход НАСТОЯЩИЙ, а не синтетика
//
// Каждая ось возвращает форму, которая в этом дереве РЕАЛЬНО стояла либо реально
// стоит у соседа. Модель из трёх строк доказала бы, что предикат работает на
// синтетике.
//
// # Осей ПЯТЬ, потому что утверждений у гейта пять
//
//	I.   прежняя ширина      — источники уровня аккаунта ВОЗВРАЩАЮТСЯ и НАЗЫВАЮТСЯ;
//	II.  прямой список       — отношение становится ВЫДАВАЕМЫМ;
//	III. без `subject`       — сам человек перестаёт быть источником;
//	IV.  без надзора облака  — расследование становится недостижимым;
//	V.   вторая сторона      — расходятся круги истории сессий и удостоверений.
//
// Ось V поставлена с ДРУГОЙ стороны намеренно: она трогает `token_reader`,
// оставляя `session_reader` нетронутым. Так проверяется, что согласие сторон
// утверждается САМО ПО СЕБЕ, а не оказывается побочным следствием четырёх
// утверждений выше: на этой оси все четыре обязаны остаться зелёными, а
// пятое — покраснеть.
package authzmap_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
)

const (
	// sessionRelation — отношение под опытом. Литерал здесь законен и нужен:
	// опыт РЕДАКТИРУЕТ текст модели, а редактировать можно только названное.
	// Гейт рядом имени не знает — он спрашивает его у каталога.
	sessionRelation = "session_reader"
	sessionType     = "iam_user"

	// sessionInjectedWidth — форма, стоявшая здесь до #1140. Читательский ярус
	// был не отдельным объявлением, а именем в записи каталога, поэтому
	// дословное возвращение прежнего состояния — это отношение, равное ярусу.
	sessionInjectedWidth = "define session_reader: viewer"
	// sessionInjectedGrantable — сегодняшняя форма плюс прямой список субъектов:
	// круг держателей внешне тот же, но отношение становится ВЫДАВАЕМЫМ.
	sessionInjectedGrantable = "define session_reader: [user, service_account, group#member] or subject or super_admin from account"
	// sessionInjectedNoSelf — сужение, забывшее самого человека.
	sessionInjectedNoSelf = "define session_reader: super_admin from account"
	// sessionInjectedNoCloud — сужение, забывшее надзор облака.
	sessionInjectedNoCloud = "define session_reader: subject"

	// credentialSideWidened — ось V: расширена ВТОРАЯ сторона личности. Форма
	// настоящая — ровно та, что стояла у `token_reader` до #1133.
	credentialSideWidened = "define token_reader: subject or v_list"
)

// sessionCleanCanonical — канонический текст модели плюс проверка предпосылки.
func sessionCleanCanonical(t *testing.T) string {
	t.Helper()
	path, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmptyf(t, dsl, "канонический файл модели пуст: %s", path)
	clean := string(dsl)
	require.NotContainsf(t, clean, sessionInjectedWidth,
		"предпосылка опыта: в %s прежней формы быть не должно — иначе «краснеет после инъекции» "+
			"ничего не доказывает, оно краснело бы и без неё", path)
	return clean
}

// sessionInjected — модель с заменённым объявлением отношения под опытом.
func sessionInjected(t *testing.T, clean, define string) *authzplan.Model {
	t.Helper()
	return sessionInjectedInto(t, clean, sessionType, sessionRelation, define)
}

// sessionInjectedInto — то же, но с явно названными типом и отношением: ось V
// правит ВТОРУЮ сторону личности, и подменять её адрес умолчанием нельзя.
func sessionInjectedInto(t *testing.T, clean, typeName, relation, define string) *authzplan.Model {
	t.Helper()
	text := replaceDefineInType(t, clean, typeName, "define "+relation+":", define)
	require.Containsf(t, text, define, "инъекция %q не внеслась — опыт не поставлен", define)
	m, err := authzplan.ParseModel(text)
	require.NoErrorf(t, err, "инъекция обязана оставаться разбираемой моделью, иначе краснеет "+
		"разбор, а не предикат")
	return m
}

// TestSessionHistoryGate_InjectionCutsBothWays — пять осей, обе стороны.
func TestSessionHistoryGate_InjectionCutsBothWays(t *testing.T) {
	clean := sessionCleanCanonical(t)
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)

	// ── сторона 1: на чистом дереве предикат молчит по всем осям ──────────────
	base := inspectCredentialRelation(t, cleanModel, sessionType, sessionRelation)
	require.Emptyf(t, base.AccountLevel,
		"на дереве без дефекта предикат называет источники уровня аккаунта %v — значит он "+
			"утверждает не то, что измеряет", base.AccountLevel)
	require.False(t, base.Grantable, "на дереве без дефекта отношение объявлено выдаваемым")
	require.True(t, base.HasSelf, "на дереве без дефекта сам человек не найден источником")
	require.True(t, base.HasCloud, "на дереве без дефекта надзор облака не найден источником")
	require.ElementsMatch(t, personalCredentialSources(), keysOf(base.Sources),
		"на дереве без дефекта круг держателей не равен объявленному — опыт ставится не над тем")

	// ── ось I: прежняя ширина возвращается ────────────────────────────────────
	wide := inspectCredentialRelation(t, sessionInjected(t, clean, sessionInjectedWidth),
		sessionType, sessionRelation)
	require.NotEmptyf(t, wide.AccountLevel,
		"инъекция %q не поймана: прежняя форма вернулась, а предикат молчит", sessionInjectedWidth)
	names := planSourceNames(wide.AccountLevel)
	require.Containsf(t, names, "факт account#admin",
		"находка не НАЗЫВАЕТ делегированного распорядителя аккаунта — перечень: %v", names)
	require.Containsf(t, names, "факт account#owner",
		"находка не НАЗЫВАЕТ владельца аккаунта — перечень: %v", names)
	require.Truef(t, wide.Grantable,
		"прежняя форма обязана быть и ВЫДАВАЕМОЙ: читательский ярус несёт прямые списки "+
			"субъектов трёх ярусов, и реконсайлер пишет в них back-compat кортеж")

	// ── ось II: отношение становится выдаваемым ───────────────────────────────
	grantable := inspectCredentialRelation(t, sessionInjected(t, clean, sessionInjectedGrantable),
		sessionType, sessionRelation)
	require.Truef(t, grantable.Grantable,
		"инъекция %q не поймана: у отношения появился прямой список субъектов — то есть его "+
			"можно ВРУЧИТЬ, — а предикат молчит", sessionInjectedGrantable)
	require.Emptyf(t, grantable.AccountLevel,
		"ось II обязана менять РОВНО одно утверждение: источников уровня аккаунта здесь не "+
			"появляется (%v)", grantable.AccountLevel)

	// ── ось III: сам человек пропал ───────────────────────────────────────────
	noSelf := inspectCredentialRelation(t, sessionInjected(t, clean, sessionInjectedNoSelf),
		sessionType, sessionRelation)
	require.Falsef(t, noSelf.HasSelf,
		"инъекция %q не поймана: сужение отняло у человека его же историю сессий, а предикат "+
			"молчит", sessionInjectedNoSelf)
	require.Truef(t, noSelf.HasCloud,
		"ось III обязана менять РОВНО одно утверждение: надзор облака здесь остаётся")

	// ── ось IV: надзор облака пропал ──────────────────────────────────────────
	noCloud := inspectCredentialRelation(t, sessionInjected(t, clean, sessionInjectedNoCloud),
		sessionType, sessionRelation)
	require.Falsef(t, noCloud.HasCloud,
		"инъекция %q не поймана: расследование инцидента стало недостижимым, а предикат молчит",
		sessionInjectedNoCloud)
	require.Truef(t, noCloud.HasSelf,
		"ось IV обязана менять РОВНО одно утверждение: сам человек здесь остаётся")

	t.Logf("опыт: осей отношения проверено 4 · на чистом дереве источников %d (уровня аккаунта "+
		"%d) · по оси прежней ширины найдено %d: %v",
		len(base.Sources), len(base.AccountLevel), len(wide.AccountLevel), names)
}

// TestSessionHistoryGate_SidesDisagreeWhenTheOtherSideMoves — ось V.
//
// Согласие двух сторон личности — САМОСТОЯТЕЛЬНОЕ утверждение, и доказывается
// это тем, что оно краснеет от правки, не трогающей `session_reader` вовсе: все
// четыре утверждения об отношении истории сессий на этой оси остаются зелёными.
// Без такого опыта «стороны согласны» было бы неотличимо от предиката, который
// сравнивает нечто, равное всегда.
func TestSessionHistoryGate_SidesDisagreeWhenTheOtherSideMoves(t *testing.T) {
	clean := sessionCleanCanonical(t)
	catalog := catalogByFQN(t)
	sess, ok := catalog[sessionHistoryRPC]
	require.Truef(t, ok, "каталог не знает %s", sessionHistoryRPC)
	tok, ok := catalog[credentialListRPC]
	require.Truef(t, ok, "каталог не знает %s", credentialListRPC)

	// сторона 1 — на чистом дереве круги равны.
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)
	baseSess, baseTok := identitySideCircles(t, cleanModel, sess, tok)
	require.ElementsMatch(t, keysOf(baseTok), keysOf(baseSess),
		"на чистом дереве круги двух сторон личности не равны — опыт ставится не над тем")

	// сторона 2 — двинута ВТОРАЯ сторона; предикат обязан это увидеть.
	moved := sessionInjectedInto(t, clean, sessionType, "token_reader", credentialSideWidened)
	injSess, injTok := identitySideCircles(t, moved, sess, tok)
	require.NotElementsMatchf(t, keysOf(injTok), keysOf(injSess),
		"инъекция %q не поймана: перечень удостоверений стал шире истории сессий (%v против "+
			"%v), а предикат объявляет стороны согласными",
		credentialSideWidened, sortedKeys(injTok), sortedKeys(injSess))

	// сторона 3 — четыре утверждения ОБ ОТНОШЕНИИ ИСТОРИИ на этой оси немы.
	// Именно это делает согласие сторон самостоятельным утверждением, а не
	// следствием остальных.
	untouched := inspectCredentialRelation(t, moved, sessionType, sessionRelation)
	require.Empty(t, untouched.AccountLevel,
		"ложная находка: инъекция во ВТОРУЮ сторону дала истории сессий источники уровня аккаунта")
	require.False(t, untouched.Grantable,
		"ложная находка: инъекция во вторую сторону сделала историю сессий выдаваемой")
	require.True(t, untouched.HasSelf,
		"ложная находка: инъекция во вторую сторону отняла у истории сессий самого человека")
	require.True(t, untouched.HasCloud,
		"ложная находка: инъекция во вторую сторону отняла у истории сессий надзор облака")
	require.ElementsMatch(t, personalCredentialSources(), keysOf(untouched.Sources),
		"ложная находка: инъекция во вторую сторону изменила круг держателей истории сессий")

	t.Logf("ось V: на чистом дереве круг из %d источников совпадает у обеих сторон; после "+
		"расширения стороны удостоверений — %d против %d, при нетронутых четырёх утверждениях "+
		"об истории сессий", len(baseSess), len(injTok), len(injSess))
}

// TestSessionHistoryGate_TwinsStaySilent — законные близнецы немы на ТОМ ЖЕ
// прогоне, где инъекция краснеет.
//
// Близнецы выбраны по СМЫСЛУ, а не по написанию: `token_issuer` сужен по тому же
// основанию (#1086), `record_writer` несёт надзор облака той же формой (#1102).
// Близнец, полученный из дефекта заменой имени, доказывал бы лишь то, что
// предикат различает две строки.
func TestSessionHistoryGate_TwinsStaySilent(t *testing.T) {
	clean := sessionCleanCanonical(t)
	checked := 0
	for _, define := range []string{
		sessionInjectedWidth, sessionInjectedGrantable, sessionInjectedNoSelf, sessionInjectedNoCloud,
	} {
		model := sessionInjected(t, clean, define)

		issuer := inspectCredentialRelation(t, model, sessionType, "token_issuer")
		require.Emptyf(t, issuer.AccountLevel,
			"ложная находка: инъекция в %q задела близнеца `token_issuer` (%v) — предикат ловит "+
				"не отношение, а модель целиком", define, issuer.AccountLevel)
		require.Falsef(t, issuer.Grantable,
			"ложная находка: `token_issuer` объявлен выдаваемым после инъекции в %q", define)
		require.Truef(t, issuer.HasSelf,
			"ложная находка: `token_issuer` потерял самого человека после инъекции в %q", define)

		writer := inspectCredentialRelation(t, model, sessionType, "record_writer")
		require.Truef(t, writer.HasCloud,
			"ложная находка: инъекция в %q отняла надзор облака у близнеца `record_writer`", define)
		require.Emptyf(t, writer.AccountLevel,
			"ложная находка: инъекция в %q дала близнецу `record_writer` источники уровня "+
				"аккаунта (%v)", define, writer.AccountLevel)
		checked++
	}
	t.Logf("опыт: инъекций прогнано %d · близнецов на каждой 2 (`token_issuer`, `record_writer`)",
		checked)
}

// TestSessionHistoryInjection_IsScopedToTheTypeNotTheSubstring — доказательство,
// что обход инъекции идёт ПО ТИПУ.
//
// Предмет отдельного опыта, а не примечания: имена отношений этого гейта
// (`session_reader`, `token_reader`) в модели УНИКАЛЬНЫ, поэтому на них
// текстовая замена и замена по типу дают один результат — то есть по осям выше
// разницу между верным и неверным обходом увидеть НЕЛЬЗЯ. Она видна только на
// неуникальном объявлении, и здесь берётся именно оно: `define v_list:` стоит у
// десятков типов, и текстовая замена попала бы в ПЕРВЫЙ по тексту.
//
// Утверждается обе стороны: адресованный тип изменился, соседний — нет.
func TestSessionHistoryInjection_IsScopedToTheTypeNotTheSubstring(t *testing.T) {
	clean := sessionCleanCanonical(t)

	// ПРЕДПОСЫЛКА опыта: объявление неуникально. Будь оно уникальным, опыт не
	// различал бы обход по типу и обход по подстроке — и молча ничего бы не
	// доказывал.
	const ambiguous = "define v_list:"
	occurrences := strings.Count(clean, ambiguous)
	require.Greaterf(t, occurrences, 1,
		"предпосылка опыта: %q обязано быть НЕуникальным в модели, иначе обход по подстроке и "+
			"обход по типу неразличимы; найдено вхождений: %d", ambiguous, occurrences)

	// Соседний тип выбирается ИЗ МОДЕЛИ, а не выписывается: выписанное имя
	// пережило бы свой предмет молча.
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)
	var neighbour string
	for _, name := range cleanModel.TypeNames() {
		if name == sessionType {
			continue
		}
		if ty := cleanModel.Type(name); ty != nil && ty.Rel("v_list") != nil {
			neighbour = name
			break
		}
	}
	require.NotEmptyf(t, neighbour,
		"в модели нет второго типа с %q — опыту не с чем сравнивать", ambiguous)

	const injected = "define v_list: [user] or super_admin"
	text := replaceDefineInType(t, clean, sessionType, ambiguous, injected)
	model, err := authzplan.ParseModel(text)
	require.NoError(t, err, "инъекция обязана оставаться разбираемой моделью")

	// Сторона 1 — АДРЕСОВАННЫЙ тип изменился.
	got := model.Type(sessionType).Rel("v_list").Raw
	require.Containsf(t, got, "[user] or super_admin",
		"инъекция не внеслась в адресованный тип %q — опыт не поставлен", sessionType)

	// Сторона 2 — СОСЕДНИЙ тип не тронут. Ровно это и промахнулась бы текстовая
	// замена: она изменила бы первый по тексту `define v_list:`, каким бы типу
	// он ни принадлежал.
	before := cleanModel.Type(neighbour).Rel("v_list").Raw
	after := model.Type(neighbour).Rel("v_list").Raw
	require.Equalf(t, before, after,
		"инъекция, адресованная типу %q, изменила объявление у СОСЕДНЕГО типа %q (%q → %q). "+
			"Значит обход идёт по подстроке, а не по типу: тогда всякий зелёный результат "+
			"опыта выше означает лишь, что правка ушла не туда.",
		sessionType, neighbour, before, after)

	t.Logf("обход по типу: %q встречается в модели %d раз · инъекция в %q внеслась · соседний "+
		"тип %q не тронут", ambiguous, occurrences, sessionType, neighbour)
}
