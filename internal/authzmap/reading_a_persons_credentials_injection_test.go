// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reading_a_persons_credentials_injection_test.go — доказательство, что соседний
// гейт СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Зелёный гейт означает одно из двух: свойство держится либо предикат ослеп. По
// прочтении эти два состояния неотличимы, поэтому здесь ставится опыт.
//
// # Предикат один, а не копия
//
// Опыт зовёт ТУ ЖЕ функцию `inspectCredentialRelation`, что и гейт. Копия
// предиката доказывала бы, что работает копия: разойдясь с оригиналом, она
// разошлась бы молча и именно там, где расхождение не видно.
//
// # Вход НАСТОЯЩИЙ, а не синтетика
//
// Инъекция идёт в канонический текст модели, и каждая ось возвращает форму,
// которая в этом дереве РЕАЛЬНО стояла либо реально стоит у соседа. Модель из
// трёх строк доказала бы, что предикат работает на синтетике.
//
// # Осей ЧЕТЫРЕ, потому что утверждений у гейта четыре
//
// Одна инъекция, роняющая гейт целиком, доказывает способность упасть — и ничего
// не говорит о том, какое из четырёх утверждений её поймало. Ось на утверждение:
//
//	I. прежняя ширина        — источники уровня аккаунта ВОЗВРАЩАЮТСЯ и НАЗЫВАЮТСЯ;
//	II. прямой список        — отношение становится ВЫДАВАЕМЫМ;
//	III. без `subject`       — сам человек перестаёт быть источником;
//	IV. без надзора облака   — расследование становится недостижимым.
//
// # Законные близнецы — РАЗНЫЕ отношения, а не переименованная копия
//
// По каждой оси рядом стоит отношение, которое обязано остаться немым на ТОМ ЖЕ
// прогоне: `token_issuer` (сужен по тому же основанию, #1086) и `record_writer`
// (несёт надзор облака, #1102). Близнец, полученный из дефекта заменой имени,
// доказывал бы лишь то, что предикат различает две строки.
//
// # Каждое утверждение обязано быть НЕСУЩИМ
//
// Мало показать, что близнец нем: он мог бы молчать и потому, что предикат не
// умеет находить свойство ВООБЩЕ. Поэтому рядом — встречный опыт на отношении,
// у которого свойство законно ЕСТЬ (`v_list` на той же строке личности): предикат
// обязан назвать его и выдаваемым, и несущим источники уровня аккаунта.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
)

const (
	// credentialRelation — отношение под опытом. Литерал здесь законен и нужен:
	// опыт РЕДАКТИРУЕТ текст модели, а редактировать можно только названное.
	// Гейт рядом имени не знает — он спрашивает его у каталога.
	credentialRelation = "token_reader"
	credentialType     = "iam_user"

	// injectedWidth — форма, стоявшая здесь до #1133, дословно.
	injectedWidth = "define token_reader: subject or v_list"
	// injectedGrantable — та же сегодняшняя форма плюс прямой список субъектов:
	// круг держателей внешне тот же, но отношение становится ВЫДАВАЕМЫМ.
	injectedGrantable = "define token_reader: [user, service_account, group#member] or subject or super_admin from account"
	// injectedNoSelf — сужение, забывшее самого человека.
	injectedNoSelf = "define token_reader: super_admin from account"
	// injectedNoCloud — сужение, забывшее надзор облака.
	injectedNoCloud = "define token_reader: subject"
)

// cleanCanonical — канонический текст модели плюс проверка предпосылки опыта.
func cleanCanonical(t *testing.T) string {
	t.Helper()
	path, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmptyf(t, dsl, "канонический файл модели пуст: %s", path)
	clean := string(dsl)
	require.NotContainsf(t, clean, injectedWidth,
		"предпосылка опыта: в %s прежней формы быть не должно — иначе «краснеет после инъекции» "+
			"ничего не доказывает, оно краснело бы и без неё", path)
	return clean
}

// injected — модель с заменённым объявлением отношения под опытом.
func injected(t *testing.T, clean, define string) *authzplan.Model {
	t.Helper()
	text := replaceDefineInType(t, clean, credentialType, "define "+credentialRelation+":", define)
	require.Containsf(t, text, define, "инъекция %q не внеслась — опыт не поставлен", define)
	m, err := authzplan.ParseModel(text)
	require.NoErrorf(t, err, "инъекция обязана оставаться разбираемой моделью, иначе краснеет "+
		"разбор, а не предикат")
	return m
}

// TestReadingCredentialsGate_InjectionCutsBothWays — четыре оси, обе стороны.
func TestReadingCredentialsGate_InjectionCutsBothWays(t *testing.T) {
	clean := cleanCanonical(t)
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)

	// ── сторона 1: на чистом дереве предикат молчит по всем четырём осям ───────
	base := inspectCredentialRelation(t, cleanModel, credentialType, credentialRelation)
	require.Emptyf(t, base.AccountLevel,
		"на дереве без дефекта предикат называет источники уровня аккаунта %v — значит он "+
			"утверждает не то, что измеряет", base.AccountLevel)
	require.False(t, base.Grantable, "на дереве без дефекта отношение объявлено выдаваемым")
	require.True(t, base.HasSelf, "на дереве без дефекта сам человек не найден источником")
	require.True(t, base.HasCloud, "на дереве без дефекта надзор облака не найден источником")
	require.ElementsMatch(t, personalCredentialSources(), keysOf(base.Sources),
		"на дереве без дефекта круг держателей не равен объявленному — опыт ставится не над тем")

	// ── ось I: прежняя ширина возвращается ────────────────────────────────────
	wide := inspectCredentialRelation(t, injected(t, clean, injectedWidth), credentialType, credentialRelation)
	require.NotEmptyf(t, wide.AccountLevel,
		"инъекция %q не поймана: прежняя форма вернулась, а предикат молчит", injectedWidth)
	names := planSourceNames(wide.AccountLevel)
	require.Containsf(t, names, "выдача <сам объект>#v_list",
		"находка не НАЗЫВАЕТ пообъектную выдачу — перечень: %v", names)
	require.Containsf(t, names, "факт account#admin",
		"находка не НАЗЫВАЕТ делегированного распорядителя аккаунта — перечень: %v", names)
	require.Containsf(t, names, "факт account#owner",
		"находка не НАЗЫВАЕТ владельца аккаунта — перечень: %v", names)

	// ── ось II: отношение становится выдаваемым ───────────────────────────────
	grantable := inspectCredentialRelation(t, injected(t, clean, injectedGrantable), credentialType, credentialRelation)
	require.Truef(t, grantable.Grantable,
		"инъекция %q не поймана: у отношения появился прямой список субъектов — то есть его "+
			"можно ВРУЧИТЬ, — а предикат молчит", injectedGrantable)

	// ── ось III: сам человек пропал ───────────────────────────────────────────
	noSelf := inspectCredentialRelation(t, injected(t, clean, injectedNoSelf), credentialType, credentialRelation)
	require.Falsef(t, noSelf.HasSelf,
		"инъекция %q не поймана: сужение отняло у владельца его же удостоверения, а предикат "+
			"молчит", injectedNoSelf)
	require.Truef(t, noSelf.HasCloud,
		"ось III обязана менять РОВНО одно утверждение: надзор облака здесь остаётся")

	// ── ось IV: надзор облака пропал ──────────────────────────────────────────
	noCloud := inspectCredentialRelation(t, injected(t, clean, injectedNoCloud), credentialType, credentialRelation)
	require.Falsef(t, noCloud.HasCloud,
		"инъекция %q не поймана: расследование стало недостижимым, а предикат молчит", injectedNoCloud)
	require.Truef(t, noCloud.HasSelf,
		"ось IV обязана менять РОВНО одно утверждение: сам человек здесь остаётся")

	t.Logf("опыт: осей проверено 4 · на чистом дереве источников %d (уровня аккаунта %d) · "+
		"по оси прежней ширины найдено %d: %v",
		len(base.Sources), len(base.AccountLevel), len(wide.AccountLevel), names)
}

// TestReadingCredentialsGate_TwinsStaySilent — законные близнецы немы на ТОМ ЖЕ
// прогоне, где инъекция краснеет.
//
// Близнецы выбраны по СМЫСЛУ, а не по написанию: `token_issuer` сужен по тому же
// основанию (#1086), `record_writer` несёт надзор облака той же формой (#1102).
// Инъекция трогает только `token_reader`, поэтому оба обязаны остаться немыми —
// иначе предикат ловит не отношение, а модель целиком.
func TestReadingCredentialsGate_TwinsStaySilent(t *testing.T) {
	clean := cleanCanonical(t)
	checked := 0
	for _, define := range []string{injectedWidth, injectedGrantable, injectedNoSelf, injectedNoCloud} {
		model := injected(t, clean, define)

		issuer := inspectCredentialRelation(t, model, credentialType, "token_issuer")
		require.Emptyf(t, issuer.AccountLevel,
			"ложная находка: инъекция в %q задела близнеца `token_issuer` (%v) — предикат ловит "+
				"не отношение, а модель целиком", define, issuer.AccountLevel)
		require.Falsef(t, issuer.Grantable, "ложная находка: `token_issuer` объявлен выдаваемым "+
			"после инъекции в %q", define)
		require.Truef(t, issuer.HasSelf, "ложная находка: `token_issuer` потерял самого человека "+
			"после инъекции в %q", define)

		writer := inspectCredentialRelation(t, model, credentialType, "record_writer")
		require.Truef(t, writer.HasCloud,
			"ложная находка: инъекция в %q отняла надзор облака у близнеца `record_writer`", define)
		require.Emptyf(t, writer.AccountLevel,
			"ложная находка: инъекция в %q дала близнецу `record_writer` источники уровня "+
				"аккаунта (%v)", define, writer.AccountLevel)
		checked++
	}
	t.Logf("опыт: инъекций прогнано %d · близнецов на каждой 2 (`token_issuer`, `record_writer`)", checked)
}

// TestReadingCredentialsGate_PredicateFindsWhatIsLegitimatelyThere — каждое
// утверждение НЕСУЩЕЕ.
//
// Тишина близнецов выше ничего не значит, если предикат не умеет находить свойство
// вообще. Здесь он спрашивается об отношении, у которого свойство законно ЕСТЬ:
// `v_list` на той же строке личности несёт и пообъектную выдачу, и источники
// уровня аккаунта, и прямой список субъектов. Предикат обязан назвать всё три —
// и обязан НЕ найти у него `subject`, иначе положительный контроль гейта был бы
// истинным для любого отношения.
func TestReadingCredentialsGate_PredicateFindsWhatIsLegitimatelyThere(t *testing.T) {
	clean := cleanCanonical(t)
	model, err := authzplan.ParseModel(clean)
	require.NoError(t, err)

	wide := inspectCredentialRelation(t, model, credentialType, "v_list")
	names := planSourceNames(wide.AccountLevel)
	require.Containsf(t, names, "выдача <сам объект>#v_list",
		"предикат не видит пообъектную выдачу там, где она законна — перечень: %v", names)
	require.Containsf(t, names, "факт account#admin",
		"предикат не видит распорядителя аккаунта там, где он законен — перечень: %v", names)
	require.True(t, wide.Grantable, "предикат не видит выдаваемость там, где она законна")
	require.True(t, wide.HasCloud, "предикат не видит надзор облака там, где он законен")
	require.Falsef(t, wide.HasSelf,
		"предикат нашёл самого человека у `v_list`, где его нет: тогда положительный контроль "+
			"гейта истинен для любого отношения и ничего не утверждает")

	t.Logf("встречный опыт: у `iam_user.v_list` источников %d, из них уровня аккаунта %d: %v",
		len(wide.Sources), len(wide.AccountLevel), names)
}

// planSourceNames — читаемые имена источников, чтобы находка НАЗЫВАЛА предмет, а
// не печатала числовой вид атома.
func planSourceNames(src []planSource) []string {
	out := make([]string, 0, len(src))
	for _, s := range src {
		parent := s.ParentType
		if parent == "" {
			parent = "<сам объект>"
		}
		kind := "факт"
		if s.Kind == authzplan.AtomBinding {
			kind = "выдача"
		}
		out = append(out, kind+" "+parent+"#"+s.Relation)
	}
	return out
}

// saKeyWidenedRead — чтение ключей машины, расширенное источником, которого нет у
// выпуска: читательский ярус той же учётки. Форма настоящая — ровно так выглядела
// бы «доброта к читателю» («пусть видит перечень тот, кто и так её видит»), ради
// которой класс #1133 завёлся у человека.
//
// ГРАНИЦА ПРЕДИКАТА НАЗВАНА, А НЕ УМОЛЧАНА. План различает ВИД источника и предка,
// на котором тот лежит, но не различает СОСТАВ прямого списка субъектов: добавь в
// него подстановочную запись — атом останется тем же, и это сравнение кругов
// смолчит. Класс «отношение, выполнимое подстановкой» ловится не здесь и ловиться
// здесь не должен: у него свой предмет и свой предикат. Первая редакция этого
// опыта инъектировала именно подстановку и была зелёной — то есть доказывала
// способность упасть тем, чего предикат не измеряет.
const saKeyWidenedRead = "define v_list: [user, service_account, group#member] or super_admin or viewer"

// TestServiceAccountKeyCircleGate_InjectionCutsBothWays — гейт смежного предмета
// СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Без этого опыта «круги равны» неотличимо от «предикат сравнивает нечто, что
// равно всегда»: имена собственных глаголов у чтения и выпуска РАЗНЫЕ by
// construction, и первая редакция сравнения была красной именно поэтому — то
// есть измеряла написание, а не свойство.
func TestServiceAccountKeyCircleGate_InjectionCutsBothWays(t *testing.T) {
	clean := cleanCanonical(t)
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)

	// сторона 1 — на чистом дереве круги равны.
	baseRead := holderCircle(t, cleanModel, "iam_service_account", "v_list")
	baseMutate := holderCircle(t, cleanModel, "iam_service_account", "v_update")
	require.ElementsMatch(t, keysOf(baseMutate), keysOf(baseRead),
		"на чистом дереве круги чтения и выпуска у машины не равны — опыт ставится не над тем")

	// сторона 2 — чтение расширено, предикат обязан это увидеть.
	widened := replaceDefineInType(t, clean, "iam_service_account", "define v_list:", saKeyWidenedRead)
	require.Contains(t, widened, saKeyWidenedRead, "инъекция не внеслась — опыт не поставлен")
	widenedModel, err := authzplan.ParseModel(widened)
	require.NoError(t, err, "инъекция обязана оставаться разбираемой моделью")
	injRead := holderCircle(t, widenedModel, "iam_service_account", "v_list")
	injMutate := holderCircle(t, widenedModel, "iam_service_account", "v_update")
	require.NotElementsMatchf(t, keysOf(injMutate), keysOf(injRead),
		"инъекция не поймана: чтение ключей стало шире выпуска (%v против %v), а предикат "+
			"объявляет круги равными", sortedKeys(injRead), sortedKeys(injMutate))

	// законный близнец — человек: его круги инъекция не трогает.
	twin := holderCircle(t, widenedModel, credentialType, credentialRelation)
	require.ElementsMatchf(t, personalCredentialSources(), keysOf(twin),
		"ложная находка: инъекция в круг машины задела круг человека (%v)", sortedKeys(twin))

	t.Logf("опыт смежного предмета: на чистом дереве круг из %d источников совпадает у чтения и "+
		"выпуска; после расширения чтения — %d против %d", len(baseRead), len(injRead), len(injMutate))
}
