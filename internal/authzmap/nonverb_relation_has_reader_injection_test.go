// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// nonverb_relation_has_reader_injection_test.go — доказательство, что соседний
// гейт СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Зелёный гейт означает одно из двух: свойство держится либо предикат ослеп. По
// прочтении эти два состояния неотличимы, поэтому здесь ставится опыт: дефект
// возвращается в дерево — гейт обязан покраснеть И НАЗВАТЬ пару; законный близнец
// остаётся на месте — гейт обязан промолчать.
//
// # Вход — НАСТОЯЩИЙ, а не синтетика
//
// Инъекция идёт в канонический текст модели, а читатели берутся те же, что у
// гейта: вшитый каталог прав и разобранные литералы прод-кода. Синтетическая
// модель из трёх строк доказала бы, что предикат работает на синтетике; здесь
// доказывается, что он работает на предмете.
//
// # Законные близнецы — РАЗНЫЕ отношения, а не переименованная копия
//
// Близнец, полученный из дефекта заменой имени, доказывает лишь то, что предикат
// различает две строки. Поэтому близнецов ТРИ, и каждый читается СВОИМ источником:
// `iam_user#token_issuer` — каталогом, `iam_service_account#admin` — выводом самой
// модели, `compute_instance#ssh` — литералом прод-кода. Все три остаются немы на
// том же прогоне, где инъекция краснеет.
//
// # Каждый источник обязан быть НЕСУЩИМ
//
// Мало показать, что близнец нем: он мог бы молчать и потому, что его источник
// вообще не читается, а тишина шла бы от другого. Поэтому по каждому источнику
// ставится встречный опыт — источник ослепляется, и его близнец обязан стать
// находкой. Источник, при ослеплении которого ничего не меняется, в предикате не
// участвует.
package authzmap_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/authzplan"
)

// injectedDefine — объявление, снятое задачей #1101. Возвращается дословно.
const injectedDefine = "define token_creator: [user, service_account] or admin"

// injectedPair — пара, которую гейт обязан назвать, когда объявление вернулось.
var injectedPair = relPair{Type: "iam_service_account", Relation: "token_creator"}

// legitimateTwins — отношения, читаемые СВОИМ источником. Ни одно не является
// переименованием инъекции: у каждого свой тип, своё имя и свой читатель.
var legitimateTwins = map[relPair]string{
	{Type: "iam_user", Relation: "token_issuer"}:     "каталог (UserTokenService.Issue/Revoke требуют его)",
	{Type: "iam_service_account", Relation: "admin"}: "вывод модели (`editor: … or admin` того же типа)",
	{Type: "compute_instance", Relation: "ssh"}:      "литерал прод-кода (приведение глагола запроса к отношению в iam)",
}

// TestNonVerbReaderGate_InjectionCutsBothWays — дефект краснеет, законное молчит.
func TestNonVerbReaderGate_InjectionCutsBothWays(t *testing.T) {
	root := monorepoRoot(t)
	catalog, catalogEntries := iamCatalogRequiredRelations(t, root)
	codeLits, filesParsed := prodCodeStringLiterals(t, root)
	require.Positive(t, catalogEntries, "каталог пуст — опыт ставится не над тем")
	require.Positive(t, filesParsed, "прод-код не разобран — опыт ставится не над тем")

	path, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	clean := string(dsl)
	require.NotContainsf(t, clean, "define token_creator",
		"предпосылка опыта: в %s ОБЪЯВЛЕНИЯ быть не должно — иначе «краснеет после инъекции» "+
			"ничего не доказывает, оно краснело бы и без неё. Разбор слова недостаточен: имя "+
			"снятого отношения законно стоит рядом в прозе, объясняющей снятие", path)

	// ── сторона 1: без инъекции гейт молчит про пару ────────────────────────────
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)
	require.Nilf(t, cleanModel.Type(injectedPair.Type).Rel(injectedPair.Relation),
		"предпосылка опыта: разобранная модель не должна нести %q", injectedPair)
	cleanDead, cleanCensus := nonVerbDeadRelations(cleanModel, catalog, codeLits)
	require.NotContainsf(t, deadPairNames(cleanDead), injectedPair.String(),
		"на дереве без дефекта предикат называет %q — значит он утверждает не то, что измеряет", injectedPair)

	// ── сторона 2: дефект возвращён — гейт краснеет И НАЗЫВАЕТ пару ─────────────
	injected := injectRelationIntoType(t, clean, injectedPair.Type, injectedDefine)
	require.Contains(t, injected, injectedDefine, "инъекция не внеслась — опыт не поставлен")
	injectedModel, err := authzplan.ParseModel(injected)
	require.NoError(t, err, "инъекция обязана оставаться разбираемой моделью, иначе краснеет разбор, а не предикат")
	injDead, injCensus := nonVerbDeadRelations(injectedModel, catalog, codeLits)
	require.Containsf(t, deadPairNames(injDead), injectedPair.String(),
		"инъекция не поймана: объявление %q вернулось в модель, читателя у него нет, а предикат молчит", injectedDefine)
	require.Equalf(t, cleanCensus.Dead+1, injCensus.Dead,
		"инъекция обязана прибавить РОВНО одну находку, иначе предикат считает не то")
	require.Equalf(t, cleanCensus.NonVerb+1, injCensus.NonVerb,
		"инъекция обязана прибавить ровно одно неглагольное объявление")

	// ── законные близнецы: немы на ТОМ ЖЕ прогоне ──────────────────────────────
	injNames := deadPairNames(injDead)
	for twin, why := range legitimateTwins {
		require.NotNilf(t, injectedModel.Type(twin.Type), "близнец %q исчез из модели — опыт потерял свой предмет", twin)
		require.NotNilf(t, injectedModel.Type(twin.Type).Rel(twin.Relation),
			"близнец %q исчез из модели — опыт потерял свой предмет", twin)
		require.NotContainsf(t, injNames, twin.String(),
			"ложная находка: %q читается (%s), но предикат назвал его мёртвым — гейт с ложными "+
				"находками перестают читать, и тогда он не ловит ничего", twin, why)
	}

	t.Logf("опыт: без инъекции мёртвых %d, с инъекцией %d (прибавилась %s); "+
		"законных близнецов проверено %d; осмотрено записей каталога %d, прод-файлов %d",
		cleanCensus.Dead, injCensus.Dead, injectedPair, len(legitimateTwins), catalogEntries, filesParsed)
}

// TestNonVerbReaderGate_EverySourceIsLoadBearing — каждый источник читателя
// НЕСУЩИЙ: ослепи его, и его близнец обязан стать находкой.
//
// Без этого опыта тишина по близнецу ничего не значит: она могла бы идти от
// другого источника, а сам проверяемый — не участвовать в предикате вовсе.
func TestNonVerbReaderGate_EverySourceIsLoadBearing(t *testing.T) {
	root := monorepoRoot(t)
	catalog, _ := iamCatalogRequiredRelations(t, root)
	codeLits, _ := prodCodeStringLiterals(t, root)
	model := canonicalModel(t)

	emptyCatalog := map[string]map[string]bool{}
	emptyLits := map[string]bool{}

	// Источник «каталог»: без него отношение, которое требует только каталог,
	// становится мёртвым.
	catalogTwin := relPair{Type: "iam_user", Relation: "token_issuer"}
	blindCatalog, _ := nonVerbDeadRelations(model, emptyCatalog, codeLits)
	require.Containsf(t, deadPairNames(blindCatalog), catalogTwin.String(),
		"источник «каталог» не несущий: он ослеплён, а %q всё равно числится читаемым", catalogTwin)

	// Источник «прод-код»: без него отношение, которое называет только код,
	// становится мёртвым.
	codeTwin := relPair{Type: "compute_instance", Relation: "ssh"}
	blindCode, _ := nonVerbDeadRelations(model, catalog, emptyLits)
	require.Containsf(t, deadPairNames(blindCode), codeTwin.String(),
		"источник «прод-код» не несущий: он ослеплён, а %q всё равно числится читаемым", codeTwin)

	// Источник «модель»: ослепить его подменой входа нельзя — он вычисляется из
	// той же модели, — поэтому опыт ставится с другой стороны: у отношения
	// отбирается ЕГО ЧИТАТЕЛЬ, и оно обязано стать находкой.
	//
	// Близнец здесь — указатель `account` служебной учётки: его читает РОВНО одно
	// объявление того же типа (`super_admin: admin from account`), каталог его не
	// требует, а источник «прод-код» на него не смотрит by construction — литерал,
	// равный имени типа модели, читателем не считается. То есть тишина по нему
	// может идти только от источника «модель», и опыт измеряет именно его.
	//
	// Читатель не СНИМАЕТСЯ, а ПЕРЕПИСЫВАЕТСЯ: снятие порвало бы вывод у соседей
	// (`v_get: … or super_admin`), и краснел бы разбор, а не предикат.
	modelTwin := relPair{Type: "iam_service_account", Relation: "account"}
	withoutReader := replaceDefineInType(t, canonicalDSL(t), modelTwin.Type,
		"define super_admin:", "define super_admin: [user]")
	strippedModel, err := authzplan.ParseModel(withoutReader)
	require.NoError(t, err, "переписанный читатель обязан оставлять модель разбираемой")
	blindModel, _ := nonVerbDeadRelations(strippedModel, catalog, codeLits)
	require.Containsf(t, deadPairNames(blindModel), modelTwin.String(),
		"источник «модель» не несущий: единственное объявление, читавшее %q, переписано "+
			"так, что его больше не называет, а отношение всё равно числится читаемым", modelTwin)

	// Обратный контроль: на нетронутом дереве ни один из трёх близнецов не мёртв.
	base, _ := nonVerbDeadRelations(model, catalog, codeLits)
	names := deadPairNames(base)
	for _, twin := range []relPair{catalogTwin, codeTwin, modelTwin} {
		require.NotContainsf(t, names, twin.String(),
			"близнец %q мёртв и без ослепления — опыт выше ничего не доказывает", twin)
	}
	t.Logf("опыт: несущими подтверждены 3 источника из 3; на нетронутом дереве все три близнеца немы")
}

// canonicalDSL — текст канонической модели.
func canonicalDSL(t *testing.T) string {
	t.Helper()
	_, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	return string(dsl)
}

// injectRelationIntoType вставляет объявление первой строкой блока `relations`
// указанного типа.
func injectRelationIntoType(t *testing.T, dsl, typeName, define string) string {
	t.Helper()
	at := relationsBlockStart(t, dsl, typeName)
	return dsl[:at] + "    " + define + "\n" + dsl[at:]
}

// replaceDefineInType заменяет в блоке типа объявление, начинающееся с prefix,
// на replacement. Отступ сохраняется.
func replaceDefineInType(t *testing.T, dsl, typeName, prefix, replacement string) string {
	t.Helper()
	at := relationsBlockStart(t, dsl, typeName)
	rest := dsl[at:]
	end := strings.Index(rest, "\ntype ")
	if end < 0 {
		end = len(rest)
	}
	block, tail := rest[:end], rest[end:]
	lines := strings.Split(block, "\n")
	hits := 0
	for i, ln := range lines {
		if !strings.HasPrefix(strings.TrimSpace(ln), prefix) {
			continue
		}
		hits++
		lines[i] = ln[:len(ln)-len(strings.TrimLeft(ln, " "))] + replacement
	}
	require.Equalf(t, 1, hits, "в блоке типа %q ожидалось ровно одно объявление %q, найдено %d — "+
		"опыт ставится не над тем", typeName, prefix, hits)
	return dsl[:at] + strings.Join(lines, "\n") + tail
}

// relationsBlockStart — смещение первой строки блока `relations` данного типа.
func relationsBlockStart(t *testing.T, dsl, typeName string) int {
	t.Helper()
	marker := "\ntype " + typeName + "\n"
	i := strings.Index(dsl, marker)
	require.GreaterOrEqualf(t, i, 0, "в модели нет типа %q — опыт ставится не над тем", typeName)
	j := i + len(marker)
	const rel = "  relations\n"
	k := strings.Index(dsl[j:], rel)
	require.GreaterOrEqualf(t, k, 0, "у типа %q нет блока relations", typeName)
	return j + k + len(rel)
}

// TestNonVerbReaderGate_LedgerExpiresItself — перечень исключений истекает сам.
//
// Половина смысла гейта — в том, что запись, которой больше нечего исключать,
// становится находкой. Эта половина не проверяется ни одним из опытов выше: там
// перечень совпадает с находками, и обе стороны сверки молчат по одной причине.
func TestNonVerbReaderGate_LedgerExpiresItself(t *testing.T) {
	root := monorepoRoot(t)
	catalog, _ := iamCatalogRequiredRelations(t, root)
	codeLits, _ := prodCodeStringLiterals(t, root)
	dead, _ := nonVerbDeadRelations(canonicalModel(t), catalog, codeLits)
	require.NotEmpty(t, dead, "на дереве ноль мёртвых пар — опыту не с чем сверяться")

	// Действующий перечень: расхождений нет ни в одну сторону.
	unknown, stale := diffAgainstLedger(dead, nonVerbWithoutReader)
	require.Emptyf(t, unknown, "перечень не покрывает найденное: %v", deadPairNames(unknown))
	require.Emptyf(t, stale, "перечень несёт записи без предмета: %v", deadPairNames(stale))

	// Запись без предмета — находка.
	ghost := relPair{Type: "iam_role", Relation: "viewer"}
	require.NotContainsf(t, deadPairNames(dead), ghost.String(),
		"близнец %q обязан быть ЖИВЫМ: иначе опыт про устаревшую запись ничего не измеряет", ghost)
	withGhost := map[relPair]string{ghost: "запись, которой нечего исключать"}
	for p, why := range nonVerbWithoutReader {
		withGhost[p] = why
	}
	_, stale = diffAgainstLedger(dead, withGhost)
	require.Containsf(t, deadPairNames(stale), ghost.String(),
		"перечень не истекает сам: запись %q ничего не исключает, а сверка её не назвала", ghost)

	// Находка вне перечня — тоже находка (контроль в обратную сторону).
	shortened := map[relPair]string{}
	var dropped relPair
	for p, why := range nonVerbWithoutReader {
		if dropped == (relPair{}) {
			dropped = p
			continue
		}
		shortened[p] = why
	}
	unknown, _ = diffAgainstLedger(dead, shortened)
	require.Containsf(t, deadPairNames(unknown), dropped.String(),
		"сверка не видит находку вне перечня: %q мертва и в перечне её нет", dropped)

	t.Logf("опыт: мёртвых на дереве %d; запись без предмета названа; находка вне перечня названа", len(dead))
}
