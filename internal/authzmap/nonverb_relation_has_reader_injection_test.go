// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
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

	// ОХРАНИТЕЛЬ ИМЁН ТИПОВ — не источник: он не добавляет
	// читателей, а отнимает у источника «прод-код» право засчитывать литерал,
	// равный имени типа модели. Без него `"user"`, стоящий в прод-коде сотнями
	// вхождений как ТИП СУБЪЕКТА, объявлял бы читателем любое отношение с таким
	// именем.
	//
	// Опыт ставится возвращением снятого: `iam_service_account#user` — отношение
	// «пользоваться служебной учёткой», снятое задачей #1115. Фикстура устойчива
	// именно потому, что предмет СНЯТ: снятое не возвращается само, в отличие от
	// живого отношения, которое завтра может уехать (тем и рассыпалась прежняя
	// фикстура пробы `mapClusterRelations`, привязанная к `billing_admin`).
	//
	// СТОИТ ПЕРЕД ОСЬЮ «МОДЕЛЬ» НАМЕРЕННО. Близнец той оси — указатель `account`,
	// и его имя тоже совпадает с именем типа: сняв охранитель, роняешь её первой, а
	// сообщение назовёт «источник модель не несущий» — то есть укажет не на то, что
	// сломано. Порядок здесь и есть то, что делает вердикт читаемым.
	//
	// Доказательство состоит из ДВУХ половин, и порознь ни одна ничего не значит:
	// литерал в прод-коде ЕСТЬ (иначе тишина шла бы от его отсутствия), и
	// отношение при этом ВСЁ РАВНО находка — значит разницу делает охранитель.
	guardTwin := relPair{Type: "iam_service_account", Relation: "user"}
	require.Truef(t, codeLits[guardTwin.Relation],
		"половина опыта отсутствует: литерала %q в прод-коде нет, поэтому находка ниже "+
			"объяснялась бы его отсутствием, а не охранителем имён типов", guardTwin.Relation)
	require.Truef(t, model.Type(guardTwin.Relation) != nil,
		"половина опыта отсутствует: %q не является именем ТИПА модели, поэтому охранитель "+
			"на него не смотрит и опыт измеряет не его", guardTwin.Relation)
	require.Nilf(t, model.Type(guardTwin.Type).Rel(guardTwin.Relation),
		"предпосылка опыта: %q обязано быть снято с дерева, иначе инъекция ничего не вносит", guardTwin)

	guarded := injectRelationIntoType(t, canonicalDSL(t), guardTwin.Type,
		"define "+guardTwin.Relation+": [user, service_account] or editor")
	guardedModel, err := authzplan.ParseModel(guarded)
	require.NoError(t, err, "инъекция обязана оставаться разбираемой моделью")
	guardedDead, _ := nonVerbDeadRelations(guardedModel, catalog, codeLits)
	require.Containsf(t, deadPairNames(guardedDead), guardTwin.String(),
		"охранитель имён типов не несущий: литерал %q в прод-коде есть, и отношение "+
			"засчитано читаемым — то есть источник «прод-код» объявляет читателя там, где "+
			"стоит имя ТИПА СУБЪЕКТА, а не отношения", guardTwin.Relation)

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
	t.Logf("опыт: несущими подтверждены 3 источника из 3 и охранитель имён типов "+
		"(на возвращённом %s: литерал в прод-коде есть, находка всё равно названа); "+
		"на нетронутом дереве все три близнеца немы", guardTwin)
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

// TestNonVerbReaderGate_LedgerExpiresItself — сверка с перечнем исключений
// различает ЧЕТЫРЕ состояния, и ни одно из них не требует, чтобы перечень был
// непуст.
//
// # Почему опыт СИНТЕТИЧЕСКИЙ, хотя соседние — на настоящем дереве
//
// Прежняя редакция брала входы у дерева и начиналась с `require.NotEmpty(dead)`:
// «на дереве ноль мёртвых пар — опыту не с чем сверяться». Она молча зависела от
// того, что перечень НЕПУСТ, — то есть от наличия незакрытой находки. Пока
// находки были, опыт работал; в тот день, когда последние пять были закрыты
// (#1114, #1115) и перечень опустел, опыт покраснел — на ДОСТИЖЕНИИ своей цели.
//
// Соблазн в такой ситуации — вернуть запись ради зелёного, то есть воскресить
// послабление без предмета: ровно тот класс, который этот гейт и стережёт.
// Поэтому чинится опыт, а не ведомость, и чинится он сменой входа: предмет здесь
// — КОМПАРАТОР `diffAgainstLedger`, чистая функция двух аргументов, и его
// свойства не зависят от того, что сегодня лежит в дереве.
//
// Тие к дереву при этом не потеряна и стоит первой: перечень и находки обязаны
// сходиться в обе стороны на НАСТОЯЩИХ входах — но это утверждение о равенстве,
// а не о непустоте, и на пустом дереве оно выполняется, а не ломается.
//
// # Четвёртое состояние — и честно о том, ЧТО оно закрывает
//
// Прежняя редакция проверяла три состояния: запись без предмета → находка,
// находка вне перечня → находка и — на стороне дерева — действующий перечень →
// тишина. Третье держалось на том, что в перечне лежали пять живых записей: с
// опустевшим перечнем `stale` пуст при ЛЮБОМ компараторе, и утверждение стало бы
// вакуумным. Здесь оно возвращено синтетикой и названо прямо: запись, у которой
// предмет ЕЩЁ ЕСТЬ, обязана МОЛЧАТЬ (ось A).
//
// ЧЕМ ОСЬ A ЯВЛЯЕТСЯ НА САМОМ ДЕЛЕ — намеренным дублированием, а не единственным
// сторожем. Здесь стояло «без неё сверка, объявляющая устаревшей вообще всякую
// запись, прошла бы оба оставшихся опыта». Это ОПРОВЕРГНУТО опытом, а не вычитано
// из кода: поломку `if !got[p]` → `if true` ловят ТРИ независимых утверждения —
// ось A, отрицательная половина оси B (`NotContains(stale, withSubject)`) и
// пустота `stale` в оси C. Сняв ось A, получаешь красное от B; сняв обе — красное
// от C; и только сняв все три, получаешь ЗЕЛЁНОЕ на сломанном компараторе.
//
// Брешь при опустевшем перечне закрывают, стало быть, ОТРИЦАТЕЛЬНЫЕ ПОЛОВИНЫ осей
// B и C, добавленные здесь же, — а не ось A. Ось A остаётся намеренно: она
// называет состояние прямо, и её сообщение об отказе единственное говорит про
// запись с ЖИВЫМ предметом, а не про «неожиданную устаревшую запись». Избыточность
// в проверках законна; неверный довод в комментарии У ГЕЙТА — нет: по нему
// следующий читатель либо снимет ось A, сочтя её несущей в одиночку, либо примет
// непроверенное рассуждение за проверенное.
func TestNonVerbReaderGate_LedgerExpiresItself(t *testing.T) {
	// ── сторона дерева: перечень и находки сходятся в ОБЕ стороны ──────────────
	root := monorepoRoot(t)
	catalog, catalogEntries := iamCatalogRequiredRelations(t, root)
	codeLits, filesParsed := prodCodeStringLiterals(t, root)
	require.Positive(t, catalogEntries, "каталог пуст — опыт ставится не над тем")
	require.Positive(t, filesParsed, "прод-код не разобран — опыт ставится не над тем")

	dead, _ := nonVerbDeadRelations(canonicalModel(t), catalog, codeLits)
	unknown, stale := diffAgainstLedger(dead, nonVerbWithoutReader)
	require.Emptyf(t, unknown, "перечень не покрывает найденное: %v", deadPairNames(unknown))
	require.Emptyf(t, stale, "перечень несёт записи без предмета: %v", deadPairNames(stale))

	// ── синтетика: четыре состояния компаратора, каждое отдельной осью ─────────
	//
	// Пары намеренно не существуют в модели: предмет опыта — компаратор, и вход
	// ему подаётся прямо, чтобы «краснеет» не зависело ни от одной живой находки.
	withSubject := relPair{Type: "synthetic_type_a", Relation: "synthetic_relation_a"}
	ghost := relPair{Type: "synthetic_type_b", Relation: "synthetic_relation_b"}
	unlisted := relPair{Type: "synthetic_type_c", Relation: "synthetic_relation_c"}

	model := canonicalModel(t)
	for _, p := range []relPair{withSubject, ghost, unlisted} {
		require.Nilf(t, model.Type(p.Type), "пара %q обязана быть синтетической — иначе опыт зависит от дерева", p)
	}

	// A. запись, у которой предмет ЕЩЁ ЕСТЬ, — молчит в обе стороны.
	synthDead := []relPair{withSubject}
	synthLedger := map[relPair]string{withSubject: "предмет на месте"}
	unknown, stale = diffAgainstLedger(synthDead, synthLedger)
	require.Emptyf(t, unknown, "действующая запись названа находкой вне перечня: %v", deadPairNames(unknown))
	require.Emptyf(t, stale, "действующая запись названа устаревшей: %v — сверка не различает "+
		"«предмет ещё есть» и «предмета не осталось». Ту же поломку ловят ещё два утверждения "+
		"ниже (отрицательная половина оси B и пустота stale в оси C); здесь она названа прямо",
		deadPairNames(stale))

	// B. запись, которой нечего исключать, — находка.
	unknown, stale = diffAgainstLedger(synthDead, map[relPair]string{
		withSubject: "предмет на месте",
		ghost:       "запись, которой нечего исключать",
	})
	require.Emptyf(t, unknown, "неожиданная находка вне перечня: %v", deadPairNames(unknown))
	require.Containsf(t, deadPairNames(stale), ghost.String(),
		"перечень не истекает сам: запись %q ничего не исключает, а сверка её не назвала", ghost)
	require.NotContainsf(t, deadPairNames(stale), withSubject.String(),
		"устаревшей названа и запись с предметом — сверка не различает два состояния")

	// C. находка вне перечня — тоже находка (контроль в обратную сторону).
	unknown, stale = diffAgainstLedger([]relPair{withSubject, unlisted}, synthLedger)
	require.Containsf(t, deadPairNames(unknown), unlisted.String(),
		"сверка не видит находку вне перечня: %q мертва и в перечне её нет", unlisted)
	require.NotContainsf(t, deadPairNames(unknown), withSubject.String(),
		"находкой названа и перечисленная пара — сверка не читает перечень")
	require.Emptyf(t, stale, "неожиданная устаревшая запись: %v", deadPairNames(stale))

	// D. ИДЕАЛ НЕ ЕСТЬ ПОЛОМКА: пустой перечень при нуле находок молчит.
	// Это и есть то состояние, на котором прежняя редакция краснела.
	unknown, stale = diffAgainstLedger(nil, map[relPair]string{})
	require.Emptyf(t, unknown, "пустая сверка выдумала находку: %v", deadPairNames(unknown))
	require.Emptyf(t, stale, "пустая сверка выдумала устаревшую запись: %v", deadPairNames(stale))

	t.Logf("опыт: на дереве мёртвых %d, записей перечня %d (расхождений нет ни в одну сторону); "+
		"состояний компаратора проверено 4 из 4 — действующая запись молчит, запись без предмета "+
		"названа, находка вне перечня названа, пустая сверка молчит; осмотрено записей каталога %d, "+
		"прод-файлов %d",
		len(dead), len(nonVerbWithoutReader), catalogEntries, filesParsed)
}
