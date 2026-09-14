// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_monorepo_gate_ledger_test.go — ВЕДОМОСТЬ гейтов монорепо, судивших
// службу и снятых её выносом: по каждому семейству назван исход.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ВЕДОМОСТЬ, ЕСЛИ АДЪЮДИКАЦИЯ УЖЕ БЫЛА
//
// Адъюдикация была и закрыла 52 семейства (kacho#2597, kaname#12/#15/#17). Её
// предикат искал ОДНУ форму записи пути — `"services/iam"` слэшем, — а область
// называют пятью:
//
//	"services/iam/internal/..."          слэшем
//	"services", "iam", "internal"        аргументами filepath.Join
//	"iam/cmd/kaname"                     голым сегментом, склеиваемым позже
//	github.com/PRO-Robotech/kaname/...   путём импорта модуля
//	"kaname.relation_fact"               именем схемы Postgres
//
// Форма, о которой предикат не знает, не даёт ни красного, ни зелёного — она
// МОЛЧИТ. Поэтому 18 семейств не попали НИ В ОДИН перечень: ни в перенесённые,
// ни в остаток, ни в снятые верно. Их не «решили оставить» — о них не знали.
//
// Перепись снятых носителей: 158 файлов, 70 семейств. Из них 52 адъюдицированы
// прежней волной, 18 — этой. Числа сходятся: 52 + 18 = 70.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТА ВЕДОМОСТЬ ДЕРЖИТ, А ЧТО НЕТ
//
// Держит: запись «переехал» обязана резолвиться держателем в этом дереве, а
// запись «остаётся» обязана иметь ЖИВОЙ предмет и НЕ иметь держателя. Вторая
// половина и есть самоистечение: семейство, тихо переехавшее, делает запись
// ложной, и ведомость об этом говорит вместо того, чтобы молчать.
//
// НЕ держит: правильность самого решения «переносить или снять». Это суждение,
// и машинного предиката у него нет — сказано прямо, чтобы «ведомость зелёная»
// не читалось как «остаток разобран».
package check_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// retiredOutcome — исход семейства.
type retiredOutcome string

const (
	// retiredMigrated — гейт живёт в этом дереве; holder обязан резолвиться.
	retiredMigrated retiredOutcome = "переехал"
	// retiredRemains — предмет жив здесь, держателя нет; holder обязан НЕ
	// резолвиться, иначе запись пережила свой предмет.
	retiredRemains retiredOutcome = "остаётся"
)

// retiredGateEntry — одно семейство корпуса монорепо.
type retiredGateEntry struct {
	// family — имя семейства в корпусе монорепо (internal/repohygiene).
	family string
	// outcome — исход.
	outcome retiredOutcome
	// holder — имя пробы-держателя. Для «переехал» — имя В ЭТОМ дереве; для
	// «остаётся» — каноническое имя из монорепо, которого здесь быть не должно.
	holder string
	// subject — координата предмета В ЭТОМ дереве. Пропадёт она — семейство
	// перестало быть нашим, и запись подлежит снятию, а не переносу.
	subject string
	// why — что именно держал гейт.
	why string
}

// retiredGateLedger — 18 семейств, которых не знала прежняя адъюдикация.
//
// Перечень закрыт и сверяется с числом ниже: приписать строку, не тронув число,
// нельзя.
var retiredGateLedger = []retiredGateEntry{
	{"guardnamedincomment", retiredMigrated, "TestCommentsNamingAGuardHaveItInScope",
		"internal/domain/rule_verbs.go",
		"комментарий, называющий защиту действующей, обязан иметь её в прод-коде пакета"},
	{"publishedkeyprivatehalf", retiredMigrated, "TestPublishedKeyFormCarriesNoPrivateHalf",
		"internal/domain/signing_key.go",
		"публикуемая форма подписного ключа не имеет поля для приватной половины"},
	{"relationfactsolewriter", retiredMigrated, "TestOnlyTheJournalProducesTheDirectFact",
		"internal/repo/kaname/pg/relverdict/query.go",
		"у таблицы прямого факта один производитель — триггер на журнале намерений"},

	{"bindingsubjects", retiredRemains, "TestBindingInsertAlwaysWritesItsSubjects",
		"internal/apps/kaname/api/access_binding",
		"вставка выдачи всегда записывает свои субъекты"},
	{"clientdocsexamplefields", retiredRemains, "TestClientDocsExampleCarriesEveryFieldTheTableNames",
		"docs/content",
		"пример ответа несёт ровно то множество полей, которое называет таблица страницы"},
	{"clienttokensurface", retiredRemains, "TestClientTokenEndpointIsRegisteredOnAnExternallyReachableSurface",
		"cmd/kaname",
		"эндпоинт выдачи токена зарегистрирован на внешне досягаемой поверхности"},
	{"clusterrelationproducer", retiredRemains, "TestClusterRelationProducerGate_DumpFormsStillMissWhatIsAbsent",
		"internal/apps/kaname/seed/embedded/permission_catalog.json",
		"запись каталога с кластерной областью называет отношение, которое кто-то производит"},
	{"fgaoutboxrowowner", retiredRemains, "TestFGAOutboxRowOwnerGate_CatchesASecondRenderer",
		"internal/repo/kaname/pg/fga_outbox",
		"строки журнала намерений рисует только их владелец"},
	{"integrityraisenamesitsconstraint", retiredRemains, "TestIntegrityRaiseGateFallsAndStaysSilentOnItsTwin",
		"internal/repo/kaname/pg/pgmaperr.go",
		"отказ класса целостности, поднятый миграцией, называет связь"},
	{"keystrengththreshold", retiredRemains, "TestKeyStrengthFloorIsDeclaredExactlyOnce",
		"internal/signingkeygen",
		"нижний порог стойкости ключа объявлен числом и ровно в одном месте"},
	{"labelverdictaxis", retiredRemains, "TestEveryLabelSelectableTypeHasAVerdictAxis",
		"internal/repo/kaname/pg/relverdict",
		"у каждого типа, отбираемого меткой, есть ось вердикта"},
	// Тонкость, которую легко принять за перенос: в дереве ЕСТЬ
	// `internal/apps/kaname/api/account/list_scan_observability_test.go` с
	// пробами TestListScan_*. Это ПОВЕДЕНЧЕСКИЕ пробы одного вызывающего, а
	// снятый гейт судил СВОЙСТВО ДЕРЕВА — «всякий цикл добора снимает свою
	// стоимость». Совпадение имени файла переносом не является: новый цикл,
	// заведённый в другом пакете, поведенческими пробами не покрывается.
	{"listscanobservability", retiredRemains, "TestRefillLoopReportsItsScan",
		"internal/apps/kaname/api/access_binding/list.go",
		"цикл добора страницы снимает стоимость этого добора — свойство ДЕРЕВА, а не одного вызывающего"},
	{"manifestkeydenial", retiredRemains, "TestAcceptanceDoesNotDenyALiveManifestKey",
		"internal/manifest",
		"приёмка не объявляет несуществующим ключ, который манифест несёт"},
	{"moduleserviceaccounthasacomponent", retiredRemains, "TestModuleSAGateDerivesComponentsFromTheTreeInBothDirections",
		"internal/migrations",
		"у служебной учётки модуля есть компонент, и перечень выводится из дерева"},
	{"quotaconsoleowners", retiredRemains, "TestQCO_CatalogueAliasIsHonouredNotGuessed",
		"internal/domain/limit.go",
		"владельцы видов величин берутся каталогом, а не угадываются"},
	{"roleverbstructuralfatal", retiredRemains, "TestIAMRV108_BootAbortsOnTheStructuralBand",
		"internal/apps/kaname/api/access_binding/structural_gates.go",
		"старт отказывает на структурной полосе, а не продолжается с предупреждением"},
	{"verdictenumeration", retiredRemains, "TestG6RedOnACommaJoinedRead",
		"internal/repo/kaname/pg/relverdict",
		"путь вердикта не читает ничего неограниченного"},
	{"verdictscopeform", retiredRemains, "TestVerdictScopeFormGateRedsOnADivergedStep",
		"internal/repo/kaname/pg/relverdict",
		"форма области вердикта одна и та же на каждой точке входа"},
}

// retiredLedgerFamilies — сколько семейств ведомость обязана нести.
//
// Число объявлено ОТДЕЛЬНО от перечня намеренно: приписать строку, не тронув
// число, нельзя, и наоборот. Два места об одном предмете здесь заведены
// сознательно — как храповик, а не как дубль.
const retiredLedgerFamilies = 18

// retiredCorpusFiles — снятых носителей гейтов в корпусе монорепо.
// Предикат (в дереве платформы, на коммите выноса 0cc1cd54c3):
//
//	git diff --name-status 0cc1cd54c3^..0cc1cd54c3 -- internal/repohygiene/ |
//	  awk '$1=="D"' | wc -l
const retiredCorpusFiles = 158

// retiredCorpusFamilies — семейств среди них (носители сводятся по имени без
// суффиксов _test/_injection_test/_boundary_test).
const retiredCorpusFamilies = 70

// retiredAdjudicatedEarlier — адъюдицировано прежней волной (kacho#2597).
const retiredAdjudicatedEarlier = 52

// retiredLedgerFindings — вердикт ведомости по собранным фактам.
//
// Вынесено функцией, а не оставлено в теле пробы: инъекция обязана проверять
// ТОТ ЖЕ предикат, которым судит гейт. Предикат, переписанный на стороне
// инъекции, доказывал бы свойство копии.
//
// stale — запись «остаётся», чей держатель в дереве УЖЕ есть (самоистечение);
// missing — запись, чей держатель либо предмет не резолвится.
func retiredLedgerFindings(
	entries []retiredGateEntry,
	declared map[string]bool,
	subjectExists func(rel string) bool,
) (stale, missing []string) {
	for _, e := range entries {
		switch e.outcome {
		case retiredMigrated:
			if !declared[e.holder] {
				missing = append(missing, e.family+": держатель "+e.holder+" не объявлен ни одним файлом")
			}
		case retiredRemains:
			if declared[e.holder] {
				stale = append(stale, e.family+": держатель "+e.holder+" В ДЕРЕВЕ ЕСТЬ")
			}
		}
		// Предмет обязан быть жив: пропал — семейство перестало быть нашим, и
		// запись подлежит снятию вместе с ним, а не переносу.
		if !subjectExists(e.subject) {
			missing = append(missing, e.family+": предмет "+e.subject+" не найден в дереве")
		}
	}
	sort.Strings(stale)
	sort.Strings(missing)
	return stale, missing
}

// TestRetiredMonorepoGateLedgerHoldsItsEntries — сама ведомость.
func TestRetiredMonorepoGateLedgerHoldsItsEntries(t *testing.T) {
	t.Parallel()

	if len(retiredGateLedger) != retiredLedgerFamilies {
		t.Fatalf("ведомость несёт %d записей при объявленных %d — храповик разошёлся: "+
			"строку приписали, не тронув число, либо наоборот",
			len(retiredGateLedger), retiredLedgerFamilies)
	}
	// Числа корпуса обязаны сходиться: адъюдицированное прежней волной плюс эта
	// ведомость — весь корпус. Разойдутся — значит найдено ещё одно семейство,
	// и его исход не назван нигде.
	if retiredAdjudicatedEarlier+retiredLedgerFamilies != retiredCorpusFamilies {
		t.Fatalf("перепись корпуса не сходится: %d адъюдицировано прежде + %d здесь = %d, "+
			"а семейств в корпусе %d — разница есть семейства, чей исход не назван НИГДЕ",
			retiredAdjudicatedEarlier, retiredLedgerFamilies,
			retiredAdjudicatedEarlier+retiredLedgerFamilies, retiredCorpusFamilies)
	}

	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	declared := map[string]bool{}
	var parsed, decls, tests int
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		names, census, serr := check.ScanDeclaredFuncNames(rel, src)
		if serr != nil {
			continue
		}
		parsed++
		decls += census.Decls
		tests += census.Tests
		for n := range names {
			declared[n] = true
		}
	}

	migrated, remains := 0, 0
	for _, e := range retiredGateLedger {
		switch e.outcome {
		case retiredMigrated:
			migrated++
		case retiredRemains:
			remains++
		}
	}

	// ОБЕ величины печатаются рядом: «ноль потерянных» обязано быть отличимо от
	// «ноль проверенных».
	t.Logf("перепись корпуса: снятых носителей %d, семейств %d; адъюдицировано прежней "+
		"волной %d, этой ведомостью %d (переехало %d, остаётся %d)",
		retiredCorpusFiles, retiredCorpusFamilies, retiredAdjudicatedEarlier,
		len(retiredGateLedger), migrated, remains)
	t.Logf("перепись дерева: файлов Go разобрано %d, объявлений функций прочитано %d, "+
		"из них объявлений проб %d", parsed, decls, tests)

	if parsed == 0 || decls == 0 {
		t.Fatalf("разобрано файлов %d, объявлений %d — обход пуст, и вердикт ведомости "+
			"беспредметен", parsed, decls)
	}
	if tests == 0 {
		t.Fatalf("объявлений проб прочитано ноль на %d файлах — разбор перестал видеть "+
			"держателей, и его молчание сказано ни о чём", parsed)
	}

	stale, missing := retiredLedgerFindings(retiredGateLedger, declared, func(rel string) bool {
		_, serr := os.Stat(filepath.Join(ownDir, filepath.FromSlash(rel)))
		return serr == nil
	})

	for _, s := range stale {
		t.Errorf("ведомость пережила свой предмет — %s.\nЗапись объявляет семейство "+
			"НЕПЕРЕНЕСЁННЫМ, а держатель в дереве уже есть: значит гейт переехал, и строку "+
			"надо перевести в «переехал», назвав координату. Оставленная запись описывает "+
			"вчерашнее дерево и удерживает работу, которой нет", s)
	}
	for _, m := range missing {
		t.Errorf("запись ведомости не резолвится — %s.\nИсходы: держатель переименован "+
			"(правьте имя) · предмет уехал или снят (снимайте запись вместе с ним) · "+
			"координата названа неверно", m)
	}
}
