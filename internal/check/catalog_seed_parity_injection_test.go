// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// catalog_seed_parity_injection_test.go — ДОКАЗАТЕЛЬСТВО способности обоих
// гейтов каталога упасть, инъекцией НАСТОЯЩИМ входом и с законным близнецом.
//
// # Почему на синтетическом входе, а не на дереве
//
// Инъекция обязана ронять ТОЛЬКО проверяемое. Вернуть дефект в саму миграцию
// нельзя: применённую не правят (запрет #5), а вход у ядра — текст, поэтому ядро
// отделено от корня дерева и здесь получает текст, собранный пробой.
//
// # Прогонов по каждой оси ТРИ, а не два
//
// Контроль (всё цело — молчат обе проверки) · инъекция нового свойства (краснеет
// только оно) · законный близнец той же ФОРМЫ (молчит). Без третьего гейт ловил
// бы форму, а не существо, и первый же ложный срабат его отключил бы.

import (
	"strings"
	"testing"
)

// goodSeed — синтетический посев, согласный со своим синтетическим литералом.
const goodSeed = `
INSERT INTO kaname.catalog_module (module) VALUES
  ('alpha'),
  ('beta');

INSERT INTO kaname.catalog_resource (module, resource, dotted) VALUES
  ('alpha', 'thing', 'alpha.thing'),
  ('beta', 'other', 'beta.other');

INSERT INTO kaname.catalog_resource
  (module, resource, dotted, retired_at, retired_reason, superseded_by, live) VALUES
  ('alpha', 'old', 'alpha.old', now(),
   'снято; причина, содержащая запятую', 'beta.other', false);

INSERT INTO kaname.catalog_verb (module, resource, verb) VALUES
  ('alpha', 'thing', 'get'),
  ('beta', 'other', 'list');
`

var (
	wantMods  = []string{"alpha", "beta"}
	wantRes   = []string{"alpha.thing", "beta.other"}
	wantVerbs = []string{"alpha.thing.get", "beta.other.list"}
)

func TestIAMCT114_Injection_ControlIsSilent(t *testing.T) {
	c, findings, err := auditCatalogSeed(oneMigration(goodSeed), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("контроль обязан разбираться: %v", err)
	}
	t.Logf("прочитано строк — модуля %d, ресурса %d, глагола %d; "+
		"классифицировано — модулей %d, ресурсов %d, глаголов %d, снятых %d",
		c.ReadModuleRows, c.ReadResourceRows, c.ReadVerbRows,
		c.SeededModules, c.SeededResources, c.SeededVerbs, c.RetiredSeeded)
	if len(findings) != 0 {
		t.Fatalf("контроль обязан молчать, найдено: %v", findings)
	}
	if c.RetiredSeeded != 1 {
		t.Fatalf("снятая строка обязана быть прочитана целиком, хотя несёт now() "+
			"и запятую внутри кавычек; прочитано %d", c.RetiredSeeded)
	}
}

func TestIAMCT114_Injection_RowMissingFromSeedIsFound(t *testing.T) {
	_, findings, err := auditCatalogSeed(oneMigration(goodSeed), wantMods,
		append(append([]string{}, wantRes...), "alpha.extra"), wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "alpha.extra") || !containsSub(findings, "не посеян миграцией") {
		t.Fatalf("строка литерала без посева обязана быть находкой; получено: %v", findings)
	}
}

func TestIAMCT114_Injection_RowBeyondTheLiteralIsFound(t *testing.T) {
	_, findings, err := auditCatalogSeed(oneMigration(goodSeed), wantMods,
		[]string{"alpha.thing"}, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "beta.other") || !containsSub(findings, "нет в литерале") {
		t.Fatalf("посев сверх литерала обязан быть находкой — иначе сравнение одностороннее; "+
			"получено: %v", findings)
	}
}

func TestIAMCT114_Injection_DottedFormOutOfStepIsFound(t *testing.T) {
	bad := strings.Replace(goodSeed,
		"('beta', 'other', 'beta.other')", "('beta', 'other', 'beta.others')", 1)
	_, findings, err := auditCatalogSeed(oneMigration(bad), wantMods,
		[]string{"alpha.thing", "beta.others"}, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "не выводится из пары") {
		t.Fatalf("третье написание обязано быть находкой даже когда литерал с ним согласен: "+
			"именно так класс 513001 и проходит незамеченным; получено: %v", findings)
	}
}

func TestIAMCT114_Injection_SuccessorPointingAtNothingIsFound(t *testing.T) {
	bad := strings.Replace(goodSeed, "'beta.other', false", "'beta.gone', false", 1)
	_, findings, err := auditCatalogSeed(oneMigration(bad), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "не является живым ключом каталога") {
		t.Fatalf("преемник, указывающий на несуществующее, обязан быть находкой — "+
			"он восстанавливает клиенту шаг, которого нет; получено: %v", findings)
	}
}

func TestIAMCT114_Injection_EmptySeedIsNotSilence(t *testing.T) {
	empty := strings.Replace(goodSeed,
		"INSERT INTO kaname.catalog_verb (module, resource, verb) VALUES\n  ('alpha', 'thing', 'get'),\n  ('beta', 'other', 'list');",
		"INSERT INTO kaname.catalog_verb (module, resource, verb) VALUES\n-- посева нет", 1)
	_, _, err := auditCatalogSeed(oneMigration(empty), wantMods, wantRes, wantVerbs)
	if err == nil {
		t.Fatal("пустой обход обязан быть ОТКАЗОМ, а не «расхождений нет»: " +
			"иначе «ноль находок» неотличимо от «ноль прочитанного»")
	}
}

// ── форма ключа ───────────────────────────────────────────────────────────────

const goodKeys = `
ALTER TABLE kaname.role_rule_ref
  ADD CONSTRAINT role_rule_ref_res_fk
  FOREIGN KEY (module, resource, live)
  REFERENCES kaname.catalog_resource (module, resource, live)
  ON DELETE NO ACTION ON UPDATE NO ACTION
  DEFERRABLE INITIALLY IMMEDIATE;

ALTER TABLE kaname.other_table
  ADD CONSTRAINT other_fk
  FOREIGN KEY (x) REFERENCES kaname.parent (x)
  DEFERRABLE INITIALLY DEFERRED;
`

func TestIAMCT113_Injection_ControlIsSilent(t *testing.T) {
	scanned, findings := auditKeyForm(goodKeys, []string{"role_rule_ref_res_fk"}, nil)
	t.Logf("осмотрено объявлений: %d", scanned)
	if scanned == 0 {
		t.Fatal("обход пуст — вердикт беспредметен")
	}
	if len(findings) != 0 {
		t.Fatalf("законный близнец обязан молчать: отложенность по умолчанию на ЧУЖОМ ключе "+
			"законна и остаётся; найдено: %v", findings)
	}
}

func TestIAMCT113_Injection_RestrictBesideDeferrableIsFound(t *testing.T) {
	bad := strings.Replace(goodKeys, "ON DELETE NO ACTION", "ON DELETE RESTRICT", 1)
	_, findings := auditKeyForm(bad, []string{"role_rule_ref_res_fk"}, nil)
	if !containsSub(findings, "RESTRICT рядом с DEFERRABLE") {
		t.Fatalf("форма, принимаемая DDL и молча инертная, обязана быть находкой; получено: %v",
			findings)
	}
}

func TestIAMCT113_Injection_DeferredOnTheNamedKeyIsFound(t *testing.T) {
	bad := strings.Replace(goodKeys, "DEFERRABLE INITIALLY IMMEDIATE", "DEFERRABLE INITIALLY DEFERRED", 1)
	_, findings := auditKeyForm(bad, []string{"role_rule_ref_res_fk"}, nil)
	if !containsSub(findings, "role_rule_ref_res_fk") {
		t.Fatalf("смена формы названного ключа обязана быть находкой: она снимает «Тогда» "+
			"у трёх сценариев отказа; получено: %v", findings)
	}
}

func TestIAMCT113_Injection_CommentAboutRestrictIsNotAKey(t *testing.T) {
	withProse := strings.Replace(goodKeys, "  ON DELETE NO ACTION ON UPDATE NO ACTION",
		"  -- RESTRICT здесь запрещён: форма DEFERRABLE молча инертна\n"+
			"  ON DELETE NO ACTION ON UPDATE NO ACTION", 1)
	_, findings := auditKeyForm(withProse, []string{"role_rule_ref_res_fk"}, nil)
	if len(findings) != 0 {
		t.Fatalf("гейт обязан судить ИСПОЛНЯЕМОЕ: иначе он краснеет на собственном "+
			"объяснении; найдено: %v", findings)
	}
}

func containsSub(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

// ── ярусная половина словаря (задача продукта #1863) ──────────────────────────
//
// Осей четыре, и по каждой прогон в ОБЕ стороны: контроль молчит, инъекция
// краснеет. Четвёртая ось — своя у этого гейта и без неё он был бы вдвое слабее
// сверки множеств: признак словаря стоит ЗНАЧЕНИЕМ, и кортеж с `true` прошёл бы
// сверку троек, означая ровно обратное тому, ради чего строка заведена.

// goodTierOnlySeed — синтетический ярусный посев, согласный со своим литералом.
const goodTierOnlySeed = `
INSERT INTO kaname.catalog_verb (module, resource, verb, per_object) VALUES
  ('alpha', 'thing', 'create', false),
  ('beta', 'other', 'create', false);
`

var wantTierOnly = []string{"alpha.thing.create", "beta.other.create"}

func TestTierOnly_Injection_ControlIsSilent(t *testing.T) {
	seeded, findings, err := auditTierOnlyVerbSeed(oneMigration(goodTierOnlySeed), wantTierOnly)
	if err != nil {
		t.Fatalf("контроль обязан разбираться: %v", err)
	}
	t.Logf("осмотрено ярусных пар: %d", seeded)
	if seeded != len(wantTierOnly) {
		t.Fatalf("контроль обязан прочитать все пары; прочитано %d из %d", seeded, len(wantTierOnly))
	}
	if len(findings) != 0 {
		t.Fatalf("контроль обязан молчать, найдено: %v", findings)
	}
}

func TestTierOnly_Injection_RowMissingFromSeedIsFound(t *testing.T) {
	_, findings, err := auditTierOnlyVerbSeed(oneMigration(goodTierOnlySeed), append(append([]string{}, wantTierOnly...), "gamma.third.create"))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "gamma.third.create") || !containsSub(findings, "не посеян миграцией") {
		t.Fatalf("ресурс, которому литерал даёт ярусный глагол, а миграция нет, обязан быть "+
			"находкой: правило роли на нём продолжает отвергаться ключом; получено: %v", findings)
	}
}

func TestTierOnly_Injection_RowBeyondTheLiteralIsFound(t *testing.T) {
	_, findings, err := auditTierOnlyVerbSeed(oneMigration(goodTierOnlySeed), []string{"alpha.thing.create"})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "beta.other.create") || !containsSub(findings, "нет в литерале") {
		t.Fatalf("посев сверх литерала обязан быть находкой — ключ пропускал бы глагол, "+
			"о котором производитель не знает; получено: %v", findings)
	}
}

// TestTierOnly_Injection_PerObjectFlagIsTheSubject — ЧЕТВЁРТАЯ ось.
//
// Тройка та же, множества сходятся — и строка при этом означает противоположное:
// пообъектная строка `create` возвращает материализацию отношения, снятого с 23
// типов осознанно. Сверка множеств этого не видит by construction.
func TestTierOnly_Injection_PerObjectFlagIsTheSubject(t *testing.T) {
	bad := strings.Replace(goodTierOnlySeed,
		"('beta', 'other', 'create', false)", "('beta', 'other', 'create', true)", 1)
	_, findings, err := auditTierOnlyVerbSeed(oneMigration(bad), wantTierOnly)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "признак словаря") {
		t.Fatalf("кортеж с пообъектным признаком обязан быть находкой: тройка та же, "+
			"смысл обратный; получено: %v", findings)
	}
}

// TestTierOnly_Injection_LegitimateTwinIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ той же формы.
//
// Без него гейт ловил бы форму, а не существо: четырёхпольный кортеж с `false` —
// нормальная строка ярусной половины, и на ней гейт обязан молчать, каким бы ни
// был её модуль.
func TestTierOnly_Injection_LegitimateTwinIsSilent(t *testing.T) {
	twin := strings.Replace(goodTierOnlySeed,
		"('beta', 'other', 'create', false)", "('gamma', 'third', 'create', false)", 1)
	_, findings, err := auditTierOnlyVerbSeed(oneMigration(twin), []string{"alpha.thing.create", "gamma.third.create"})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("законный близнец обязан молчать, найдено: %v", findings)
	}
}

func TestTierOnly_Injection_EmptySeedIsNotSilence(t *testing.T) {
	empty := "INSERT INTO kaname.catalog_verb (module, resource, verb, per_object) VALUES\n-- посева нет\n"
	_, _, err := auditTierOnlyVerbSeed(oneMigration(empty), wantTierOnly)
	if err == nil {
		t.Fatal("пустой обход обязан быть ОТКАЗОМ, а не «расхождений нет»: " +
			"иначе «ноль находок» неотличимо от «ноль прочитанного»")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ВТОРАЯ ФОРМА ЗАПИСИ ПОСЕВА — форма дампа (свод 171 миграции в одну первичную)
//
// Распознаватель обязан знать ВСЕ законные формы записи предмета, и по КАЖДОЙ
// прогон в обе стороны. Форма, о которой он не знает, не даёт ни красного, ни
// зелёного — она молчит; именно это и произошло со сводом: четыре литеральных
// префикса прежней редакции дали ноль попаданий, и гейт краснел «оператор посева
// не найден» вместо того, чтобы сверять.
//
// Ниже — ТА ЖЕ синтетика, что в `goodSeed` выше, записанная как её печатает
// `pg_dump --column-inserts`: по оператору на строку, все колонки, готовые
// значения, дискриминаторы (`live`, `per_object`) значением, а не умолчанием.

const goodSeedDumpForm = `
INSERT INTO kaname.catalog_module (module, retired_at, retired_reason, live) VALUES ('alpha', NULL, NULL, true);
INSERT INTO kaname.catalog_module (module, retired_at, retired_reason, live) VALUES ('beta', NULL, NULL, true);
INSERT INTO kaname.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('alpha', 'thing', 'alpha.thing', NULL, NULL, NULL, true, 'alpha_thing');
INSERT INTO kaname.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('beta', 'other', 'beta.other', NULL, NULL, NULL, true, 'beta_other');
INSERT INTO kaname.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('alpha', 'old', 'alpha.old', now(), 'снято; причина, содержащая запятую, точку с запятой и (скобки)', 'beta.other', false, 'alpha_old');
INSERT INTO kaname.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('alpha', 'thing', 'get', NULL, NULL, true, true);
INSERT INTO kaname.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('beta', 'other', 'list', NULL, NULL, true, true);
INSERT INTO kaname.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('alpha', 'thing', 'create', NULL, NULL, true, false);
INSERT INTO kaname.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('beta', 'other', 'create', NULL, NULL, true, false);
`

// TestIAMCT114_Injection_DumpForm_ControlIsSilent — КОНТРОЛЬ второй формы.
//
// Он же — доказательство, что дискриминаторы читаются ЗНАЧЕНИЕМ: в этом теле
// живые и снятая строка ресурса лежат в ОДНОМ операторе с одним перечнем
// колонок, а пообъектная и ярусная половины словаря — в одной таблице. Прежняя
// редакция различала их текстом оператора и здесь не различила бы вовсе.
func TestIAMCT114_Injection_DumpForm_ControlIsSilent(t *testing.T) {
	c, findings, err := auditCatalogSeed(oneMigration(goodSeedDumpForm), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("контроль второй формы обязан разбираться: %v", err)
	}
	t.Logf("прочитано строк — модуля %d, ресурса %d, глагола %d; "+
		"классифицировано — модулей %d, живых ресурсов %d, снятых %d, пообъектных глаголов %d",
		c.ReadModuleRows, c.ReadResourceRows, c.ReadVerbRows,
		c.SeededModules, c.SeededResources, c.RetiredSeeded, c.SeededVerbs)
	if len(findings) != 0 {
		t.Fatalf("контроль обязан молчать, найдено: %v", findings)
	}
	// Перепись обязана показать, что ЧИТАЛОСЬ больше, чем классифицировано в
	// пообъектную половину: иначе «ярусные строки не попали в сверку» было бы
	// неотличимо от «их не прочитали».
	if c.ReadVerbRows != 4 || c.SeededVerbs != 2 {
		t.Fatalf("строк глагола прочитано %d (ожидалось 4), пообъектных классифицировано %d "+
			"(ожидалось 2): ярусные строки обязаны быть ПРОЧИТАНЫ и не попасть в пообъектную "+
			"половину", c.ReadVerbRows, c.SeededVerbs)
	}
	if c.ReadResourceRows != 3 || c.SeededResources != 2 || c.RetiredSeeded != 1 {
		t.Fatalf("строк ресурса прочитано %d/3, живых %d/2, снятых %d/1: снятие различается "+
			"значением live, а не отдельным оператором",
			c.ReadResourceRows, c.SeededResources, c.RetiredSeeded)
	}
}

// TestIAMCT114_Injection_DumpForm_RowBeyondTheLiteralIsFound — вторая сторона по
// той же оси: дефект, внесённый ВО ВТОРУЮ форму, обязан находиться.
//
// Инъекция снимает у ярусной строки признак словаря — тройка при этом остаётся
// той же, а строка становится пообъектной и сверх литерала.
func TestIAMCT114_Injection_DumpForm_RowBeyondTheLiteralIsFound(t *testing.T) {
	bad := strings.Replace(goodSeedDumpForm,
		"VALUES ('alpha', 'thing', 'create', NULL, NULL, true, false)",
		"VALUES ('alpha', 'thing', 'create', NULL, NULL, true, true)", 1)
	_, findings, err := auditCatalogSeed(oneMigration(bad), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "alpha.thing.create") || !containsSub(findings, "нет в литерале") {
		t.Fatalf("строка, ставшая пообъектной, обязана быть находкой пообъектной половины; "+
			"получено: %v", findings)
	}
}

// TestIAMCT114_Injection_DumpForm_RetiredRowIsNotALiveKey — ЗАКОННЫЙ БЛИЗНЕЦ той
// же формы: снятая строка не засчитывается живой.
//
// Без этой пробы разбор, игнорирующий `live`, прошёл бы контроль выше только
// потому, что литерал случайно совпал бы с полным набором строк.
func TestIAMCT114_Injection_DumpForm_RetiredRowIsNotALiveKey(t *testing.T) {
	// Литерал НЕ содержит `alpha.old` — и не должен: строка снята. Разбор,
	// считающий её живой, назовёт её посеянной сверх литерала.
	_, findings, err := auditCatalogSeed(oneMigration(goodSeedDumpForm), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if containsSub(findings, "alpha.old") {
		t.Fatalf("снятая строка живым ключом каталога не является и в сверку живых не входит; "+
			"получено: %v", findings)
	}
	// Обратная сторона: оживи ту же строку — и она обязана стать находкой.
	revived := strings.Replace(goodSeedDumpForm,
		"'beta.other', false, 'alpha_old'", "NULL, true, 'alpha_old'", 1)
	_, findings, err = auditCatalogSeed(oneMigration(revived), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "alpha.old") || !containsSub(findings, "нет в литерале") {
		t.Fatalf("та же строка, объявленная живой, обязана быть находкой — иначе фильтр по live "+
			"не проверен ни в одну сторону; получено: %v", findings)
	}
}

// TestIAMCT114_Injection_DumpForm_ProseWithSemicolonsIsOneRow — граница разбора.
//
// Причина снятия — русская проза, и она содержит точку с запятой, запятую и
// скобки. Разбор, режущий по этим знакам наивно, прочитал бы одну строку как
// несколько и объявил бы кортеж не сходящимся с перечнем колонок — то есть
// находка была бы о разборе, а не о дереве.
func TestIAMCT114_Injection_DumpForm_ProseWithSemicolonsIsOneRow(t *testing.T) {
	rows, err := parseInsertRows(goodSeedDumpForm, "kaname.catalog_resource")
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("строк ресурса обязано быть 3, прочитано %d", len(rows))
	}
	var retired insertRow
	for _, r := range rows {
		if r.get("dotted") == "alpha.old" {
			retired = r
		}
	}
	if got := retired.get("retired_reason"); !strings.Contains(got, "точку с запятой") ||
		!strings.Contains(got, "(скобки)") {
		t.Fatalf("причина снятия прочитана усечённо: %q", got)
	}
	if len(retired.vals) != len(retired.cols) {
		t.Fatalf("кортеж %d значений при %d колонках — проза разрезала строку",
			len(retired.vals), len(retired.cols))
	}
}

// TestIAMCT114_Injection_ArityMismatchIsFound — кортеж, не сходящийся с перечнем
// колонок СВОЕГО оператора.
//
// Прежняя редакция сверяла длину с числом («три поля»), верным ровно для той
// формы, под которую писалась. Сверка с перечнем верна для обеих.
func TestIAMCT114_Injection_ArityMismatchIsFound(t *testing.T) {
	bad := strings.Replace(goodSeedDumpForm,
		"VALUES ('beta', 'other', 'beta.other', NULL, NULL, NULL, true, 'beta_other')",
		"VALUES ('beta', 'other', 'beta.other', NULL, NULL, NULL, true)", 1)
	_, findings, err := auditCatalogSeed(oneMigration(bad), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "при 8 названных колонках") {
		t.Fatalf("кортеж короче перечня колонок обязан быть находкой, называющей ОБА числа; "+
			"получено: %v", findings)
	}
}

// TestIAMCT114_Injection_TableNameBoundaryIsRespected — СВОЙСТВО: строка
// соседней таблицы, чьё имя продолжает искомое, в обход не попадает.
//
// Иначе `catalog_verb` набрал бы строк `catalog_verb_history`, и находка была бы
// о таблице, которой гейт не касается.
//
// # Что эта проба доказывает, а что нет
//
// Свойство держит не отдельная проверка границы имени, а требование перечня
// колонок сразу за именем: `_history (` пробелом не является и скобкой тоже, так
// что оператор не читается. Явная проверка границы здесь СТОЯЛА и снята — её
// снятие не меняло исхода ни на одном входе, включая этот, то есть она была
// мёртвой ветвью, документирующей чужой контракт. Проба остаётся: она запирает
// свойство на случай, если разбор станут делать терпимее (например, искать
// ближайшую скобку где угодно после имени).
func TestIAMCT114_Injection_TableNameBoundaryIsRespected(t *testing.T) {
	withNeighbour := goodSeedDumpForm +
		"INSERT INTO kaname.catalog_verb_history (module, resource, verb, live, per_object) " +
		"VALUES ('gamma', 'third', 'get', true, true);\n"
	c, findings, err := auditCatalogSeed(oneMigration(withNeighbour), wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if c.ReadVerbRows != 4 {
		t.Fatalf("строк глагола прочитано %d: строка соседней таблицы с тем же началом имени "+
			"попала в обход", c.ReadVerbRows)
	}
	if len(findings) != 0 {
		t.Fatalf("контроль обязан молчать: %v", findings)
	}
}

// ── ярусная половина во ВТОРОЙ форме ─────────────────────────────────────────

func TestTierOnly_Injection_DumpForm_ControlIsSilent(t *testing.T) {
	seeded, findings, err := auditTierOnlyVerbSeed(oneMigration(goodSeedDumpForm), wantTierOnly)
	if err != nil {
		t.Fatalf("контроль второй формы обязан разбираться: %v", err)
	}
	t.Logf("осмотрено ярусных пар: %d (из таблицы, где лежат обе половины)", seeded)
	if seeded != len(wantTierOnly) {
		t.Fatalf("прочитано %d ярусных пар из %d", seeded, len(wantTierOnly))
	}
	if len(findings) != 0 {
		t.Fatalf("контроль обязан молчать, найдено: %v", findings)
	}
}

// TestTierOnly_Injection_DumpForm_PerObjectRowsAreNotFindings — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// В одной таблице с ярусной половиной лежат пообъектные строки, и их признак
// словаря — `true` ЗАКОННО. Требование `false` от всякой прочитанной строки (так
// было, пока половины сеяли разные миграции) объявило бы находкой каждую из них.
func TestTierOnly_Injection_DumpForm_PerObjectRowsAreNotFindings(t *testing.T) {
	_, findings, err := auditTierOnlyVerbSeed(oneMigration(goodSeedDumpForm), wantTierOnly)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if containsSub(findings, "alpha.thing.get") || containsSub(findings, "beta.other.list") {
		t.Fatalf("пообъектная строка соседней половины находкой ярусного гейта не является; "+
			"получено: %v", findings)
	}
}

// TestTierOnly_Injection_DumpForm_PerObjectFlagIsTheSubject — та же ЧЕТВЁРТАЯ
// ось во второй форме: тройка названа литералом ярусной, а посеяна пообъектной.
func TestTierOnly_Injection_DumpForm_PerObjectFlagIsTheSubject(t *testing.T) {
	bad := strings.Replace(goodSeedDumpForm,
		"VALUES ('beta', 'other', 'create', NULL, NULL, true, false)",
		"VALUES ('beta', 'other', 'create', NULL, NULL, true, true)", 1)
	_, findings, err := auditTierOnlyVerbSeed(oneMigration(bad), wantTierOnly)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "признак словаря") {
		t.Fatalf("кортеж с пообъектным признаком у тройки, названной литералом ярусной, "+
			"обязан быть находкой: тройка та же, смысл обратный; получено: %v", findings)
	}
}

// ── ведомость послаблений на форму ключа ─────────────────────────────────────
//
// Осей три, и все три обязательны: прощённый ключ молчит · непрощённый той же
// формы краснеет · запись, которой нечего исключать, краснеет сама.

const keysWithLegacyCycle = `
ALTER TABLE ONLY kaname.accounts
    ADD CONSTRAINT accounts_owner_fk FOREIGN KEY (owner_user_id) REFERENCES kaname.users(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY kaname.role_rule_ref
    ADD CONSTRAINT role_rule_ref_res_fk FOREIGN KEY (module, resource, live) REFERENCES kaname.catalog_resource(module, resource, live) DEFERRABLE;
`

func TestIAMCT113_Injection_ExemptKeyIsSilent(t *testing.T) {
	scanned, findings := auditKeyForm(keysWithLegacyCycle,
		[]string{"role_rule_ref_res_fk"}, []string{"accounts_owner_fk"})
	t.Logf("осмотрено объявлений: %d; прощено: 1", scanned)
	if scanned != 2 {
		t.Fatalf("объявлений обязано быть прочитано 2, прочитано %d", scanned)
	}
	if len(findings) != 0 {
		t.Fatalf("поимённо прощённый ключ обязан молчать: %v", findings)
	}
}

// TestIAMCT113_Injection_UnexemptKeyOfTheSameFormIsFound — ЗАКОННЫЙ БЛИЗНЕЦ
// наоборот: та же форма у ключа, которого в ведомости нет, остаётся находкой.
// Без этой оси ведомость была бы не послаблением, а снятием запрета.
func TestIAMCT113_Injection_UnexemptKeyOfTheSameFormIsFound(t *testing.T) {
	_, findings := auditKeyForm(keysWithLegacyCycle,
		[]string{"role_rule_ref_res_fk"}, nil)
	if !containsSub(findings, "RESTRICT рядом с DEFERRABLE") {
		t.Fatalf("та же форма у непрощённого ключа обязана быть находкой; получено: %v", findings)
	}
}

// TestIAMCT113_Injection_ExemptionWithoutASubjectIsFound — САМОИСТЕЧЕНИЕ.
//
// Запись, у которой в теле нет предмета, — находка. Без этого ведомость пережила
// бы снятие ключа и осталась бы слепой зоной, выданной вперёд следующему
// объявлению того же имени.
func TestIAMCT113_Injection_ExemptionWithoutASubjectIsFound(t *testing.T) {
	_, findings := auditKeyForm(keysWithLegacyCycle,
		[]string{"role_rule_ref_res_fk"}, []string{"accounts_owner_fk", "long_gone_fk"})
	if !containsSub(findings, "long_gone_fk") || !containsSub(findings, "нечего исключать") {
		t.Fatalf("запись без предмета обязана быть находкой; получено: %v", findings)
	}
	// Вторая сторона: запись, у которой предмет ЕСТЬ, находкой не становится.
	if containsSub(findings, "accounts_owner_fk") {
		t.Fatalf("запись с живым предметом находкой не является; получено: %v", findings)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// СВОД ЦЕПОЧКИ (kacho#1922) — доказательство по каждой оси, с законным близнецом
//
// Ось заведена вместе с предметом: базовая миграция сеет `alpha.thing.get`
// живым, поздняя помечает его снятым, и литерал этого глагола не называет.
// До свода такой корпус давал находку «посеян миграцией, нет в литерале» — то
// есть вердикт о состоянии, которого в базе нет ни секунды.

// retireVerbUp — поздняя миграция В ПРИЗНАННОЙ ФОРМЕ, с разметкой goose и с
// откатом, оживляющим ту же строку. Откат стоит здесь НАМЕРЕННО: разбор обязан
// читать только применяемую половину, иначе снятие свелось бы со своим же
// откатом в ноль — молча.
const retireVerbUp = `
-- +goose Up
UPDATE kaname.catalog_verb
   SET retired_at = now(), live = false,
       retired_reason = 'читателя нет ни одного; причина, содержащая точку с запятой; и запятую'
 WHERE module = 'alpha' AND resource = 'thing' AND verb = 'get' AND live;

-- +goose Down
UPDATE kaname.catalog_verb
   SET retired_at = NULL, live = true, retired_reason = NULL
 WHERE module = 'alpha' AND resource = 'thing' AND verb = 'get' AND NOT live;
`

// wantVerbsAfterRetire — литерал ПОСЛЕ снятия: `alpha.thing.get` он не называет.
var wantVerbsAfterRetire = []string{"beta.other.list"}

// TestIAMCT114_Injection_Chain_ControlIsSilent — КОНТРОЛЬ: цепочка из посева и
// признанного снятия согласна с литералом, который снятого глагола не называет.
func TestIAMCT114_Injection_Chain_ControlIsSilent(t *testing.T) {
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_retire.sql", Body: retireVerbUp},
	}
	c, findings, err := auditCatalogSeed(corpus, wantMods, wantRes, wantVerbsAfterRetire)
	if err != nil {
		t.Fatalf("контроль обязан разбираться: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("контроль обязан молчать, найдено: %v", findings)
	}
	if c.MigrationsRead != 2 || c.RetiredLater != 1 {
		t.Fatalf("перепись обязана называть охват: прочитано %d миграций, снято поздним %d "+
			"(ждали 2 и 1) — иначе прибавка охвата неотличима от прибавки находок",
			c.MigrationsRead, c.RetiredLater)
	}
}

// TestIAMCT114_Injection_Chain_WithoutTheFoldTheSeedDiverges — ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ САМОГО СВОДА: без поздней миграции тот же литерал даёт находку.
//
// Без этой оси зелёный контроля был бы неотличим от «гейт перестал сверять
// глаголы вовсе».
func TestIAMCT114_Injection_Chain_WithoutTheFoldTheSeedDiverges(t *testing.T) {
	_, findings, err := auditCatalogSeed(oneMigration(goodSeed), wantMods, wantRes, wantVerbsAfterRetire)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "alpha.thing.get") || !containsSub(findings, "нет в литерале") {
		t.Fatalf("посев без снятия обязан расходиться с литералом; получено: %v", findings)
	}
}

// TestIAMCT114_Injection_Chain_DownHalfIsNotFolded — ЗАКОННЫЙ БЛИЗНЕЦ формы:
// оживляющий оператор стоит в откате и в свод НЕ входит.
//
// Читай разбор файл целиком — снятие и его откат погасили бы друг друга, и
// вердикт вернулся бы к досводному, оставаясь на вид исправным.
func TestIAMCT114_Injection_Chain_DownHalfIsNotFolded(t *testing.T) {
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_retire.sql", Body: retireVerbUp},
	}
	_, retired, findings := catalogCorpus(corpus)
	if len(findings) != 0 {
		t.Fatalf("законная форма находкой не является; получено: %v", findings)
	}
	if !retired["alpha.thing.get"] || len(retired) != 1 {
		t.Fatalf("свод обязан прочитать РОВНО снятие применяемой половины; прочитано: %v", retired)
	}
}

// TestIAMCT114_Injection_Chain_UnknownFormIsFoundNotSilent — ГЛАВНАЯ ось.
//
// Оператор над каталогом, формы которого разбор не знает, обязан быть НАЗВАН.
// Молчание здесь хуже красного: свод считал бы живой строку, которую цепочка
// снимает, и посев расходился бы с литералом незамеченным.
func TestIAMCT114_Injection_Chain_UnknownFormIsFoundNotSilent(t *testing.T) {
	unknown := `
-- +goose Up
DELETE FROM kaname.catalog_verb WHERE module = 'alpha' AND resource = 'thing' AND verb = 'get';
`
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_unknown.sql", Body: unknown},
	}
	_, findings, err := auditCatalogSeed(corpus, wantMods, wantRes, wantVerbsAfterRetire)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "форма которого разбору НЕИЗВЕСТНА") ||
		!containsSub(findings, "20260914120000_unknown.sql") {
		t.Fatalf("неизвестная форма обязана быть находкой С ИМЕНЕМ файла; получено: %v", findings)
	}
}

// TestIAMCT114_Injection_Chain_PartialRetireFormIsNotAccepted — форма узкая, и
// это проверяется с обеих сторон: оператор, снимающий живость БЕЗ отметки
// времени, признанным снятием не становится.
//
// Иначе гейт принял бы за снятие всякий `UPDATE … live = false`, в том числе
// тот, что правит другие колонки или отбирает больше одной строки.
func TestIAMCT114_Injection_Chain_PartialRetireFormIsNotAccepted(t *testing.T) {
	partial := strings.Replace(retireVerbUp, "retired_at = now(), live = false", "live = false", 1)
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_partial.sql", Body: partial},
	}
	_, _, findings := catalogCorpus(corpus)
	if !containsSub(findings, "форма которого разбору НЕИЗВЕСТНА") {
		t.Fatalf("неполная форма снятия признанной не является; получено: %v", findings)
	}
}

// TestIAMCT114_Injection_Chain_RetireWithoutASubjectIsFound — САМОИСТЕЧЕНИЕ.
//
// Снятие строки, которой посев не сеет живой, — оператор, переживший свой
// предмет: он стоит в цепочке, выглядит работающим и не меняет ничего.
func TestIAMCT114_Injection_Chain_RetireWithoutASubjectIsFound(t *testing.T) {
	stale := strings.ReplaceAll(retireVerbUp, "'thing'", "'gone'")
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_stale.sql", Body: stale},
	}
	_, findings, err := auditCatalogSeed(corpus, wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "alpha.gone.get") || !containsSub(findings, "пережил свой предмет") {
		t.Fatalf("снятие без предмета обязано быть находкой; получено: %v", findings)
	}
}

// TestIAMCT114_Injection_Chain_CommentIsNotAStatement — ЗАКОННЫЙ БЛИЗНЕЦ:
// та же форма, записанная комментарием, оператором не является.
//
// Без этой оси гейт краснел бы на собственном объяснении — ровно тот класс,
// который ловит `testing.md` §«Гейт на класс» п. 4.
func TestIAMCT114_Injection_Chain_CommentIsNotAStatement(t *testing.T) {
	commented := `
-- +goose Up
-- Здесь ОБЪЯСНЯЕТСЯ форма снятия, а не производится снятие:
--   DELETE FROM kaname.catalog_verb WHERE module = 'alpha';
--   UPDATE kaname.catalog_verb SET live = false WHERE verb = 'get';
SELECT 1;
`
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_prose.sql", Body: commented},
	}
	c, findings, err := auditCatalogSeed(corpus, wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("проза о снятии оператором не является; получено: %v", findings)
	}
	if c.RetiredLater != 0 {
		t.Fatalf("свод обязан прочитать ноль снятий из прозы, прочитано %d", c.RetiredLater)
	}
}

// TestIAMCT114_Injection_Chain_DollarBlockHidingAWriteIsNamed — МАСКА НЕ СТАНОВИТСЯ
// СЛЕПОЙ ЗОНОЙ.
//
// Долларовый блок маскируется потому, что точка с запятой внутри границей
// оператора не является. Запись в каталог, спрятанная внутри, обязана быть
// НАЗВАНА: иначе маска дала бы ровно то молчание, ради устранения которого
// заведён свод.
func TestIAMCT114_Injection_Chain_DollarBlockHidingAWriteIsNamed(t *testing.T) {
	hidden := `
-- +goose Up
DO $$
BEGIN
    UPDATE kaname.catalog_verb SET live = false WHERE module = 'alpha';
END
$$;
`
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_hidden.sql", Body: hidden},
	}
	_, _, findings := catalogCorpus(corpus)
	if !containsSub(findings, "долларового блока") || !containsSub(findings, "20260914120000_hidden.sql") {
		t.Fatalf("запись, спрятанная в блоке, обязана быть названа; получено: %v", findings)
	}
}

// TestIAMCT114_Injection_Chain_DollarBlockWithoutAWriteIsSilent — ЗАКОННЫЙ
// БЛИЗНЕЦ предыдущей оси: блок, который каталог только ЧИТАЕТ, находкой не
// является. В дереве такой блок есть (предпосылка миграции 20260904135459
// считает живые модули), и красное на нём отключило бы гейт первым же прогоном.
func TestIAMCT114_Injection_Chain_DollarBlockWithoutAWriteIsSilent(t *testing.T) {
	reading := `
-- +goose Up
DO $$
DECLARE n integer;
BEGIN
    SELECT count(*) INTO n FROM kaname.catalog_module WHERE live;
    IF n = 0 THEN RAISE EXCEPTION 'каталог пуст'; END IF;
END
$$;
`
	corpus := []catalogSeedMigration{
		{Name: "0001_initial.sql", Body: goodSeed},
		{Name: "20260914120000_reading.sql", Body: reading},
	}
	_, _, findings := catalogCorpus(corpus)
	if len(findings) != 0 {
		t.Fatalf("чтение каталога в блоке находкой не является; получено: %v", findings)
	}
}
