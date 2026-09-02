// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
INSERT INTO kacho_iam.catalog_module (module) VALUES
  ('alpha'),
  ('beta');

INSERT INTO kacho_iam.catalog_resource (module, resource, dotted) VALUES
  ('alpha', 'thing', 'alpha.thing'),
  ('beta', 'other', 'beta.other');

INSERT INTO kacho_iam.catalog_resource
  (module, resource, dotted, retired_at, retired_reason, superseded_by, live) VALUES
  ('alpha', 'old', 'alpha.old', now(),
   'снято; причина, содержащая запятую', 'beta.other', false);

INSERT INTO kacho_iam.catalog_verb (module, resource, verb) VALUES
  ('alpha', 'thing', 'get'),
  ('beta', 'other', 'list');
`

var (
	wantMods  = []string{"alpha", "beta"}
	wantRes   = []string{"alpha.thing", "beta.other"}
	wantVerbs = []string{"alpha.thing.get", "beta.other.list"}
)

func TestIAMCT114_Injection_ControlIsSilent(t *testing.T) {
	c, findings, err := auditCatalogSeed(goodSeed, wantMods, wantRes, wantVerbs)
	if err != nil {
		t.Fatalf("контроль обязан разбираться: %v", err)
	}
	t.Logf("осмотрено: модулей %d, ресурсов %d, глаголов %d, снятых %d",
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
	_, findings, err := auditCatalogSeed(goodSeed, wantMods,
		append(append([]string{}, wantRes...), "alpha.extra"), wantVerbs)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "alpha.extra") || !containsSub(findings, "не посеян миграцией") {
		t.Fatalf("строка литерала без посева обязана быть находкой; получено: %v", findings)
	}
}

func TestIAMCT114_Injection_RowBeyondTheLiteralIsFound(t *testing.T) {
	_, findings, err := auditCatalogSeed(goodSeed, wantMods,
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
	_, findings, err := auditCatalogSeed(bad, wantMods,
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
	_, findings, err := auditCatalogSeed(bad, wantMods, wantRes, wantVerbs)
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
		"INSERT INTO kacho_iam.catalog_verb (module, resource, verb) VALUES\n  ('alpha', 'thing', 'get'),\n  ('beta', 'other', 'list');",
		"INSERT INTO kacho_iam.catalog_verb (module, resource, verb) VALUES\n-- посева нет", 1)
	_, _, err := auditCatalogSeed(empty, wantMods, wantRes, wantVerbs)
	if err == nil {
		t.Fatal("пустой обход обязан быть ОТКАЗОМ, а не «расхождений нет»: " +
			"иначе «ноль находок» неотличимо от «ноль прочитанного»")
	}
}

// ── форма ключа ───────────────────────────────────────────────────────────────

const goodKeys = `
ALTER TABLE kacho_iam.role_rule_ref
  ADD CONSTRAINT role_rule_ref_res_fk
  FOREIGN KEY (module, resource, live)
  REFERENCES kacho_iam.catalog_resource (module, resource, live)
  ON DELETE NO ACTION ON UPDATE NO ACTION
  DEFERRABLE INITIALLY IMMEDIATE;

ALTER TABLE kacho_iam.other_table
  ADD CONSTRAINT other_fk
  FOREIGN KEY (x) REFERENCES kacho_iam.parent (x)
  DEFERRABLE INITIALLY DEFERRED;
`

func TestIAMCT113_Injection_ControlIsSilent(t *testing.T) {
	scanned, findings := auditKeyForm(goodKeys, []string{"role_rule_ref_res_fk"})
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
	_, findings := auditKeyForm(bad, []string{"role_rule_ref_res_fk"})
	if !containsSub(findings, "RESTRICT рядом с DEFERRABLE") {
		t.Fatalf("форма, принимаемая DDL и молча инертная, обязана быть находкой; получено: %v",
			findings)
	}
}

func TestIAMCT113_Injection_DeferredOnTheNamedKeyIsFound(t *testing.T) {
	bad := strings.Replace(goodKeys, "DEFERRABLE INITIALLY IMMEDIATE", "DEFERRABLE INITIALLY DEFERRED", 1)
	_, findings := auditKeyForm(bad, []string{"role_rule_ref_res_fk"})
	if !containsSub(findings, "role_rule_ref_res_fk") {
		t.Fatalf("смена формы названного ключа обязана быть находкой: она снимает «Тогда» "+
			"у трёх сценариев отказа; получено: %v", findings)
	}
}

func TestIAMCT113_Injection_CommentAboutRestrictIsNotAKey(t *testing.T) {
	withProse := strings.Replace(goodKeys, "  ON DELETE NO ACTION ON UPDATE NO ACTION",
		"  -- RESTRICT здесь запрещён: форма DEFERRABLE молча инертна\n"+
			"  ON DELETE NO ACTION ON UPDATE NO ACTION", 1)
	_, findings := auditKeyForm(withProse, []string{"role_rule_ref_res_fk"})
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
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, per_object) VALUES
  ('alpha', 'thing', 'create', false),
  ('beta', 'other', 'create', false);
`

var wantTierOnly = []string{"alpha.thing.create", "beta.other.create"}

func TestTierOnly_Injection_ControlIsSilent(t *testing.T) {
	seeded, findings, err := auditTierOnlyVerbSeed(goodTierOnlySeed, wantTierOnly)
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
	_, findings, err := auditTierOnlyVerbSeed(goodTierOnlySeed,
		append(append([]string{}, wantTierOnly...), "gamma.third.create"))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !containsSub(findings, "gamma.third.create") || !containsSub(findings, "не посеян миграцией") {
		t.Fatalf("ресурс, которому литерал даёт ярусный глагол, а миграция нет, обязан быть "+
			"находкой: правило роли на нём продолжает отвергаться ключом; получено: %v", findings)
	}
}

func TestTierOnly_Injection_RowBeyondTheLiteralIsFound(t *testing.T) {
	_, findings, err := auditTierOnlyVerbSeed(goodTierOnlySeed, []string{"alpha.thing.create"})
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
	_, findings, err := auditTierOnlyVerbSeed(bad, wantTierOnly)
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
	_, findings, err := auditTierOnlyVerbSeed(twin,
		[]string{"alpha.thing.create", "gamma.third.create"})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("законный близнец обязан молчать, найдено: %v", findings)
	}
}

func TestTierOnly_Injection_EmptySeedIsNotSilence(t *testing.T) {
	empty := "INSERT INTO kacho_iam.catalog_verb (module, resource, verb, per_object) VALUES\n-- посева нет\n"
	_, _, err := auditTierOnlyVerbSeed(empty, wantTierOnly)
	if err == nil {
		t.Fatal("пустой обход обязан быть ОТКАЗОМ, а не «расхождений нет»: " +
			"иначе «ноль находок» неотличимо от «ноль прочитанного»")
	}
}
