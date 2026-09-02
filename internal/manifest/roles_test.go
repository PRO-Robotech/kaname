// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// roles_test.go — раздел `roles` (приёмка §2.6, §2.6а; сценарии MOD-MR-10 …
// MOD-MR-15).
//
// Раздел АВТОРСКИЙ: аннотации о ролях не говорят ничего. Зато говорят
// МИГРАЦИИ — 51 системная роль объявлена применёнными, а применённую миграцию
// не правят (ban #5). Поэтому манифест объявляет роли уровня аккаунта и
// проекта, а системную отвергает ЯВНО.
//
// Форма выдачи изоморфна `domain.Rule` ДОСЛОВНО — имя в имя, число в число.
// Второе написание того же предмета разошлось бы с первым молча.
package manifest_test

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// yamlKeysOf — ключи, ОБЪЯВЛЕННЫЕ тегами структуры, а не выписанные списком:
// выписанный перечень не сдвинулся бы от нового поля.
func yamlKeysOf(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag, ok := t.Field(i).Tag.Lookup("yaml")
		if !ok {
			continue
		}
		if name := strings.Split(tag, ",")[0]; name != "" && name != "-" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// lowerFirst — имя поля Go в том написании, в каком его несёт ключ YAML.
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	// `ResourceNames` → `resourceNames`; `ID` → `id` (аббревиатура целиком).
	n := 1
	for n < len(r) && unicode.IsUpper(r[n]) && (n+1 == len(r) || unicode.IsUpper(r[n+1])) {
		n++
	}
	for i := 0; i < n; i++ {
		r[i] = unicode.ToLower(r[i])
	}
	return string(r)
}

// ── MOD-MR-10 ───────────────────────────────────────────────────────────────

// TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule — положительный
// контроль полосы `roles` плюс РАВЕНСТВО множеств ключей выдачи и полей
// `domain.Rule`.
//
// Равенство, а не членство: ключ без поля — такая же ложь контракта, как поле
// без ключа. Обе стороны ВЫВЕДЕНЫ обходом типов.
func TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule(t *testing.T) {
	m, err := manifest.Load([]byte(mustReadResourcesFixture(t)))
	if err != nil {
		t.Fatalf("раздел roles отвергнут: %v", err)
	}
	if len(m.Roles) != 2 {
		t.Fatalf("ролей прочитано %d, в фикстуре две", len(m.Roles))
	}
	if m.Roles[0].Tier == nil || m.Roles[0].Tier.TierType != "iam.project" {
		t.Errorf("ярус роли прочитан неверно: %+v", m.Roles[0].Tier)
	}
	if len(m.Roles[0].Rules) != 1 || m.Roles[0].Rules[0].Module != "vpc" {
		t.Errorf("выдача роли прочитана неверно: %+v", m.Roles[0].Rules)
	}

	manifestKeys := yamlKeysOf(reflect.TypeOf(manifest.Rule{}))
	var domainKeys []string
	dt := reflect.TypeOf(domain.Rule{})
	for i := 0; i < dt.NumField(); i++ {
		if f := dt.Field(i); f.IsExported() {
			domainKeys = append(domainKeys, lowerFirst(f.Name))
		}
	}
	sort.Strings(domainKeys)

	inDomain := map[string]bool{}
	for _, k := range domainKeys {
		inDomain[k] = true
	}
	inManifest := map[string]bool{}
	for _, k := range manifestKeys {
		inManifest[k] = true
	}
	for _, k := range manifestKeys {
		if !inDomain[k] {
			t.Errorf("ключ выдачи %q не имеет поля в domain.Rule: манифест заводит второй "+
				"словарь для того же предмета", k)
		}
	}
	for _, k := range domainKeys {
		if !inManifest[k] {
			t.Errorf("поле domain.Rule %q не имеет ключа в выдаче манифеста: правило, "+
				"выразимое в продукте, невыразимо в манифесте", k)
		}
	}
	t.Logf("перепись: ключей выдачи манифеста %d (%v) · полей domain.Rule %d (%v)",
		len(manifestKeys), manifestKeys, len(domainKeys), domainKeys)
}

// ── MOD-MR-11 ───────────────────────────────────────────────────────────────

// TestMODMR11RoleIDOfAForeignModuleIsRefused — манифест объявляет роли СВОЕГО
// модуля; чужая роль здесь была бы объявлением за чужой домен.
func TestMODMR11RoleIDOfAForeignModuleIsRefused(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: %s\n    name: Наблюдатель\n    description: Читает.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "compute.viewer", 1)))
	if err == nil {
		t.Fatalf("роль чужого модуля принята")
	}
	if !errors.Is(err, manifest.ErrRoleForeignModule) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"roles[0].id", "compute", "vpc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "vpc.viewer", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MR-12 ───────────────────────────────────────────────────────────────

// TestMODMR12ResourceWildcardIsAlwaysRefusedAndVerbWildcardIsNot — асимметрия
// ИЗМЕРЕНА, а не предположена: подстановка ресурса системна by construction, а
// подстановка глагола в несистемной роли законна и значит «все глаголы типа».
//
// Проверять надо ОБЕ стороны: односторонняя проба зеленела бы на загрузчике,
// отвергающем всякую подстановку.
func TestMODMR12ResourceWildcardIsAlwaysRefusedAndVerbWildcardIsNot(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.viewer\n    name: Наблюдатель\n    description: Читает.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - {module: vpc, resources: [%s], verbs: [%s]}\n"

	wildcardResources := strings.Replace(strings.Replace(base, "%s", `"*"`, 1), "%s", "get", 1)
	_, err := manifest.Load([]byte(wildcardResources))
	if err == nil {
		t.Fatalf("подстановка ресурса в несистемной роли принята")
	}
	if !errors.Is(err, manifest.ErrRoleRuleInvalid) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	// Текст домена — часть контракта и воспроизводится ДОСЛОВНО.
	if !strings.Contains(err.Error(), "Illegal argument resources (wildcard '*' is system-only)") {
		t.Errorf("отказ не несёт дословного текста домена: %v", err)
	}

	// Парный положительный, измеренный и АСИММЕТРИЧНЫЙ: подстановка глагола
	// единственным элементом законна.
	wildcardVerbs := strings.Replace(strings.Replace(base, "%s", "network", 1), "%s", `"*"`, 1)
	if _, err := manifest.Load([]byte(wildcardVerbs)); err != nil {
		t.Fatalf("подстановка глагола в несистемной роли отвергнута: %v", err)
	}
}

// ── MOD-MR-13 ───────────────────────────────────────────────────────────────

// TestMODMR13ResourceNamesAndMatchLabelsAreMutuallyExclusive — действительный
// взаимоисключающий инвариант `domain.Rule` со своим стабильным текстом.
func TestMODMR13ResourceNamesAndMatchLabelsAreMutuallyExclusive(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.viewer\n    name: Наблюдатель\n    description: Читает.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - module: vpc\n        resources: [network]\n        verbs: [get]\n%s"

	both := "        resourceNames: [net-abc]\n        matchLabels: {env: prod}\n"
	_, err := manifest.Load([]byte(strings.Replace(base, "%s", both, 1)))
	if err == nil {
		t.Fatalf("resourceNames и matchLabels приняты вместе")
	}
	if !errors.Is(err, manifest.ErrRoleRuleInvalid) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(),
		"Illegal argument: resourceNames and matchLabels are mutually exclusive") {
		t.Errorf("отказ не несёт дословного текста домена: %v", err)
	}

	// Парные положительные: ровно одно из двух.
	for _, only := range []string{
		"        resourceNames: [net-abc]\n",
		"        matchLabels: {env: prod}\n",
	} {
		if _, err := manifest.Load([]byte(strings.Replace(base, "%s", only, 1))); err != nil {
			t.Fatalf("ровно один селектор отвергнут (%q): %v", strings.TrimSpace(only), err)
		}
	}
}

// ── MOD-MR-14 ───────────────────────────────────────────────────────────────

// TestMODMR14SystemRoleIsRefusedExplicitly — системность НЕ отдельный признак, а
// СЛЕДСТВИЕ яруса: контракт говорит дословно, что `is_system` выводится из
// `tier_type == iam.cluster`. Поэтому отказ по ярусу и есть отказ системной
// роли, а не его приближение.
//
// Исход 2 запрета «принято-и-проигнорировано»: приняв, мы вернули бы
// вызывающему успех и уверенность, что его роль заведена, тогда как заводит её
// миграция, которой в этом изменении нет.
func TestMODMR14SystemRoleIsRefusedExplicitly(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.admin\n    name: Администратор\n    description: Может всё.\n" +
		"    tier: {tierType: %s, tierId: cluster_kacho_root}\n" +
		"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "iam.cluster", 1)))
	if err == nil {
		t.Fatalf("системная роль в манифесте принята")
	}
	if !errors.Is(err, manifest.ErrSystemRoleNotAuthorable) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{
		"roles[0].tier.tierType", "iam.cluster", "iam.account", "iam.project", "миграц",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "iam.project", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MR-15 ───────────────────────────────────────────────────────────────

// TestMODMR15RoleIDOfABindingIsResolvedByTheRolesSection — послабление #1088
// ИСТЕКЛО: перечень ролей приезжает из разобранного документа, а не подаётся
// перечнем сбоку.
//
// Перепись обязана сообщать НЕНУЛЕВОЕ число сверенных ссылок и не содержать
// строки «раздел roles не описан»: ноль сверенных читался бы как «сверили и не
// нашли расхождений».
func TestMODMR15RoleIDOfABindingIsResolvedByTheRolesSection(t *testing.T) {
	doc := mustReadResourcesFixture(t)

	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("фикстура отвергнута: %v", err)
	}
	census := m.Linkage()
	t.Logf("перепись связности: %s", census)
	if census.RoleRefsChecked == 0 {
		t.Errorf("сверено ноль ссылок на роль при описанном разделе: %s", census)
	}
	if !census.RolesDeclared {
		t.Errorf("раздел roles описан, а перепись считает его необъявленным: %s", census)
	}
	if strings.Contains(census.String(), "не описан") {
		t.Errorf("перепись всё ещё объясняет ноль сверенных отсутствием раздела: %s", census)
	}

	broken := replaceOnce(t, doc, "roleId: vpc.internalConsumer", "roleId: vpc.nosuchRole")
	_, err = manifest.Load([]byte(broken))
	if err == nil {
		t.Fatalf("выдача на роль, которой манифест не объявляет, принята")
	}
	if !errors.Is(err, manifest.ErrRoleNotDeclared) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"vpc.nosuchRole", "seed.accessBindings[0].roleId"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
}
