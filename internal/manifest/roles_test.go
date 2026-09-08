// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// roles_test.go — раздел `roles` (приёмка §2.6, §2.6а; сценарии MOD-MR-10 …
// MOD-MR-15).
//
// Раздел АВТОРСКИЙ: аннотации о ролях не говорят ничего. Зато говорят
// МИГРАЦИИ — 51 системная роль объявлена применёнными, а применённую миграцию
// не правят (ban #5).
//
// Здесь стояло «поэтому манифест объявляет роли уровня аккаунта и проекта, а
// системную отвергает ЯВНО». Утверждение снято вместе со своим предметом
// (приёмка `roles-come-as-data-not-migrations.md` §3.2): кластерный ярус
// ПРИНИМАЕТСЯ, писателем строки становится применитель манифеста, а отказ
// остаётся у роли ЧУЖОГО модуля. Что при этом не изменилось — ярусы аккаунта и
// проекта, — утверждает MOD-RD-05 положительным контролем.
//
// Здесь стояло «форма выдачи изоморфна `domain.Rule` ДОСЛОВНО — имя в имя»:
// утверждение пережило свой предмет (#1849). Право роли пишется ключом
// `classes`, а хранится полем `Verbs`; расхождение ОДНО, объявлено словарём
// `ruleKeyToDomainField` и утверждается пробой перевода — см. MOD-MR-10 ниже.
package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// ── MOD-MR-10 ───────────────────────────────────────────────────────────────

// TestMODMR10RolesSectionLoads — положительный контроль полосы `roles`: раздел
// проходит загрузчик целиком, и значения ключей доступны вызывающему.
//
// # Сверка ключей выдачи с полями `domain.Rule` ПЕРЕЕХАЛА, а не снята
//
// Здесь стояла вторая половина — равенство множеств «ключи `manifest.Rule` ↔
// поля `domain.Rule`» по именам. Предмет её никуда не делся, но проверялась она
// ЗАПРЕТОМ ВСЯКОГО расхождения, а расхождение теперь есть и оно законно: право
// роли пишется ключом `classes`, а хранится полем `Verbs`, и второго поля
// хранимая форма не получит (#1849, `roles.go` §«Расхождение имён с
// `domain.Rule` ОБЪЯВЛЕНО, а не запрещено»).
//
// Предмет держит `TestMODRC08NameDivergenceIsDeclaredAndSelfExpiring`
// (`ruletranslation_internal_test.go`), и он СТРОГО СИЛЬНЕЕ снятой половины —
// три стороны против двух: (1) у ключа манифеста есть либо одноимённое поле,
// либо запись словаря; (2) у КАЖДОЙ записи словаря существуют обе стороны,
// поэтому запись, пережившая свой предмет, роняет пробу; (3) поле домена без
// ключа и без записи словаря невыразимо манифестом — та самая половина, которую
// ловил прежний изоморфизм, и она сохранена дословно.
//
// Держать её и здесь значило бы завести два места об одном предмете: они
// разошлись бы на первом же новом поле, и разошлись бы МОЛЧА — обе стороны
// отвечают одинаково на законном входе.
func TestMODMR10RolesSectionLoads(t *testing.T) {
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
	// Право роли прочитано ЗНАЧЕНИЕМ, а не только по числу правил: иначе
	// положительный контроль зеленел бы на правиле, у которого его нет вовсе.
	if len(m.Roles[0].Rules[0].Classes) == 0 {
		t.Errorf("право роли прочитано пустым: %+v", m.Roles[0].Rules[0])
	}
	t.Logf("перепись: ролей прочитано %d · правил у первой %d · классов у первого правила %d",
		len(m.Roles), len(m.Roles[0].Rules), len(m.Roles[0].Rules[0].Classes))
}

// ── MOD-MR-11 ───────────────────────────────────────────────────────────────

// TestMODMR11RoleIDOfAForeignModuleIsRefused — манифест объявляет роли СВОЕГО
// модуля; чужая роль здесь была бы объявлением за чужой домен.
func TestMODMR11RoleIDOfAForeignModuleIsRefused(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: %s\n    description: Читает топологию проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n"

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
		"  - id: vpc.viewer\n    description: Читает топологию проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - {module: vpc, resources: [%s], classes: [%s]}\n"

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
		"  - id: vpc.viewer\n    description: Читает топологию проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - module: vpc\n        resources: [network]\n        classes: [get]\n%s"

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

// ── MOD-MR-14 СНЯТ ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ ────────────────────────────────
//
// Здесь стояла проба `TestMODMR14SystemRoleIsRefusedExplicitly`, утверждавшая
// отказ `ErrSystemRoleNotAuthorable` по кластерному ярусу. Её предмет СНЯТ
// решением приёмки `roles-come-as-data-not-migrations.md` §3.2: отказ ФОРМЫ
// заменён отказом ВЛАДЕНИЯ, потому что все живые системные роли — кластерные, и
// исполнимого входа у раздела не существовало ни одного.
//
// Проба ЗАМЕНЕНА, а не ослаблена: новое свойство того же предмета утверждают
// `TestMODRD01ClusterTierRoleOfOwnModuleIsAccepted` (ярус принимается) и
// `TestMODRD02ClusterTierRoleOfAForeignModuleIsStillRefused` (право объявления
// не расширилось) в `roles_cluster_tier_test.go`. Убрать утверждение и оставить
// пробу было бы ослаблением; оставить её как есть — утверждением о том, чего в
// продукте больше нет.

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

	broken := replaceOnce(t, doc, "roleId: vpc.internal_consumer", "roleId: vpc.nosuchRole")
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

// ── MOD-MR-36 ───────────────────────────────────────────────────────────────

// TestMODMR36RoleDescriptionIsJudgedByPresenceNotByLength — назначение роли
// судится НАЛИЧИЕМ, а не длиной, и обе стороны утверждаются здесь.
//
// # Почему длина этому полю не судья — доказано ЖИВЫМ набором, а не доводом
//
// Предел длины на этом поле выносит приговор по длине ИМЕНИ ТИПА, а не по
// пригодности прозы. Четыре живые строки, один шаблон, один автор, одно
// содержание — и противоположные вердикты при пределе в шестнадцать знаков:
//
//	`Admin RouteTable`    16 знаков — прошёл бы
//	`Edit RouteTable`     15 знаков — не прошёл бы
//	`Admin SecurityGroup` 19 знаков — прошёл бы
//	`Admin Subnet`        12 знаков — не прошёл бы
//
// Проверка, чей вердикт есть функция чего-то, кроме её предмета, предметом не
// распоряжается. Отписку («TODO», «-») длина ловит попутно, а платит за это
// отказом двадцати семи живым ролям из сорока двух — то есть возможностью,
// объявленной и неисполнимой (`api-conventions.md` §«Неисполнимая
// возможность»).
//
// # Что судит назначение ВМЕСТО длины
//
// Применитель пишет назначение ДОСЛОВНО поверх живой строки, поэтому у наших
// модулей оно закреплено побайтовой сверкой с базой
// (`moduleroleparity`) — строго сильнее любого предела длины. Загрузчику
// остаётся то, о чём он вправе судить один: назначение НАЗВАНО.
func TestMODMR36RoleDescriptionIsJudgedByPresenceNotByLength(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: iam\nroles:\n" +
		"  - id: iam.role.edit\n    description: %s\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n      - {module: iam, resources: [role], classes: [get, list, update]}\n"

	// Положительный: ДОСЛОВНОЕ назначение живой роли `iam.role.edit` — девять
	// знаков, самое короткое в дереве. Иначе объявить эту роль невозможно ни при
	// каком написании: длиннее — разошлось бы со строкой, которую применитель
	// переписал бы молча.
	for _, live := range []string{`"Edit Role"`, `"Read User"`, `"Admin Subnet"`, `"Edit RouteTable"`} {
		if _, err := manifest.Load([]byte(strings.Replace(base, "%s", live, 1))); err != nil {
			t.Errorf("живое назначение %s отвергнуто: %v", live, err)
		}
	}

	// Отрицательный: назначения НЕТ. Пустая строка и одни пробелы — оба вида
	// «не названо», и второй проверяется отдельно: без него отказ зеленел бы на
	// пробеле, то есть на отписке в её чистейшем виде.
	for _, absent := range []string{`""`, `"   "`} {
		_, err := manifest.Load([]byte(strings.Replace(base, "%s", absent, 1)))
		if err == nil {
			t.Fatalf("роль без назначения принята (description: %s)", absent)
		}
		if !errors.Is(err, manifest.ErrRoleDescriptionTooShort) {
			t.Errorf("отказ не отнесён к своей причине: %v", err)
		}
		if !strings.Contains(err.Error(), "roles[0].description") {
			t.Errorf("отказ не называет поле: %v", err)
		}
	}
}
