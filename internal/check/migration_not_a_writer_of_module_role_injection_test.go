// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_not_a_writer_of_module_role_injection_test.go — доказательство, что
// гейт СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17, семейство
// `migrationnotawriterofmodulerole`).
//
// Инъекция зовёт ТЕ ЖЕ функции, что и гейт — разбор манифеста, разбор вставок и
// предикат находки, — а не свои копии.
//
// # Законный близнец у КАЖДОЙ оси
//
// Односторонняя проверка зеленела бы на дереве, где сломано всё сразу. Поэтому
// рядом с каждой находкой стоит вход той же формы, на котором гейт обязан
// МОЛЧАТЬ: роль модуля без манифеста, роль без владельца в имени и та же
// вставка в НЕдобавленной миграции.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injManifest — манифест модуля в том виде, в каком его опознаёт разбор.
const injManifest = `apiVersion: iam/v1
module: iam
resources:
  - name: account
`

// injManifestWithoutVersion — законный близнец: документ, манифестом не
// являющийся. Отличается РОВНО ОДНИМ фактом — нет объявления версии контракта.
const injManifestWithoutVersion = `module: iam
resources:
  - name: account
`

// injHandwrittenInsert — рукописная форма: идентификатор ВЫВОДИТСЯ из имени.
const injHandwrittenInsert = `-- +goose Up
INSERT INTO kaname.roles (id, account_id, name, rules)
VALUES ('rol' || substr(md5('iam.account.admin'),1,17), NULL, 'iam.account.admin', '[]'::jsonb);
`

// injDumpInsert — снимочная форма: идентификатор уже вычислен, колонки
// перечислены явно. Её производит сведённый свод миграций, и разбор, знавший
// одну форму, извлекал бы отсюда НОЛЬ имён — то есть невидимость.
const injDumpInsert = `-- +goose Up
INSERT INTO kaname.roles (id, account_id, name, rules) VALUES ('rol6307abcdefghijk', NULL, 'iam.account.admin', '[{"verbs": ["*"], "module": "iam"}]');
`

// injForeignModuleInsert — законный близнец: роль модуля, манифеста у которого
// нет. Миграция остаётся его законным писателем.
const injForeignModuleInsert = `-- +goose Up
INSERT INTO kaname.roles (id, account_id, name, rules) VALUES ('rol000000000000vpc', NULL, 'vpc.network.admin', '[]');
`

// injOwnerlessInsert — законный близнец: имя без владельца в первом сегменте.
const injOwnerlessInsert = `-- +goose Up
INSERT INTO kaname.roles (id, account_id, name, rules) VALUES ('rol000000000sysadmin', NULL, 'sysadmin', '[]');
`

// injForeignTableInsert — законный близнец: вставка в ЧУЖУЮ таблицу. Тот же
// образец идентификатора встречается в селекторах и выдачах, и предикат без
// привязки к блоку мерил бы упоминания, а не строки роли.
const injForeignTableInsert = `-- +goose Up
INSERT INTO kaname.role_rule_selectors (role_id, selector)
VALUES ('rol' || substr(md5('iam.account.admin'),1,17), 'iam.account');
`

// injUnknownFormInsert — вставка роли БЕЗ перечня колонок и без деривации: имя
// в ней разбором не читается ничем.
const injUnknownFormInsert = `-- +goose Up
INSERT INTO kaname.roles VALUES ('rol6307abcdefghijk', NULL, 'iam.account.admin', '[]');
`

func TestModuleRoleGate_ManifestIsRecognisedByContent(t *testing.T) {
	t.Parallel()

	site, ok := check.ScanModuleManifest("manifest.yaml", []byte(injManifest))
	if !ok || site.Module != "iam" {
		t.Fatalf("манифест не опознан по содержимому (ok=%v, модуль %q) — гейт, привязанный "+
			"к пути, молчал бы вечно, окажись путь другим", ok, site.Module)
	}
	// Законный близнец: отличается РОВНО ОДНИМ фактом.
	if _, ok := check.ScanModuleManifest("manifest.yaml", []byte(injManifestWithoutVersion)); ok {
		t.Fatal("документ без объявления версии контракта опознан манифестом — тогда " +
			"манифестом станет любой YAML со словом «module», и каждая миграция такого " +
			"модуля превратится в находку")
	}
}

func TestModuleRoleGate_BothNameFormsAreRead(t *testing.T) {
	t.Parallel()

	for name, src := range map[string]string{
		"рукописная (имя аргументом деривации)": injHandwrittenInsert,
		"снимочная (перечень колонок)":          injDumpInsert,
	} {
		sites, census := check.ScanMigrationRoleInserts("m.sql", []byte(src))
		if census.Blocks != 1 || census.Names != 1 || census.Unreadable != 0 || len(sites) != 1 {
			t.Fatalf("%s: блоков %d, имён %d, непрочитанных %d, сайтов %d — форма выпала бы "+
				"из наблюдения молча", name, census.Blocks, census.Names, census.Unreadable, len(sites))
		}
		if sites[0].Name != "iam.account.admin" || sites[0].Owner != "iam" {
			t.Fatalf("%s: имя %q, владелец %q", name, sites[0].Name, sites[0].Owner)
		}
	}
}

func TestModuleRoleGate_UnknownFormIsCountedNotSkipped(t *testing.T) {
	t.Parallel()

	sites, census := check.ScanMigrationRoleInserts("m.sql", []byte(injUnknownFormInsert))
	if census.Blocks != 1 || census.Unreadable != 1 || len(sites) != 0 {
		t.Fatalf("блоков %d, непрочитанных %d, сайтов %d — неизвестная форма обязана быть "+
			"ВИДНА числом: роль вставлена, а гейт о ней не судил, и это невидимость, "+
			"а не находка и не молчание", census.Blocks, census.Unreadable, len(sites))
	}
}

func TestModuleRoleGate_ForeignTableIsNotARoleBlock(t *testing.T) {
	t.Parallel()

	_, census := check.ScanMigrationRoleInserts("m.sql", []byte(injForeignTableInsert))
	if census.Blocks != 0 {
		t.Fatalf("вставка в ЧУЖУЮ таблицу зачтена блоком роли (%d) — предикат мерил бы "+
			"упоминания идентификатора, а не строки роли", census.Blocks)
	}
}

func TestModuleRoleGate_FindingAndItsLawfulTwins(t *testing.T) {
	t.Parallel()

	bearing := map[string]string{"iam": "manifest.yaml"}

	// ИНЪЕКЦИЯ: добавленная миграция вставляет роль модуля с манифестом.
	sites, _ := check.ScanMigrationRoleInserts("internal/migrations/0999_add.sql",
		[]byte(injDumpInsert))
	added := map[string]bool{"internal/migrations/0999_add.sql": true}
	got := migrationRoleFindings(sitesInFiles(sites, added), bearing)
	if len(got) != 1 {
		t.Fatalf("возвращённый дефект не найден: находок %d", len(got))
	}
	for _, want := range []string{"0999_add.sql", "iam.account.admin", "manifest.yaml"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("находка не называет %q: %s", want, got[0])
		}
	}
	t.Logf("плечо падения: %s", got[0])

	// БЛИЗНЕЦ 1: та же вставка в НЕдобавленной миграции. Отличается ровно одним
	// фактом — составом добавленного. Применённую миграцию не правят (ban #5),
	// и требовать её починки значило бы держать ствол красным за прошлое.
	if rest := migrationRoleFindings(sitesInFiles(sites, map[string]bool{}), bearing); len(rest) != 0 {
		t.Fatalf("историческая миграция объявлена находкой (%d) — гейт требовал бы правки "+
			"применённого:\n  %s", len(rest), strings.Join(rest, "\n  "))
	}

	// БЛИЗНЕЦ 2: роль модуля БЕЗ манифеста. Миграция — его законный писатель.
	foreign, _ := check.ScanMigrationRoleInserts("internal/migrations/0999_add.sql",
		[]byte(injForeignModuleInsert))
	if rest := migrationRoleFindings(sitesInFiles(foreign, added), bearing); len(rest) != 0 {
		t.Fatalf("роль модуля без манифеста объявлена находкой (%d):\n  %s",
			len(rest), strings.Join(rest, "\n  "))
	}

	// БЛИЗНЕЦ 3: имя без владельца в первом сегменте — владельца нет, сверять
	// не с чем.
	ownerless, _ := check.ScanMigrationRoleInserts("internal/migrations/0999_add.sql",
		[]byte(injOwnerlessInsert))
	if rest := migrationRoleFindings(sitesInFiles(ownerless, added), bearing); len(rest) != 0 {
		t.Fatalf("роль без владельца в имени объявлена находкой (%d):\n  %s",
			len(rest), strings.Join(rest, "\n  "))
	}

	// БЛИЗНЕЦ 4: популяция пуста — манифестов нет вовсе. Молчание здесь означает
	// «сверять не с чем», и оно обязано быть молчанием, а не находкой.
	if rest := migrationRoleFindings(sitesInFiles(sites, added), map[string]string{}); len(rest) != 0 {
		t.Fatalf("при пустой популяции найдено %d — гейт судил бы то, чего не знает", len(rest))
	}

	t.Log("плечи молчания: историческая миграция · модуль без манифеста · имя без владельца · " +
		"пустая популяция — находок 0 в каждом")
}
