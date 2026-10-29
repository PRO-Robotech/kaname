// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// role_id_rename_ratchet_injection_test.go — способность храповика перевода id
// роли УПАСТЬ и СМОЛЧАТЬ (kaname#543). Каждому дефекту — законный близнец,
// отличающийся одним фактом.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const (
	injRoleRename      = "-- +goose Up\nUPDATE kaname.roles SET id = 'rolb' WHERE id = 'rola';\n-- +goose Down\nSELECT 1;\n"
	injRoleRenameLater = "-- +goose Up\nUPDATE kaname.roles SET name = 'x', id = 'rolb' WHERE id = 'rola';\n"
	injRoleNameOnly    = "-- +goose Up\nUPDATE kaname.roles SET name = 'x' WHERE id = 'rola';\n"
	injRoleRenameDown  = "-- +goose Up\nSELECT 1;\n-- +goose Down\nUPDATE kaname.roles SET id = 'rola' WHERE id = 'rolb';\n"
	injRoleRenameInDo  = "-- +goose Up\n-- +goose StatementBegin\nDO $$\nBEGIN\n    UPDATE kaname.roles SET id = 'rolb' WHERE id = 'rola';\nEND $$;\n-- +goose StatementEnd\n"
)

func injRoleCorpus(body string) []migrations.GrantMigrationSource {
	return []migrations.GrantMigrationSource{{Name: "20991231000000_x.sql", Body: body}}
}

// Дефект: перевод id, храповиком не названный, — находка с именем файла.
func TestRoleIDRenameRatchet_UnnamedRenameIsFound(t *testing.T) {
	for name, body := range map[string]string{
		"голый оператор":            injRoleRename,
		"id не первым в списке SET": injRoleRenameLater,
		"внутри тела DO":            injRoleRenameInDo,
		"таблица под псевдонимом":   "-- +goose Up\nUPDATE kaname.roles AS r SET id = 'rolb' WHERE r.id = 'rola';\n",
	} {
		renames, statements := migrations.AuditRoleIDRenames(injRoleCorpus(body))
		require.Equalf(t, 1, statements, "%s: оператор правки роли не сосчитан", name)
		require.Equalf(t, []string{"20991231000000_x.sql"}, renames, "%s: перевод id не узнан", name)
		f := migrations.RoleIDRenameFindings(renames, nil)
		require.Lenf(t, f, 1, "%s: перевод вне храповика оставил гейт зелёным", name)
		require.Containsf(t, f[0], "20991231000000_x.sql", "%s: находка без координаты", name)
	}
}

// Законные близнецы: правка роли без id и перевод в нижней половине — молчание.
func TestRoleIDRenameRatchet_LawfulTwinsAreSilent(t *testing.T) {
	renames, statements := migrations.AuditRoleIDRenames(injRoleCorpus(injRoleNameOnly))
	require.Equal(t, 1, statements, "правка роли без id обязана быть СОСЧИТАНА")
	require.Empty(t, renames, "правка имени роли названа переводом id")

	renames, _ = migrations.AuditRoleIDRenames(injRoleCorpus(injRoleRenameDown))
	require.Empty(t, renames, "нижняя половина названа переводом: откат о том, что в силе, не говорит")
}

// Названный перевод — молчание; запись храповика без перевода — находка.
func TestRoleIDRenameRatchet_RecordMatchesItsSubjectBothWays(t *testing.T) {
	renames, _ := migrations.AuditRoleIDRenames(injRoleCorpus(injRoleRename))
	require.Empty(t, migrations.RoleIDRenameFindings(renames, []string{"20991231000000_x.sql"}),
		"названный храповиком перевод подан находкой")

	f := migrations.RoleIDRenameFindings(nil, []string{"20991231000000_x.sql"})
	require.Len(t, f, 1, "запись храповика пережила свой предмет молча")
	require.Contains(t, f[0], "пережила свой предмет")
}
