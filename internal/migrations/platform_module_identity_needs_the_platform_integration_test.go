// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_module_identity_needs_the_platform_integration_test.go — установка
// службы БЕЗ платформы не заводит служебных учёток чужого продукта (#2452).
//
// # Что утверждается — НАБЛЮДАЕМОЕ, а не форма файла
//
// Проба не читает текст миграции. Она проигрывает цепочку целиком в пустую базу
// — это и есть самостоятельная установка: доставки манифестов у неё нет, чужих
// модулей нет, всё, что окажется в таблицах, положила цепочка, — и спрашивает
// живые строки. Разбор SQL был бы распознавателем: форму записи, которой он не
// знает, он пропускает МОЛЧА, и молчание неотличимо от согласия.
//
// # Владелец выводится ИМЕНЕМ, и это не соглашение автора
//
// Служебная запись модуля платформы называется `kacho-<служба>`, служба — из
// закрытого словаря `pkg/platformmodules`. То же правило читает сверка посева
// (`internal/moduleseedparity`), и второй его копии здесь не заводится: имя
// строится из словаря, а не выписывается перечнем.
//
// Запись, чьё имя этому не отвечает, модуля-владельца НЕ имеет by construction —
// это личности самой службы (`kacho-bootstrap-admin`) и край платформы
// (`kacho-api-gateway`, у которого манифеста нет вовсе). Их эта проба не судит,
// и почему — сказано у положительного близнеца ниже.
//
// # Положительный близнец ОБЯЗАТЕЛЕН
//
// Утверждение «модульных учёток ноль» зеленеет на ПУСТОЙ таблице, то есть на
// сорванной цепочке миграций, — и отличить это от исполненного требования нечем.
// Поэтому рядом стоит требование, чтобы собственные личности службы читались:
// оно краснеет ровно там, где отрицание зеленело бы вхолостую.
package migrations_test

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/corelib/platformmodules"
)

// moduleIdentityPrefix — приставка, по которой имя строки переводится в модуль.
const moduleIdentityPrefix = "kacho-"

// moduleIdentityNames — имена служебных записей модулей платформы, ВЫВЕДЕННЫЕ из
// словаря платформы. Перечнем они здесь не выписываются: выписанный разошёлся бы
// со словарём молча, и новый модуль оказался бы вне наблюдения.
func moduleIdentityNames() map[string]string {
	out := make(map[string]string, len(platformmodules.Services()))
	for _, svc := range platformmodules.Services() {
		if svc == "iam" {
			// Служба доступа — не чужой продукт: её собственная личность под
			// этот вердикт не подпадает ни при каком исходе.
			continue
		}
		out[moduleIdentityPrefix+svc] = svc
	}
	return out
}

// standaloneIdentityCensus — объём осмотренного вместе с находками: «модульных
// записей ноль» обязано быть отличимо от «прочитано ноль».
type standaloneIdentityCensus struct {
	rowsRead   int
	ownerless  []string
	moduleRows []string
}

// TestPlatformModuleIdentitiesNeedThePlatform — самостоятельная установка не
// несёт ни одной служебной учётки модуля платформы.
func TestPlatformModuleIdentitiesNeedThePlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: вердикт даёт ПРОГОН цепочки в пустую базу, а не разбор SQL")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))

	owners := moduleIdentityNames()
	census := readStandaloneIdentities(t, db, owners)

	sort.Strings(census.ownerless)
	sort.Strings(census.moduleRows)
	t.Logf("перепись: служебных записей прочитано %d · без модуля-владельца %d (%s) · "+
		"принадлежащих модулю платформы %d · словарь платформы знает модулей %d",
		census.rowsRead, len(census.ownerless), strings.Join(census.ownerless, ", "),
		len(census.moduleRows), len(owners))

	require.NotZero(t, census.rowsRead,
		"служебных записей прочитано ноль — цепочка не доиграна либо чтение смотрит не туда; "+
			"«модульных записей ноль» означало бы «прочитано ноль»")
	require.NotEmpty(t, census.ownerless,
		"собственных личностей службы не прочитано ни одной — отрицание ниже зеленело бы вхолостую")

	require.Emptyf(t, census.moduleRows,
		"самостоятельная установка завела %d служебную(ых) учётку(ок) модуля платформы:\n  %s\n\n"+
			"Строка, обязанная существовать у арендатора, который развернул службу У СЕБЯ, —\n"+
			"справочник; всё остальное — посев, и заводит его установка платформы, а не\n"+
			"цепочка миграций службы (`data-integrity.md` §«Данные СТЕНДА заводятся посевом»).",
		len(census.moduleRows), strings.Join(census.moduleRows, "\n  "))
}

// TestPlatformModuleIdentitiesLeaveNothingBehind — вместе с учёткой не остаётся
// ни одной строки, которая на неё ссылается.
//
// Отдельная проба, а не ещё одно утверждение в первой: предметы разные. Первая
// говорит о ЛИЧНОСТЯХ, эта — о ссылках на них. Снятие личности при живой ссылке
// оставляет членство и выдачу висеть на записи, которой нет, и такое состояние
// снаружи выглядит исправным.
func TestPlatformModuleIdentitiesLeaveNothingBehind(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: вердикт даёт ПРОГОН цепочки в пустую базу")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	owners := moduleIdentityNames()

	ids := moduleIdentityIDs(t, db, owners)

	type ref struct {
		what  string
		query string
	}
	refs := []ref{
		{"членство в группе", `SELECT count(*) FROM kaname.group_members
			 WHERE member_type = 'service_account' AND member_id = ANY($1)`},
		{"выдача", `SELECT count(*) FROM kaname.access_bindings
			 WHERE subject_type = 'service_account' AND subject_id = ANY($1)`},
		{"субъект выдачи", `SELECT count(*) FROM kaname.access_binding_subjects
			 WHERE subject_type = 'service_account' AND subject_id = ANY($1)`},
		{"прямой факт отношения", `SELECT count(*) FROM kaname.relation_fact
			 WHERE subject = ANY($1)`},
		{"строка журнала прав", `SELECT count(*) FROM kaname.fga_outbox
			 WHERE payload ->> 'user' = ANY($1)`},
		{"носитель потолка", `SELECT count(*) FROM kaname.project_resource_quotas
			 WHERE carrier_type = 'iam.serviceAccount' AND carrier_id = ANY($1)`},
	}

	subjects := make([]string, 0, len(ids))
	for _, id := range ids {
		subjects = append(subjects, "service_account:"+id)
	}

	var found []string
	for _, r := range refs {
		arg := any(ids)
		if strings.Contains(r.query, "relation_fact") || strings.Contains(r.query, "fga_outbox") {
			arg = any(subjects)
		}
		var n int
		require.NoError(t, db.QueryRow(r.query, arg).Scan(&n), r.what)
		t.Logf("перепись: %s — строк на модульные учётки %d", r.what, n)
		if n > 0 {
			found = append(found, fmt.Sprintf("%s: %d", r.what, n))
		}
	}

	require.Emptyf(t, found,
		"самостоятельная установка держит строки, ссылающиеся на служебные учётки модулей: %s\n"+
			"(учёток найдено %d)", strings.Join(found, " · "), len(ids))
}

// readStandaloneIdentities читает ВСЕ служебные записи базы и раскладывает их на
// две стопки: с модулем-владельцем и без него.
func readStandaloneIdentities(t *testing.T, db *sql.DB, owners map[string]string) standaloneIdentityCensus {
	t.Helper()
	rows, err := db.Query(`SELECT sa.id, sa.name, a.name
	                         FROM kaname.service_accounts sa
	                         JOIN kaname.accounts a ON a.id = sa.account_id`)
	require.NoError(t, err, "чтение служебных записей не состоялось — вердикт беспредметен")
	defer func() { _ = rows.Close() }()

	var census standaloneIdentityCensus
	for rows.Next() {
		var id, name, account string
		require.NoError(t, rows.Scan(&id, &name, &account))
		census.rowsRead++
		if module, ok := owners[name]; ok {
			census.moduleRows = append(census.moduleRows,
				fmt.Sprintf("%s/%s (id %s) — модуль %q", account, name, id, module))
			continue
		}
		census.ownerless = append(census.ownerless, account+"/"+name)
	}
	require.NoError(t, rows.Err())
	return census
}

// moduleIdentityIDs — идентификаторы модульных записей, если они ещё есть.
func moduleIdentityIDs(t *testing.T, db *sql.DB, owners map[string]string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT id, name FROM kaname.service_accounts`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id, name string
		require.NoError(t, rows.Scan(&id, &name))
		if _, ok := owners[name]; ok {
			ids = append(ids, id)
		}
	}
	require.NoError(t, rows.Err())
	sort.Strings(ids)
	return ids
}
