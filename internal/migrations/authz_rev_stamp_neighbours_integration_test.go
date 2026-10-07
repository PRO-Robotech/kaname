// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authz_rev_stamp_neighbours_integration_test.go — триггер версии прав видит
// ОКОНЧАТЕЛЬНУЮ строку (приёмка NTF-3, Р30 «Колонка версии прав»; полоса K1).
//
// # Предмет
//
// Триггер `<таблица>_…authz_rev…` сравнивает `NEW` с `OLD` по значимым
// столбцам. Postgres исполняет BEFORE-триггеры одного вида в порядке ИМЁН, и
// триггер, исполненный ПОСЛЕ версии и переписавший значимый столбец, прошёл бы
// мимо неё: право изменилось бы, а версия осталась прежней — то есть ограда
// пропустила бы изменение права молча.
//
// Поэтому соседи, исполняемые позже, — закрытый перечень с доводом у каждого:
// сосед, заведённый завтра, требует решения, а не проходит незамеченным. Сегодня
// в перечне один сосед: триггер снятия отметки подтверждения адреса на `users`.
// Его место «последним» держит его собственная проба (Н2,
// `TestIntegration_AddressVerificationTriggerHasNoLaterNeighbour`), и он пишет
// только отметку подтверждения — служебный столбец. Что это так, проба ниже
// утверждает поведением, а не словами: смена адреса, на которой он срабатывает,
// не сдвигает версию и не меняет ни одного значимого столбца.
package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stampLaterNeighbours — объявленные соседи: таблица → триггер → довод.
var stampLaterNeighbours = map[string]map[string]string{
	"users": {
		"users_email_change_drops_verification": "пишет только email_verified_at (служебный столбец); " +
			"последним его держит Н2 — смена адреса обязана снять отметку после всех прочих",
	},
}

// stampNeighbour — BEFORE UPDATE-триггер таблицы, исполняемый после триггера
// версии.
type stampNeighbour struct{ table, stamp, trigger string }

// stampNeighbours — перепись: на каждой таблице с триггером версии прав —
// построчные BEFORE UPDATE-триггеры, чьё имя сортируется после его имени.
func stampNeighbours(t *testing.T, ctx context.Context, db *sql.DB) (tables int, out []stampNeighbour) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		WITH stamp AS (
		  SELECT tg.tgrelid, tg.tgname
		    FROM pg_trigger tg
		    JOIN pg_proc p ON p.oid = tg.tgfoid
		   WHERE NOT tg.tgisinternal
		     AND p.pronamespace = 'kaname'::regnamespace
		     AND p.proname LIKE '%\_authz\_rev\_stamp')
		SELECT c.relname, s.tgname, coalesce(n.tgname, '')
		  FROM stamp s
		  JOIN pg_class c ON c.oid = s.tgrelid
		  LEFT JOIN pg_trigger n
		         ON n.tgrelid = s.tgrelid AND NOT n.tgisinternal
		        AND (n.tgtype & 1) = 1 AND (n.tgtype & 2) = 2 AND (n.tgtype & 16) = 16
		        AND n.tgname COLLATE "C" > s.tgname COLLATE "C"
		 ORDER BY 1, 3`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	for rows.Next() {
		var n stampNeighbour
		require.NoError(t, rows.Scan(&n.table, &n.stamp, &n.trigger))
		seen[n.table] = true
		if n.trigger != "" {
			out = append(out, n)
		}
	}
	require.NoError(t, rows.Err())
	return len(seen), out
}

// stampNeighbourFindings — соседи вне перечня и записи перечня без соседа.
func stampNeighbourFindings(found []stampNeighbour, declared map[string]map[string]string) []string {
	var findings []string
	have := map[string]bool{}
	for _, n := range found {
		have[n.table+"/"+n.trigger] = true
		if _, ok := declared[n.table][n.trigger]; !ok {
			findings = append(findings, fmt.Sprintf("%s: BEFORE UPDATE-триггер %s исполняется после %s и может "+
				"переписать значимый столбец мимо версии прав — нужно решение: переименовать его в место до "+
				"версии либо объявить соседом с доводом и пробой", n.table, n.trigger, n.stamp))
		}
	}
	for table, trigs := range declared {
		for trig := range trigs {
			if !have[table+"/"+trig] {
				findings = append(findings, fmt.Sprintf("%s: объявленный сосед %s после триггера версии не "+
					"найден — запись перечня без предмета", table, trig))
			}
		}
	}
	sort.Strings(findings)
	return findings
}

func stampWorld(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	if testing.Short() {
		t.Skip("интеграционная проба: нужен Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx, freshIamSchema(t)
}

// TestAuthzRevStampHasOnlyDeclaredLaterNeighbours — перепись соседей на дереве.
func TestAuthzRevStampHasOnlyDeclaredLaterNeighbours(t *testing.T) {
	ctx, db := stampWorld(t)
	tables, found := stampNeighbours(t, ctx, db)
	t.Logf("перепись: таблиц с триггером версии прав %d, соседей после него %d: %v", tables, len(found), found)
	require.NotZero(t, tables, "триггеров версии прав 0 — перепись не читает каталог")
	require.Empty(t, stampNeighbourFindings(found, stampLaterNeighbours))
}

// TestAuthzRevStampNeighbourInjection — инъекция: на привязке заведён
// BEFORE UPDATE-триггер, чьё имя сортируется после триггера версии и который
// на смене защиты от удаления (служебный столбец) переписывает срок, — гейт
// называет его; внесённое различие показывает, почему правило нужно: служебная
// правка, на которой сосед сменил срок, оставляет версию прав прежней. Близнец по одному факту: тот же триггер с именем,
// сортирующимся ДО версии, — гейт молчит, и версия движется.
func TestAuthzRevStampNeighbourInjection(t *testing.T) {
	const fn = `CREATE FUNCTION kaname.arv_probe_rewrite_expiry() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		  IF NEW.deletion_protection IS DISTINCT FROM OLD.deletion_protection THEN
		    NEW.expires_at := now() + interval '99 days';
		  END IF;
		  RETURN NEW;
		END $$`
	for _, c := range []struct {
		name, trigger string
		wantFinding   bool
	}{
		{"сосед после версии", "access_bindings_zzz_arv_probe_trg", true},
		{"близнец: тот же сосед до версии", "access_bindings_aaa_arv_probe_trg", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, db := stampWorld(t)
			_, err := db.ExecContext(ctx, fn)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `CREATE TRIGGER `+c.trigger+` BEFORE UPDATE ON kaname.access_bindings
				FOR EACH ROW EXECUTE FUNCTION kaname.arv_probe_rewrite_expiry()`)
			require.NoError(t, err)

			_, found := stampNeighbours(t, ctx, db)
			findings := stampNeighbourFindings(found, stampLaterNeighbours)
			named := strings.Contains(strings.Join(findings, "\n"), c.trigger)
			require.Equalf(t, c.wantFinding, named, "находки: %v", findings)

			// Внесённое различие поведением: служебная правка привязки, на
			// которой сосед переписал срок.
			seedXID := seedFencedWorld(t, ctx, db)
			xid := updateInOwnTx(t, ctx, db, fencedRow{table: "kaname.access_bindings",
				where: "id = '" + arvBinding + "'"}, "deletion_protection = NOT deletion_protection")
			var expires sql.NullTime
			require.NoError(t, db.QueryRowContext(ctx,
				`SELECT expires_at FROM kaname.access_bindings WHERE id = $1`, arvBinding).Scan(&expires))
			require.True(t, expires.Valid, "фикстура: сосед не переписал срок")
			rev := authzRevOf(t, ctx, db, "kaname.access_bindings", "id = '"+arvBinding+"'")
			if c.wantFinding {
				require.Equal(t, seedXID, rev, "сосед после версии: срок сменился, а версия прежняя — ради этого правило")
			} else {
				require.Equal(t, xid, rev, "сосед до версии: смену срока версия видит")
			}
		})
	}
}

// TestAuthzRevStampDeclaredNeighbourWritesNoSignificantColumn — довод
// объявленного соседа поведением: смена адреса, на которой срабатывает снятие
// отметки подтверждения, не меняет ни версии, ни значимых столбцов строки
// `users`, а отметку снимает (положительный контроль срабатывания соседа).
func TestAuthzRevStampDeclaredNeighbourWritesNoSignificantColumn(t *testing.T) {
	ctx, db := stampWorld(t)
	seedXID := seedFencedWorld(t, ctx, db)
	where := "id = '" + arvMember + "'"
	_, err := db.ExecContext(ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE `+where)
	require.NoError(t, err, "фикстура: отметка подтверждения не поставлена")

	significant := func() string {
		var s string
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT row(id, account_id, invite_status, labels)::text FROM kaname.users WHERE `+where).Scan(&s))
		return s
	}
	before := significant()
	updateInOwnTx(t, ctx, db, fencedRow{table: "kaname.users", where: where}, "email = 'arv-member-new@probe.invalid'")

	var verified sql.NullTime
	require.NoError(t, db.QueryRowContext(ctx, `SELECT email_verified_at FROM kaname.users WHERE `+where).Scan(&verified))
	require.False(t, verified.Valid, "фикстура: сосед не сработал — отметка пережила смену адреса")
	require.Equal(t, before, significant(), "сосед сменил значимый столбец строки users")
	require.Equal(t, seedXID, authzRevOf(t, ctx, db, "kaname.users", where),
		"смена адреса со снятием отметки сдвинула версию прав")
}
