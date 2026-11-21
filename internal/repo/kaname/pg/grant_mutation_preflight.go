// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Закрытые профили соответствуют реальным signed kind/purpose. SQL не меняет
// decision_at: caller обязан перепроверить источники ПОСЛЕ всех этих ожиданий.
func grantMutationPreflight(ctx context.Context, tx pgx.Tx, profile string) error {
	_, err := tx.Exec(ctx, `SELECT kaname.authority_grant_mutation_preflight($1)`, profile)
	return err
}

// Exact proposed subjects уже нормализованы до fences. subject_ref_exists
// берёт те же KEY SHARE при INSERT parent и набора; class не имеет строки.
func bindingDecisionPreflight(ctx context.Context, tx pgx.Tx, b domain.AccessBinding, create bool) error {
	if err := grantMutationPreflight(ctx, tx, "binding"); err != nil {
		return err
	}
	if !create {
		return nil
	}
	subjects, err := domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
	if err != nil {
		return err
	}
	// NormalizeSubjects может вернуть исходный backing array: canonical primary
	// и ordinal не меняются ради порядка блокировок. Сортируется только копия.
	subjects = slices.Clone(subjects)
	slices.SortFunc(subjects, func(a, b domain.Subject) int {
		if c := strings.Compare(string(a.Type), string(b.Type)); c != 0 {
			return c
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	for _, s := range subjects {
		if s.Type == domain.SubjectTypeSystemClass {
			if s.ID != "anonymous" && s.ID != "authenticated" {
				return kaname.ErrInvalidAuthorityFencePlan
			}
			continue
		}
		if err := grantPrincipalPrelockRow(ctx, tx, string(s.Type), string(s.ID)); err != nil {
			// Нет строки именно запрошенного типа: такой получатель не может
			// принять новую выдачу. Это только отказ, не authority proof до
			// final clock. Не превращаем постоянный typed mismatch в три retry.
			if errors.Is(err, pgx.ErrNoRows) {
				return iamerr.ErrPermissionDenied
			}
			return err
		}
	}
	return ctx.Err()
}

// GD delegate сохраняет прежний контракт классификации: Binding recipient
// admission выше не меняет retry/ошибки других callers этого prelock.
func grantPrincipalPrelock(ctx context.Context, tx pgx.Tx, kind, id string) error {
	err := grantPrincipalPrelockRow(ctx, tx, kind, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return kaname.ErrAuthorityClassificationChanged
	}
	return err
}

func grantPrincipalPrelockRow(ctx context.Context, tx pgx.Tx, kind, id string) error {
	table, err := grantPrincipalTable(kind)
	if err != nil {
		return err
	}
	var found int
	return tx.QueryRow(ctx, `SELECT 1 FROM `+table+` WHERE id=$1 FOR KEY SHARE`, id).Scan(&found)
}

func grantPrincipalTable(kind string) (string, error) {
	switch kind {
	case "user":
		return "kaname.users", nil
	case "service_account":
		return "kaname.service_accounts", nil
	case "group":
		return "kaname.groups", nil
	default:
		return "", kaname.ErrInvalidAuthorityFencePlan
	}
}

// Нормализованный полный набор ограничен публичным cap32. Читаем только
// existence без row locks и без allow. Иначе absent typed epoch key породил
// бы 40001 ещё до позднего FK preflight. Счётчики возвращаются в общий budget.
func bindingRecipientDiscovery(ctx context.Context, tx pgx.Tx, subjects []domain.Subject) (rows, reads int, err error) {
	if len(subjects) == 0 || len(subjects) > domain.MaxSubjectsPerBinding {
		return 0, 0, kaname.ErrInvalidAuthorityFencePlan
	}
	for _, subject := range subjects {
		if err = ctx.Err(); err != nil {
			return rows, reads, err
		}
		if subject.Validate() != nil {
			return rows, reads, kaname.ErrInvalidAuthorityFencePlan
		}
		if subject.IsSystemClass() {
			continue
		}
		table, e := grantPrincipalTable(string(subject.Type))
		if e != nil {
			return rows, reads, e
		}
		var found int
		reads++
		err = tx.QueryRow(ctx, `SELECT 1 FROM `+table+` WHERE id=$1`, string(subject.ID)).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return rows, reads, iamerr.ErrPermissionDenied
		}
		if err != nil {
			return rows, reads, err
		}
		rows++
	}
	return rows, reads, ctx.Err()
}

// В RR сохраняются физические identities всех actual children до fences.
// Только три постоянных таблицы, keyset pages; client не задаёт SQL/table.
var grantChildTables = [...]string{
	"kaname.access_binding_emitted_tuples",
	"kaname.access_binding_subjects",
	"kaname.access_binding_target_members",
}

func createGrantChildSpool(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `CREATE TEMP TABLE kaname_grant_child_stage(seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,table_index integer NOT NULL,binding_id text NOT NULL,row_tid tid NOT NULL,row_xmin text NOT NULL) ON COMMIT PRESERVE ROWS`)
	return err
}
func captureGrantChildren(ctx context.Context, tx pgx.Tx, id domain.AccessBindingID) error {
	for index, table := range grantChildTables {
		cursor := "(0,0)"
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT ctid::text,xmin::text FROM `+table+` WHERE binding_id=$1 AND ctid>$2::tid ORDER BY ctid LIMIT $3`, string(id), cursor, bindingStagePage)
			if err != nil {
				return err
			}
			type identity struct{ tid, xmin string }
			var page []identity
			for rows.Next() {
				var row identity
				if err = rows.Scan(&row.tid, &row.xmin); err != nil {
					rows.Close()
					return err
				}
				page = append(page, row)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, row := range page {
				if _, err = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_grant_child_stage(table_index,binding_id,row_tid,row_xmin) VALUES($1,$2,$3::tid,$4)`, index, string(id), row.tid, row.xmin); err != nil {
					return err
				}
				cursor = row.tid
			}
			if len(page) < bindingStagePage {
				break
			}
		}
	}
	return nil
}
func lockGrantChildren(ctx context.Context, tx pgx.Tx) error {
	var after int64
	for {
		rows, err := tx.Query(ctx, `SELECT seq,table_index,binding_id,row_tid::text,row_xmin FROM pg_temp.kaname_grant_child_stage WHERE seq>$1 ORDER BY seq LIMIT $2`, after, bindingStagePage)
		if err != nil {
			return err
		}
		type identity struct {
			seq                int64
			index              int
			binding, tid, xmin string
		}
		var page []identity
		for rows.Next() {
			var row identity
			if err = rows.Scan(&row.seq, &row.index, &row.binding, &row.tid, &row.xmin); err != nil {
				rows.Close()
				return err
			}
			page = append(page, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, row := range page {
			if row.index < 0 || row.index >= len(grantChildTables) {
				return kaname.ErrInvalidAuthorityFencePlan
			}
			var found int
			err = tx.QueryRow(ctx, `SELECT 1 FROM `+grantChildTables[row.index]+` WHERE binding_id=$1 AND ctid=$2::tid AND xmin::text=$3 FOR UPDATE`, row.binding, row.tid, row.xmin).Scan(&found)
			if errors.Is(err, pgx.ErrNoRows) {
				return kaname.ErrAuthorityClassificationChanged
			}
			if err != nil {
				return err
			}
			after = row.seq
		}
		if len(page) < bindingStagePage {
			return ctx.Err()
		}
	}
}

// Обход только подготовленных commands, не новой inventory под fences.
// Дочерние existing rows уже locked по RR identities; здесь fold и role FK
// для новых members, которые ещё не существовали в snapshot.
func prelockBindingCommands(ctx context.Context, tx pgx.Tx) error {
	for phase := 0; phase < 2; phase++ {
		var after int64
		for {
			rows, err := tx.Query(ctx, `SELECT seq,body FROM pg_temp.kaname_binding_stage WHERE phase=$1 AND seq>$2 ORDER BY seq LIMIT $3`, phase, after, bindingStagePage)
			if err != nil {
				return err
			}
			var commands []reconcile.BindingCommand
			for rows.Next() {
				var raw []byte
				if err = rows.Scan(&after, &raw); err != nil {
					rows.Close()
					return err
				}
				var c reconcile.BindingCommand
				if err = json.Unmarshal(raw, &c); err != nil {
					rows.Close()
					return err
				}
				commands = append(commands, c)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, c := range commands {
				switch c.Kind {
				case "members":
					for _, m := range c.Members {
						var found int
						if err = tx.QueryRow(ctx, `SELECT 1 FROM kaname.roles WHERE id=$1 AND live FOR KEY SHARE`, string(m.RoleID)).Scan(&found); err != nil {
							return err
						}
					}
				case "write", "delete":
					for _, tuple := range c.Tuples {
						typ, id, ok := strings.Cut(tuple.Object, ":")
						if !ok || typ == "" || id == "" {
							return kaname.ErrInvalidAuthorityFencePlan
						}
						subject := tuple.User
						if c.Kind == "delete" && subject == "user:*" {
							subject = "system_class:authenticated"
							if tuple.Relation == "v_get" {
								subject = "system_class:anonymous"
							}
						}
						if _, err = tx.Exec(ctx, `SELECT 1 FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 FOR UPDATE`, typ, id, tuple.Relation, subject); err != nil {
							return err
						}
					}
				case "record", "forget", "member_delete", "audit":
				default:
					return kaname.ErrInvalidAuthorityFencePlan
				}
			}
			if len(commands) < bindingStagePage {
				break
			}
		}
	}
	return ctx.Err()
}
