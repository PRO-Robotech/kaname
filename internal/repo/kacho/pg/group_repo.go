// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// group_repo.go — pgxpool-impl для group.ReaderIface / WriterIface.
//
// Ban #10 (within-service refs — DB-уровень):
//   - FK groups_account_fk (23503).
//   - UNIQUE groups_account_name_unique (23505).
//   - AddMember: triггер group_members_member_exists_trg → 23503 если member
//     не существует (DB-уровень).
//   - AddMember идемпотентен (PK group_id+member_type+member_id) — ON CONFLICT DO NOTHING.
//   - RemoveMember идемпотентен (0 rows — не ошибка).
//   - Delete Group: atomic CAS WHERE NOT EXISTS на access_bindings
//     (subject_type='group'). group_members CASCADE автоматически чистится.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
)

type groupReader struct {
	tx pgx.Tx
}

const groupCols = "id, account_id, name, description, labels, created_at"

func (r *groupReader) Get(ctx context.Context, id domain.GroupID) (domain.Group, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM groups WHERE id = $1`, groupCols), string(id))
	g, err := scanGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Group{}, iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", id)
		}
		return domain.Group{}, mapErr(err, "", string(id))
	}
	return g, nil
}

func (r *groupReader) List(ctx context.Context, f group.ListFilter) ([]domain.Group, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // reject >max, no silent clamp
	if err != nil {
		return nil, "", err
	}
	conditions := []string{}
	args := []any{}
	argIdx := 1
	if f.AccountID != "" {
		conditions = append(conditions, fmt.Sprintf("account_id = $%d", argIdx))
		args = append(args, string(f.AccountID))
		argIdx++
	}
	if f.Filter != "" {
		if name, ok := parseNameFilter(f.Filter); ok {
			conditions = append(conditions, fmt.Sprintf("name = $%d", argIdx))
			args = append(args, name)
			argIdx++
		}
	}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}
	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	q := fmt.Sprintf(`SELECT %s FROM groups %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		groupCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// IsMember — single EXISTS on group_members for (group_id, member_type, member_id).
// Returns false (no error) when the triple does not exist; that includes
// the case where the group itself does not exist (no DB call needed beyond
// the EXISTS). Used by AccessBinding.ListBySubject to authorise group
// subjects: caller is allowed to enumerate bindings of a group iff member.
func (r *groupReader) IsMember(ctx context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) (bool, error) {
	var ok bool
	err := r.tx.QueryRow(ctx,
		`SELECT EXISTS(
		     SELECT 1 FROM group_members
		      WHERE group_id    = $1
		        AND member_type = $2
		        AND member_id   = $3
		 )`,
		string(groupID), string(memberType), string(memberID),
	).Scan(&ok)
	if err != nil {
		return false, mapErr(err, "Group.IsMember", string(groupID))
	}
	return ok, nil
}

// ListMembers — SELECT FROM group_members WHERE group_id = $1.
// Без pagination (members обычно ≤ ~hundreds).
func (r *groupReader) ListMembers(ctx context.Context, groupID domain.GroupID) ([]domain.GroupMember, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT group_id, member_type, member_id, added_at FROM group_members WHERE group_id = $1 ORDER BY added_at ASC`,
		string(groupID),
	)
	if err != nil {
		return nil, mapErr(err, "", string(groupID))
	}
	defer rows.Close()
	var out []domain.GroupMember
	for rows.Next() {
		var m domain.GroupMember
		if err := rows.Scan((*string)(&m.GroupID), (*string)(&m.MemberType), (*string)(&m.MemberID), &m.AddedAt); err != nil {
			return nil, mapErr(err, "", "")
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

type groupWriter struct {
	groupReader
}

func (w *groupWriter) Insert(ctx context.Context, g domain.Group) (domain.Group, error) {
	labelsJSON, err := marshalLabels(g.Labels)
	if err != nil {
		return domain.Group{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	now := time.Now().UTC()
	q := fmt.Sprintf(`
		INSERT INTO groups (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, groupCols)
	row := w.tx.QueryRow(ctx, q,
		string(g.ID), string(g.AccountID), string(g.Name), string(g.Description), labelsJSON, now,
	)
	out, err := scanGroup(row)
	if err != nil {
		return domain.Group{}, mapErr(err, "", string(g.Name))
	}
	return out, nil
}

func (w *groupWriter) Update(ctx context.Context, g domain.Group, updateMask []string) (domain.Group, error) {
	labelsJSON, err := marshalLabels(g.Labels)
	if err != nil {
		return domain.Group{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	mutableFields := map[string]bool{"name": true, "description": true, "labels": true}
	apply := map[string]bool{}
	if len(updateMask) == 0 {
		for k := range mutableFields {
			apply[k] = true
		}
	} else {
		for _, f := range updateMask {
			if !mutableFields[f] {
				return domain.Group{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument update_mask field %q", f)
			}
			apply[f] = true
		}
	}
	parts := []string{}
	args := []any{}
	idx := 1
	if apply["name"] {
		parts = append(parts, fmt.Sprintf("name = $%d", idx))
		args = append(args, string(g.Name))
		idx++
	}
	if apply["description"] {
		parts = append(parts, fmt.Sprintf("description = $%d", idx))
		args = append(args, string(g.Description))
		idx++
	}
	if apply["labels"] {
		parts = append(parts, fmt.Sprintf("labels = $%d", idx))
		args = append(args, labelsJSON)
	}
	if len(parts) == 0 {
		return w.Get(ctx, g.ID)
	}
	args = append(args, string(g.ID))
	q := fmt.Sprintf(`UPDATE groups SET %s WHERE id = $%d RETURNING %s`,
		strings.Join(parts, ", "), len(args), groupCols)
	row := w.tx.QueryRow(ctx, q, args...)
	out, err := scanGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Group{}, iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", g.ID)
		}
		return domain.Group{}, mapErr(err, "", string(g.Name))
	}
	return out, nil
}

// Delete — atomic CAS WHERE NOT EXISTS на access_bindings + access_binding_subjects
// (subject_type='group'). group_members CASCADE автоматически (FK
// group_members_group_fk ON DELETE CASCADE).
//
// The access_bindings guard covers the legacy subjects[0] projection; the
// access_binding_subjects guard covers subjects[1..N] — an independent grantee of a
// multi-subject binding (migration 0028) the subjects[0]-only guard missed (SEC r8,
// hard-rule #10). The concurrent delete-vs-add-subject window is closed at the DB
// level by the BEFORE DELETE trigger (migration 0050); this software guard is the
// fast common-case reject + canonical error text.
func (w *groupWriter) Delete(ctx context.Context, id domain.GroupID) error {
	const q = `
		WITH del AS (
			DELETE FROM groups g
			WHERE g.id = $1
			  AND NOT EXISTS (SELECT 1 FROM access_bindings         WHERE subject_type = 'group' AND subject_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM access_binding_subjects WHERE subject_type = 'group' AND subject_id = $1)
			RETURNING 1
		)
		SELECT
		  (SELECT count(*) FROM del)::int                                                                    AS deleted,
		  EXISTS(SELECT 1 FROM groups WHERE id = $1)                                                         AS group_exists,
		  (EXISTS(SELECT 1 FROM access_bindings         WHERE subject_type='group' AND subject_id = $1)
		   OR EXISTS(SELECT 1 FROM access_binding_subjects WHERE subject_type='group' AND subject_id = $1))  AS has_bindings
	`
	var (
		deleted                  int
		groupExists, hasBindings bool
	)
	err := w.tx.QueryRow(ctx, q, string(id)).Scan(&deleted, &groupExists, &hasBindings)
	if err != nil {
		return mapErr(err, "Group.Delete", string(id))
	}
	if deleted == 1 {
		return nil
	}
	if !groupExists {
		return iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", id)
	}
	if hasBindings {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"Group %s has active access bindings and cannot be deleted", id)
	}
	return iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", id)
}

// AddMember — INSERT ON CONFLICT (group_id, member_type, member_id) DO NOTHING.
// Идемпотентен: повторный AddMember — не ошибка.
// Триггер group_members_member_exists_trg валидирует existence member_id в
// users/service_accounts (23503 → FailedPrecondition).
func (w *groupWriter) AddMember(ctx context.Context, m domain.GroupMember) error {
	now := time.Now().UTC()
	_, err := w.tx.Exec(ctx, `
		INSERT INTO group_members (group_id, member_type, member_id, added_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (group_id, member_type, member_id) DO NOTHING`,
		string(m.GroupID), string(m.MemberType), string(m.MemberID), now,
	)
	if err != nil {
		return mapErr(err, "", string(m.MemberID))
	}
	return nil
}

// RemoveMember — DELETE. Идемпотентен (0 rows — не ошибка).
func (w *groupWriter) RemoveMember(ctx context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) error {
	_, err := w.tx.Exec(ctx, `
		DELETE FROM group_members
		WHERE group_id = $1 AND member_type = $2 AND member_id = $3`,
		string(groupID), string(memberType), string(memberID),
	)
	if err != nil {
		return mapErr(err, "", string(memberID))
	}
	return nil
}

func scanGroup(row scanner) (domain.Group, error) {
	var (
		g          domain.Group
		labelsJSON []byte
	)
	err := row.Scan(
		(*string)(&g.ID),
		(*string)(&g.AccountID),
		(*string)(&g.Name),
		(*string)(&g.Description),
		&labelsJSON,
		&g.CreatedAt,
	)
	if err != nil {
		return domain.Group{}, err
	}
	g.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.Group{}, err
	}
	return g, nil
}
