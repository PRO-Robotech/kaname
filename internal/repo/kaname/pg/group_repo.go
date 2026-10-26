// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
)

type groupReader struct {
	tx pgx.Tx
}

const groupCols = "id, account_id, name, description, labels, created_at"

// groupUpdateQ — оператор записи группы. СТАТИЧЕСКИЙ: набор колонок известен
// компилятору, применимость поля приезжает параметром (kacho#2065; разбор —
// `mutable_triplet_update.go`). `account_id` неизменяем и в перечень не входит —
// вызывающий отвергает его до записи.
const groupUpdateQ = `UPDATE groups SET` + mutableTripletSetSQL +
	` WHERE id = $1 RETURNING ` + groupCols

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
		// Whitelist `name="value"`; anything else is refused by name, never
		// accepted-and-ignored (kacho#445). The predicate is built from the parsed
		// expression, so the column follows the whitelist instead of being
		// restated here and drifting from it.
		ast, ferr := parseListFilter(f.Filter, "name")
		if ferr != nil {
			return nil, "", ferr
		}
		if ast != nil {
			frag, fargs := ast.ToSQL(argIdx)
			conditions = append(conditions, frag)
			args = append(args, fargs...)
			argIdx += len(fargs)
		}
	}
	// Курсор. Разобранный (After) имеет приоритет: путь, который его задаёт,
	// токена не передаёт вовсе, поэтому «оба заданы» здесь не встречается — но
	// порядок назван явно, чтобы это было свойством кода, а не совпадением.
	switch {
	case f.After != nil:
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, f.After.CreatedAt, f.After.ID)
		argIdx += 2
	case f.PageToken != "":
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	// Сужение набора КАНДИДАТОВ (задача kacho#645). Оно стоит здесь, в отборе строк, а
	// не после него: постфильтр по видимости теряет всякую группу, перед которой
	// лежит больше `page_size` невидимых предшественников — она до фильтра просто
	// не доезжает.
	//
	// nil — не сужать (администратор облака); непустой указатель с пустыми
	// наборами не называет ни одной строки и потому не пропускает ни одной.
	if f.Candidates != nil {
		conditions = append(conditions,
			fmt.Sprintf("(account_id = ANY($%d) OR id = ANY($%d))", argIdx, argIdx+1))
		args = append(args, nonNilStrings(f.Candidates.AccountIDs), nonNilStrings(f.Candidates.ObjectIDs))
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

// ListMembers — one page of group_members, ordered by the cursor (added_at,
// member_id) the continuation token encodes.
//
// member_id is the tie-break rather than the (member_type, member_id) pair the
// primary key carries: an id already names its own kind by prefix (usr / sva / grp),
// so it is unique within a group on its own, and a single-column tie-break is what
// the shared token encoding takes.
func (r *groupReader) ListMembers(ctx context.Context, groupID domain.GroupID, page group.MemberPage) ([]domain.GroupMember, string, error) {
	limit, err := effectivePageSize(int32(min(page.PageSize, maxListPageSize+1))) // #nosec G115 -- значение зажато проверенным диапазоном (не больше предела страницы плюс один), поэтому сужение типа переполнить нельзя
	if err != nil {
		return nil, "", err
	}

	args := []any{string(groupID)}
	cursor := ""
	if page.PageToken != "" {
		ts, id, terr := decodePageToken(page.PageToken)
		if terr != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		cursor = " AND (added_at, member_id) > ($2, $3)"
		args = append(args, ts, id)
	}
	args = append(args, limit+1)

	q := fmt.Sprintf(`SELECT group_id, member_type, member_id, added_at
		 FROM group_members
		 WHERE group_id = $1%s
		 ORDER BY added_at ASC, member_id ASC
		 LIMIT $%d`, cursor, len(args))

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", string(groupID))
	}
	defer rows.Close()
	var out []domain.GroupMember
	for rows.Next() {
		var m domain.GroupMember
		if err := rows.Scan((*string)(&m.GroupID), (*string)(&m.MemberType), (*string)(&m.MemberID), &m.AddedAt); err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var next string
	if int64(len(out)) > limit {
		last := out[limit-1]
		next = encodePageToken(last.AddedAt, string(last.MemberID))
		out = out[:limit]
	}
	return out, next, nil
}

// maxMembersInGrantSurface — верхняя граница состава, возвращаемого ОДНИМ
// перечислением выдач.
//
// Величина та же, что у страницы платформы: сумма составов не вправе быть
// больше того, что этот контракт и так согласен отдать одним ответом. Число
// намеренно совпадает с пределом страницы, а не выбрано отдельно, — иначе у
// одного ответа было бы две несогласованные границы.
const maxMembersInGrantSurface = maxListPageSize

// membersOfGroupsSQL — оператор состава, вынесенный КОНСТАНТОЙ ради того, чтобы
// проба замеряла ИМЕННО ЕГО.
//
// Предел выборки держит не форму ответа (её держит срез в Go), а СТОИМОСТЬ
// чтения: без него запрос читает весь состав названных групп, чтобы отдать
// первую тысячу. Утверждать это можно только по плану настоящего оператора —
// проба, переписавшая текст своей рукой, замеряла бы ДРУГОЙ запрос и осталась бы
// зелёной при снятом пределе.
const membersOfGroupsSQL = `
		SELECT group_id, member_type, member_id, added_at
		  FROM group_members
		 WHERE group_id = ANY($1)
		 ORDER BY group_id ASC, added_at ASC, member_id ASC
		 LIMIT $2`

// MembersOfGroups — состав нескольких групп одним обращением, ограниченный
// сверху, с честным признаком усечения.
//
// Ключ `group_members_pkey (group_id, member_type, member_id)` ведущей колонкой
// обслуживает сравнение `group_id = ANY(...)` НАПРЯМУЮ: колонка идёт голой, без
// вычисления вокруг неё, поэтому строки чужих групп не читаются вовсе. Порядок
// задан явно и совпадает с порядком предела: без него «первые N» означало бы
// «какие достались».
//
// Читается на одну строку больше предела. Эта строка НЕ отдаётся — она отвечает
// на единственный вопрос, на который иначе ответить нечем: усечён ли ответ, и с
// какой группы. Группы строго ДО неё возвращены целиком; её собственная группа и
// все запрошенные после неё — неполны либо не читались вовсе, и именно они
// называются вторым возвратом.
func (r *groupReader) MembersOfGroups(ctx context.Context, groupIDs []domain.GroupID) ([]domain.GroupMember, []domain.GroupID, error) {
	if len(groupIDs) == 0 {
		// Пустой вход — пустой ответ. Ни в коем случае не «все группы»: тот же
		// запрос без предиката вернул бы состав всего кластера.
		return nil, nil, nil
	}
	ids := make([]string, 0, len(groupIDs))
	for _, id := range groupIDs {
		if id == "" {
			continue
		}
		ids = append(ids, string(id))
	}
	if len(ids) == 0 {
		return nil, nil, nil
	}
	sort.Strings(ids)

	rows, err := r.tx.Query(ctx, membersOfGroupsSQL, ids, maxMembersInGrantSurface+1)
	if err != nil {
		return nil, nil, mapErr(err, "", "")
	}
	defer rows.Close()
	out := make([]domain.GroupMember, 0, len(ids))
	for rows.Next() {
		var m domain.GroupMember
		if err := rows.Scan((*string)(&m.GroupID), (*string)(&m.MemberType), (*string)(&m.MemberID), &m.AddedAt); err != nil {
			return nil, nil, mapErr(err, "", "")
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err, "", "")
	}
	if int64(len(out)) <= maxMembersInGrantSurface {
		return out, nil, nil
	}

	// Опережающая строка прочитана — значит предел достигнут. Её группа и есть
	// первая, чей состав отдать целиком не удалось.
	boundary := string(out[maxMembersInGrantSurface].GroupID)
	out = out[:maxMembersInGrantSurface]
	incomplete := make([]domain.GroupID, 0, len(ids))
	for _, id := range ids {
		if id >= boundary {
			incomplete = append(incomplete, domain.GroupID(id))
		}
	}
	return out, incomplete, nil
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
	args, changed, err := mutableTripletUpdateArgs(
		string(g.ID), string(g.Name), string(g.Description), labelsJSON, updateMask)
	if err != nil {
		return domain.Group{}, err
	}
	if !changed {
		return w.Get(ctx, g.ID)
	}
	row := w.tx.QueryRow(ctx, groupUpdateQ, args...)
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
//
// Считаются только ДЕЙСТВУЮЩИЕ выдачи (`revoked_at IS NULL`) — то же условие, что
// у человека, сервисного аккаунта и функции триггера (kaname#664, Р10):
// отозванная выдача — история, и текст «active» обязан быть правдой.
func (w *groupWriter) Delete(ctx context.Context, id domain.GroupID) error {
	const q = `
		WITH del AS (
			DELETE FROM groups g
			WHERE g.id = $1
			  AND NOT EXISTS (SELECT 1 FROM access_bindings b WHERE b.subject_type = 'group' AND b.subject_id = $1 AND b.revoked_at IS NULL)
			  AND NOT EXISTS (SELECT 1 FROM access_binding_subjects s JOIN access_bindings b ON b.id = s.binding_id WHERE s.subject_type = 'group' AND s.subject_id = $1 AND b.revoked_at IS NULL)
			RETURNING 1
		)
		SELECT
		  (SELECT count(*) FROM del)::int                                                    AS deleted,
		  EXISTS(SELECT 1 FROM groups WHERE id = $1)                                         AS group_exists,
		  (EXISTS(SELECT 1 FROM access_bindings b
		           WHERE b.subject_type = 'group' AND b.subject_id = $1 AND b.revoked_at IS NULL)
		   OR EXISTS(SELECT 1 FROM access_binding_subjects s JOIN access_bindings b ON b.id = s.binding_id
		              WHERE s.subject_type = 'group' AND s.subject_id = $1 AND b.revoked_at IS NULL)) AS has_bindings
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

// RequireMemberOfGroupAccount — участник принадлежит аккаунту группы (Д-3
// приёмки role-rights-stay-within-what-is-named.md, kaname#1037): учётка — своей
// колонкой `account_id`, человек — строкой `memberships` пары «человек, аккаунт
// группы» в состоянии ACTIVE (как Д6 делегирования). Выдача на аккаунт и владение
// им членством не являются; приглашённый (PENDING) — не участник.
//
// Отказ — ровно та форма, что у несуществующего участника (`fkText`, общий текст
// без вида и идентификатора): иначе ответ различал бы «такого нет» и «такой есть
// в другом аккаунте» — оракул существования чужих субъектов.
//
// Строка, на которой держится ответ, берётся под FOR SHARE в транзакции
// вставки: снятие членства (учётки) либо смена его состояния ждут её коммита, а
// после ожидания условие перечитывается на новой версии строки. Поэтому участник,
// чьё членство снято конкурентно, либо не проходит проверку, либо уже в группе к
// моменту снятия — третьего порядка нет.
func (w *groupWriter) RequireMemberOfGroupAccount(ctx context.Context, m domain.GroupMember) error {
	var (
		q    string
		args = []any{string(m.GroupID), string(m.MemberID)}
	)
	switch m.MemberType {
	case domain.SubjectTypeUser:
		q = `SELECT 1 FROM memberships ms
		       JOIN groups g ON g.account_id = ms.account_id
		      WHERE g.id = $1 AND ms.user_id = $2 AND ms.state = $3
		      FOR SHARE OF ms`
		args = append(args, string(domain.MembershipStateActive))
	case domain.SubjectTypeServiceAccount:
		q = `SELECT 1 FROM service_accounts sa
		       JOIN groups g ON g.account_id = sa.account_id
		      WHERE g.id = $1 AND sa.id = $2
		      FOR SHARE OF sa`
	default:
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument member_type %s", m.MemberType)
	}
	var one int
	err := w.tx.QueryRow(ctx, q, args...).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return iamerr.Wrapf(iamerr.ErrReferenceMissing, "%s", referenceMissingText)
	}
	if err != nil {
		return mapErr(err, "", string(m.MemberID))
	}
	return nil
}

// AddMember — INSERT ON CONFLICT (group_id, member_type, member_id) DO NOTHING.
// Идемпотентен: повторный AddMember — не ошибка.
// Триггер group_members_member_exists_trg валидирует existence member_id в
// users/service_accounts (23503 → FailedPrecondition). Принадлежность участника
// аккаунту группы — RequireMemberOfGroupAccount, той же транзакцией до вставки.
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
		return mapErr(err, "Group.RemoveMember", string(memberID))
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
