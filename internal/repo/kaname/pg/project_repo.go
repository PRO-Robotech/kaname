// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// project_repo.go — pgxpool-impl для project.ReaderIface / WriterIface.
//
// Ban #10 (within-service refs — DB-уровень):
//   - FK projects_account_fk на accounts(id) ON DELETE RESTRICT (23503).
//   - UNIQUE projects_account_name_unique (account_id, name) (23505).
//   - FK roles_project_fk на projects(id) ON DELETE RESTRICT (23503) — запасной
//     упор охраны непустоты в `Delete` (см. `projectDeleteQ`).

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
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
)

// projectReader — Get/List/CountByAccount поверх pgx.Tx.
type projectReader struct {
	tx pgx.Tx
}

const projectCols = "id, account_id, name, description, labels, created_at"

// projectUpdateQ — оператор записи проекта. СТАТИЧЕСКИЙ: набор колонок известен
// компилятору, применимость поля приезжает параметром (#2065; разбор —
// `mutable_triplet_update.go`). `account_id` неизменяем и в перечень не входит —
// вызывающий отвергает его до записи.
const projectUpdateQ = `UPDATE projects SET` + mutableTripletSetSQL +
	` WHERE id = $1 RETURNING ` + projectCols

// Get — Kachō contract: well-formed-но-несуществующий → NotFound "Project <id> not found".
func (r *projectReader) Get(ctx context.Context, id domain.ProjectID) (domain.Project, error) {
	q := fmt.Sprintf(`SELECT %s FROM projects WHERE id = $1`, projectCols)
	row := r.tx.QueryRow(ctx, q, string(id))
	p, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Project{}, iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", id)
		}
		return domain.Project{}, mapErr(err, "", string(id))
	}
	return p, nil
}

// List — cursor pagination + опц. filter (name="…") + опц. AccountID scope.
func (r *projectReader) List(ctx context.Context, f project.ListFilter) ([]domain.Project, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // #184: reject >max, no silent clamp
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
		// accepted-and-ignored (#445). The predicate is built from the parsed
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

	// Сужение набора КАНДИДАТОВ (задача #645). Оно стоит здесь, в отборе строк, а
	// не после него: постфильтр по видимости теряет всякий объект, перед которым
	// лежит больше `page_size` невидимых предшественников — он до фильтра просто
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
	q := fmt.Sprintf(`SELECT %s FROM projects %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		projectCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, p)
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

// CountByAccount — для AccountService.Delete sync precheck (iface compatibility).
// Production path не использует (DELETE-WHERE-NOT-EXISTS в account_repo race-safe).
func (r *projectReader) CountByAccount(ctx context.Context, accountID domain.AccountID) (int64, error) {
	var n int64
	err := r.tx.QueryRow(ctx, `SELECT count(*) FROM projects WHERE account_id = $1`, string(accountID)).Scan(&n)
	if err != nil {
		return 0, mapErr(err, "", string(accountID))
	}
	return n, nil
}

// projectWriter — DML над projects через writer-TX.
type projectWriter struct {
	projectReader
}

// Insert — INSERT INTO projects ... RETURNING ...
// FK projects_account_fk (23503) — account_id не существует → FailedPrecondition.
// UNIQUE projects_account_name_unique (23505) — дубль name per account → AlreadyExists.
func (w *projectWriter) Insert(ctx context.Context, p domain.Project) (domain.Project, error) {
	labelsJSON, err := marshalLabels(p.Labels)
	if err != nil {
		return domain.Project{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	now := time.Now().UTC()
	q := fmt.Sprintf(`
		INSERT INTO projects (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, projectCols)
	row := w.tx.QueryRow(ctx, q,
		string(p.ID), string(p.AccountID), string(p.Name), string(p.Description), labelsJSON, now,
	)
	out, err := scanProject(row)
	if err != nil {
		return domain.Project{}, mapErr(err, "", string(p.Name))
	}
	return out, nil
}

// Update — UPDATE mutable полей (name, description, labels). account_id —
// hard-immutable; если попало в mask → caller отверг до repo.
func (w *projectWriter) Update(ctx context.Context, p domain.Project, updateMask []string) (domain.Project, error) {
	labelsJSON, err := marshalLabels(p.Labels)
	if err != nil {
		return domain.Project{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	args, changed, err := mutableTripletUpdateArgs(
		string(p.ID), string(p.Name), string(p.Description), labelsJSON, updateMask)
	if err != nil {
		return domain.Project{}, err
	}
	if !changed {
		return w.Get(ctx, p.ID)
	}
	row := w.tx.QueryRow(ctx, projectUpdateQ, args...)
	out, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Project{}, iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", p.ID)
		}
		return domain.Project{}, mapErr(err, "", string(p.Name))
	}
	return out, nil
}

// projectRoleChildKind — ПОДПИСЬ счёта проектных ролей в перечне отказа: имя
// живой строки каталога, под которым арендатор видит этот вид в ответе каталога
// прав. Это не предикат отбора — отбором семейства управляет приставка в
// операторе ниже (приёмка `non-empty-project-is-not-deleted.md`, §2.3).
const projectRoleChildKind = "iam.role"

// projectDeleteQ — удаление проекта ОДНИМ оператором: две охраны `NOT EXISTS`
// (зеркало чужих ресурсов и своя таблица ролей) плюс зонд, отвечающий, ЧТО
// удерживает, — оба слагаемых перечня в том же снимке (запрет #10; форма взята
// у `accountWriter.Delete`).
//
// Условий у охраны зеркала ДВА — родитель и семейство. Каталог охрану не
// спрашивает НАМЕРЕННО: строка чужого вида удерживает проект в любом состоянии
// каталога, потому что за ней может стоять живой ресурс, а условие «только
// живой глагол удаления» было бы занижением счёта — ошибкой, которая сиротит
// ресурс необратимо (приёмка §2.2, §«Удерживает ЛЮБАЯ строка чужого вида»).
//
// Семейство `iam.*` исключается из зеркала ПРИСТАВКОЙ С РАЗДЕЛИТЕЛЕМ — тем же
// предикатом, каким свой вид классифицирует `internal/domain/selector_feed.go`.
// Свои типы служба в зеркало не кладёт, ребёнок проекта у семейства ровно один
// (роль, ключ `roles_project_fk`) и считается своей таблицей — без исключения
// роль считалась бы дважды, а строка любого другого вида службы держала бы
// проект неснимаемо. Разделитель несущий: вид модуля, чьё имя начинается на
// `iam` (`iamx.thing`), — чужой, и удерживает как всякий чужой.
//
// Отбор в охране и в группировке ДОСЛОВНО ОДИН — разойдись они, отказ пришёл бы
// с пустой скобкой либо назвал бы вид, которого удержание не касается. Гейт
// формы файла — `project_delete_operator_form_test.go`.
//
// Ключ `roles_project_fk ON DELETE RESTRICT` остаётся запасным упором для
// конкурента, проскочившего между снимком и коммитом: его отказ приходит общим
// текстом ссылочной полосы, как у аккаунта.
const projectDeleteQ = `
	WITH del AS (
		DELETE FROM projects p
		 WHERE p.id = $1
		   AND NOT EXISTS (SELECT 1 FROM resource_mirror m
		                    WHERE m.parent_project_id = $1
		                      AND m.object_type NOT LIKE 'iam.%')
		   AND NOT EXISTS (SELECT 1 FROM roles WHERE project_id = $1)
		RETURNING 1
	), held AS (
		SELECT m.object_type AS kind, count(*)::bigint AS n
		  FROM resource_mirror m
		 WHERE m.parent_project_id = $1
		   AND m.object_type NOT LIKE 'iam.%'
		 GROUP BY m.object_type
	)
	SELECT
	  (SELECT count(*) FROM del)::int                                       AS deleted,
	  EXISTS (SELECT 1 FROM projects WHERE id = $1)                          AS project_exists,
	  (SELECT count(*) FROM roles WHERE project_id = $1)::bigint             AS role_count,
	  (SELECT coalesce(jsonb_object_agg(kind, n), '{}'::jsonb) FROM held)    AS held
`

// Delete снимает строку проекта, если он ПУСТ: ни одной зарегистрированной
// строки зеркала чужого вида с этим родителем и ни одной проектной роли.
// Иначе — `ErrReferenceInUse` с перечнем видов и чисел в порядке имени вида:
//
//	Project <id> is not empty (compute.instance: 1, iam.role: 2, vpc.network: 3)
//
// Печатаются виды и числа, НИКОГДА идентификаторы дочерних (состав проекта по
// идентификаторам — карта арендатора); вид с нулём в перечень не попадает.
//
// Состав читается в том же операторе, что снимает строку, — отдельный `SELECT`
// перед удалением брал бы свой снимок, а между ним и `DELETE` лежит ещё и
// запуск воркера операции. Гарантия при этом одна для рода «роли» (вставка
// роли берёт по ключу блокировку строки проекта) и отсутствует для рода
// «зеркало»: у зеркала нет ключа на `projects`, и регистрация, обогнавшая
// удаление, ложится с родителем, которого нет, — это окно объявлено
// контрактом глагола и закреплено пробой как законный исход.
//
// «Удалено» читается ПЕРВЫМ, зонд вторым: у оператора один снимок, и удаление
// из своего же CTE внешнему чтению не видно — зонд отвечает «проект
// существует» и после успешного удаления.
func (w *projectWriter) Delete(ctx context.Context, id domain.ProjectID) error {
	var (
		deleted       int
		projectExists bool
		roleCount     int64
		held          map[string]int64
	)
	err := w.tx.QueryRow(ctx, projectDeleteQ, string(id)).
		Scan(&deleted, &projectExists, &roleCount, &held)
	if err != nil {
		return mapErr(err, "Project.Delete", string(id))
	}
	if deleted == 1 {
		return nil
	}
	if !projectExists {
		return iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", id)
	}
	if roleCount > 0 {
		held[projectRoleChildKind] = roleCount
	}
	if len(held) > 0 {
		return iamerr.Wrapf(iamerr.ErrReferenceInUse, "Project %s is not empty (%s)", id, formatHeldKinds(held))
	}
	// Строка исчезла между шагом удаления и зондом (чужой коммит). NotFound.
	return iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", id)
}

// formatHeldKinds печатает перечень «вид: число» в порядке имени вида — в
// байтовом порядке, а не в порядке сортировки базы: два одинаковых отказа
// обязаны читаться одинаково независимо от локали соединения.
func formatHeldKinds(held map[string]int64) string {
	kinds := make([]string, 0, len(held))
	for kind := range held {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		parts = append(parts, fmt.Sprintf("%s: %d", kind, held[kind]))
	}
	return strings.Join(parts, ", ")
}

// ---- helpers ---------------------------------------------------------------

func scanProject(row scanner) (domain.Project, error) {
	var (
		p          domain.Project
		labelsJSON []byte
	)
	err := row.Scan(
		(*string)(&p.ID),
		(*string)(&p.AccountID),
		(*string)(&p.Name),
		(*string)(&p.Description),
		&labelsJSON,
		&p.CreatedAt,
	)
	if err != nil {
		return domain.Project{}, err
	}
	p.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.Project{}, err
	}
	return p, nil
}
