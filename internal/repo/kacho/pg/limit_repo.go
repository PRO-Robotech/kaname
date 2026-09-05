// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// limit_repo.go — pgx adapter for the Limit resource (resource-count quotas, S1).
//
// Standalone reader/writer struct wired from the composition root, the same shape
// InteractiveClientRepo uses: a Limit is cluster-scoped administrative surface and
// does not belong to the tenant CQRS root.

import (
	"context"
	stderrors "errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	kerrors "github.com/PRO-Robotech/kacho/pkg/errors"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// limitCols — the column list every read shares, so a column added to one query
// cannot silently go missing from another.
const limitCols = `id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision`

// limitScopeRefConstraint — the constraint the polymorphic-reference trigger tags
// its refusal with (migration 0092). It is named here because the ANSWER depends
// on it: a missing account or project is this service's OWN row not being there,
// so the lane is direct-read (`NOT_FOUND`), and the generic 23503 mapping —
// FAILED_PRECONDITION, correct for a real foreign key — would tell the caller a
// peer's precondition failed when there is no peer.
const limitScopeRefConstraint = "limits_scope_ref"

// iamServiceDomain — the `domain` half of ErrorInfo (`iam.kacho.cloud`).
const iamServiceDomain = "iam"

// LimitRepo — reads and writes kacho_iam.limits.
type LimitRepo struct {
	pool *pgxpool.Pool
}

// NewLimitRepo — constructor. Composition root: cmd/kacho-iam/wiring.go.
func NewLimitRepo(pool *pgxpool.Pool) *LimitRepo { return &LimitRepo{pool: pool} }

// Get — direct-read lane: this is iam's OWN resource, so a well-formed id with no
// row is NOT_FOUND with the contract tone AND the machine-readable lane token, so
// a client can tell the lane apart without parsing prose.
//
// A withdrawn limit reads as absent. The tombstone exists for the delta, not as a
// second lifecycle state the caller has to reason about: "withdrawn" is what the
// delta says, "gone" is what Get says, and they describe the same fact to two
// different audiences.
func (r *LimitRepo) Get(ctx context.Context, id domain.LimitID) (domain.Limit, error) {
	const q = `SELECT ` + limitCols + ` FROM kacho_iam.limits WHERE id = $1 AND withdrawn_at IS NULL`
	out, err := scanLimit(r.pool.QueryRow(ctx, q, string(id)))
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.Limit{}, limitNotFound(id)
	}
	if err != nil {
		return domain.Limit{}, mapLimitErr(err, "", string(id))
	}
	return out, nil
}

// List — cursor page over (created_at, id) ASC, the platform ordering, narrowed by
// the three closed filters. Withdrawn limits are excluded.
func (r *LimitRepo) List(
	ctx context.Context, limit int, pageToken string, f domain.LimitFilter,
) ([]domain.Limit, string, error) {
	var (
		afterTS time.Time
		afterID string
	)
	if pageToken != "" {
		ts, id, err := decodePageToken(pageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		afterTS, afterID = ts, id
	}

	const q = `SELECT ` + limitCols + ` FROM kacho_iam.limits
		WHERE withdrawn_at IS NULL
		  AND ($3::timestamptz IS NULL OR (created_at, id) > ($3, $4))
		  AND ($2 = '' OR scope    = $2)
		  AND ($5 = '' OR scope_id = $5)
		  AND ($6 = '' OR kind     = $6)
		ORDER BY created_at ASC, id ASC
		LIMIT $1`
	var after any
	if !afterTS.IsZero() {
		after = afterTS
	}
	// limit+1: "is there a next page" is answered by the data, not by comparing
	// the returned slice with the bound it was just cut to.
	rows, err := r.pool.Query(ctx, q, limit+1, string(f.Scope), after, afterID, f.ScopeID, string(f.Kind))
	if err != nil {
		return nil, "", mapLimitErr(err, "", "")
	}
	defer rows.Close()

	out := make([]domain.Limit, 0, limit+1)
	for rows.Next() {
		l, serr := scanLimit(rows)
		if serr != nil {
			return nil, "", mapLimitErr(serr, "", "")
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapLimitErr(err, "", "")
	}

	var next string
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = encodePageToken(last.CreatedAt, string(last.ID))
	}
	return out, next, nil
}

// Insert — states a ceiling.
//
// The revision is NOT supplied here: a trigger assigns it, so the rule "advance on
// change, stand still on a restatement" holds for every writer that exists and
// every writer that will exist, not only for the path this file happens to own.
func (r *LimitRepo) Insert(ctx context.Context, l domain.Limit) (domain.Limit, error) {
	const q = `INSERT INTO kacho_iam.limits (id, scope, scope_id, kind, limit_value)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING ` + limitCols
	out, err := scanLimit(r.pool.QueryRow(ctx, q,
		string(l.ID), string(l.Scope), l.ScopeID, string(l.Kind), l.Value))
	if err != nil {
		return domain.Limit{}, mapLimitErr(err, "Limit", limitTripleHint(l))
	}
	return out, nil
}

// Update — applies the new ceiling. Single UPDATE … RETURNING, so "does it still
// exist" and the write are one act; a zero-row result is the absence, not a race
// lost after checking.
//
// `withdrawn_at IS NULL` in the qualifier is load-bearing: raising the ceiling of a
// withdrawn limit would resurrect it outside the uniqueness the partial index
// promises, and two rows would then be in force for one triple.
func (r *LimitRepo) Update(ctx context.Context, id domain.LimitID, value int64) (domain.Limit, error) {
	const q = `UPDATE kacho_iam.limits
		SET limit_value = $2
		WHERE id = $1 AND withdrawn_at IS NULL
		RETURNING ` + limitCols
	out, err := scanLimit(r.pool.QueryRow(ctx, q, string(id), value))
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.Limit{}, limitNotFound(id)
	}
	if err != nil {
		return domain.Limit{}, mapLimitErr(err, "Limit", string(id))
	}
	return out, nil
}

// Withdraw — marks the ceiling as no longer applying and reports whether this call
// was the one that did it.
//
// The boolean exists so the use-case can be idempotent WITHOUT the repo
// pretending: withdrawing an already-withdrawn limit succeeds at the RPC level,
// and the only code that must still tell the two apart is the one deciding whether
// anything changed.
func (r *LimitRepo) Withdraw(ctx context.Context, id domain.LimitID) (domain.Limit, bool, error) {
	const q = `UPDATE kacho_iam.limits
		SET withdrawn_at = now()
		WHERE id = $1 AND withdrawn_at IS NULL
		RETURNING ` + limitCols
	out, err := scanLimit(r.pool.QueryRow(ctx, q, string(id)))
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.Limit{}, false, nil
	}
	if err != nil {
		return domain.Limit{}, false, mapLimitErr(err, "Limit", string(id))
	}
	return out, true, nil
}

// StatedFor returns every limit in force that could apply to one scope object: the
// object's own rows, its account's rows when the object is a project, and the
// platform defaults.
//
// It answers in ONE query rather than three round-trips because precedence is a
// property of the SET: three separate reads could observe three different moments,
// and the winner would then be chosen from a state that never existed.
//
// `ok=false` means the id names neither a project nor an account. The kind of
// object is established by LOOKING IT UP, never by reading the id's prefix — a
// prefix is a routing hint, and a hint that decides existence is a hint deciding
// an answer it cannot know.
func (r *LimitRepo) StatedFor(ctx context.Context, scopeID string) ([]domain.Limit, bool, error) {
	const q = `
		WITH subject AS (
			SELECT p.id AS project_id, p.account_id AS account_id FROM kacho_iam.projects p WHERE p.id = $1
			UNION ALL
			SELECT ''   AS project_id, a.id        AS account_id FROM kacho_iam.accounts a WHERE a.id = $1
		)
		SELECT ` + limitCols + `
		  FROM kacho_iam.limits l, subject s
		 WHERE l.withdrawn_at IS NULL
		   AND (   l.scope = 'DEFAULT'
		        OR (l.scope = 'ACCOUNT' AND l.scope_id = s.account_id)
		        OR (l.scope = 'PROJECT' AND s.project_id <> '' AND l.scope_id = s.project_id))`
	const existsQ = `SELECT EXISTS (
			SELECT 1 FROM kacho_iam.projects WHERE id = $1
			UNION ALL
			SELECT 1 FROM kacho_iam.accounts WHERE id = $1)`

	var exists bool
	if err := r.pool.QueryRow(ctx, existsQ, scopeID).Scan(&exists); err != nil {
		return nil, false, mapLimitErr(err, "", scopeID)
	}
	if !exists {
		return nil, false, nil
	}

	rows, err := r.pool.Query(ctx, q, scopeID)
	if err != nil {
		return nil, false, mapLimitErr(err, "", scopeID)
	}
	defer rows.Close()

	var out []domain.Limit
	for rows.Next() {
		l, serr := scanLimit(rows)
		if serr != nil {
			return nil, false, mapLimitErr(serr, "", scopeID)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, false, mapLimitErr(err, "", scopeID)
	}
	return out, true, nil
}

// ChangedSince returns limits whose revision is greater than `after`, in revision
// order, INCLUDING withdrawn ones.
//
// Withdrawn rows travel here and nowhere else: a puller that only ever learns
// about writes can never drop a projection row, so a withdrawn project override
// would keep overriding forever.
//
// # Голый курсор здесь БЕЗОПАСЕН, и держит это не «наверное» (kacho#1373)
//
// Обычно позиция, продвинутая на голый номер, теряет строку навсегда: номер
// выдаётся счётчиком на вставке, а видимой строка становится на фиксации, и
// перечитывание идёт строго «больше курсора». Здесь этого окна НЕТ: ревизию
// штампует триггер `limits_stamp_revision` (миграция 0092), берущий
// `pg_advisory_xact_lock` ПЕРЕД `nextval` и держащий её до конца транзакции.
// Значит невыданными в каждый момент остаются номера ОДНОГО писателя, все они
// старше всякого видимого, и порядок ревизий есть порядок фиксаций.
//
// Свойство лежит в ЧУЖОМ и далёком артефакте, поэтому его держат ДВЕ половины, и
// ни одна не заменяет другую: объявление — гейт `internal/repohygiene`
// (он читает тела триггеров последовательно, и позднейшая миграция вправе
// закрытость снять); поведение — `TestLimitRevisionOrderIsCommitOrder`, чья
// способность падать доказана тем же триггером без блокировки в базе пробы.
//
// Верхняя граница по устоявшемуся здесь НЕ применяется осознанно: она добавила
// бы на путь чтения наблюдение блокировок и режим «поток задержан
// незавершившимся писателем» там, где терять нечего.
func (r *LimitRepo) ChangedSince(ctx context.Context, after int64, limit int) ([]domain.Limit, int64, error) {
	const q = `SELECT ` + limitCols + ` FROM kacho_iam.limits
		WHERE revision > $1
		ORDER BY revision ASC
		LIMIT $2`
	rows, err := r.pool.Query(ctx, q, after, limit)
	if err != nil {
		return nil, 0, mapLimitErr(err, "", "")
	}
	defer rows.Close()

	out := make([]domain.Limit, 0, limit)
	next := after
	for rows.Next() {
		l, serr := scanLimit(rows)
		if serr != nil {
			return nil, 0, mapLimitErr(serr, "", "")
		}
		out = append(out, l)
		next = l.Revision
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mapLimitErr(err, "", "")
	}
	return out, next, nil
}

// limitNotFound — the direct-read lane refusal: the contract tone plus the machine
// token, built by the closed lane type so the code and the token cannot disagree.
func limitNotFound(id domain.LimitID) error {
	return kerrors.ReasonResourceNotFound.Errf(
		kerrors.PeerRef{Service: iamServiceDomain, ResourceType: "iam.limit", ResourceID: string(id)},
		"Limit %s not found", id)
}

// scopeSubjectNotFound — the refusal when the account or project a limit names does
// not exist. Same lane as above: the subject is iam's OWN row.
func scopeSubjectNotFound(resource, id string) error {
	return kerrors.ReasonResourceNotFound.Errf(
		kerrors.PeerRef{Service: iamServiceDomain, ResourceType: "iam." + strings.ToLower(resource), ResourceID: id},
		"%s %s not found", resource, id)
}

// mapLimitErr — the adapter's SQLSTATE bridge, with ONE arm of its own before the
// shared mapper: the polymorphic-reference trigger's 23503.
//
// The shared mapper reads 23503 as FAILED_PRECONDITION, which is right for a real
// foreign key (a peer's precondition). Here there is no peer: accounts and projects
// are iam's own rows, so the lane is direct-read and the answer is NOT_FOUND.
func mapLimitErr(err error, kindHint, idHint string) error {
	var pgErr *pgconn.PgError
	if stderrors.As(err, &pgErr) && pgErr.ConstraintName == limitScopeRefConstraint {
		// The trigger already names the resource and the id in its message; it is
		// OUR text, not the driver's, and it is re-built here rather than echoed so
		// no future edit to the trigger can start forwarding driver prose.
		resource, id := parseScopeRefMessage(pgErr.Message)
		if resource != "" {
			return scopeSubjectNotFound(resource, id)
		}
	}
	return mapErr(err, kindHint, idHint)
}

// parseScopeRefMessage — reads `<Resource> <id> not found` back out of the
// trigger's own message. Returns empty strings when the shape is not the expected
// one, and the caller then falls back to the shared mapper rather than inventing an
// answer from a message it did not recognise.
func parseScopeRefMessage(msg string) (resource, id string) {
	fields := strings.Fields(msg)
	if len(fields) != 4 || fields[2] != "not" || fields[3] != "found" {
		return "", ""
	}
	switch fields[0] {
	case "Account", "Project":
		return fields[0], fields[1]
	}
	return "", ""
}

// limitTripleHint — the hint the unique-violation text is built from. The triple is
// the limit's identity among those in force, so it is what the caller must be told
// is already taken.
func limitTripleHint(l domain.Limit) string {
	if l.Scope == domain.LimitScopeDefault {
		return fmt.Sprintf("%s for %s", l.Kind, strings.ToLower(string(l.Scope)))
	}
	return fmt.Sprintf("%s for %s %s", l.Kind, strings.ToLower(string(l.Scope)), l.ScopeID)
}

func scanLimit(row pgx.Row) (domain.Limit, error) {
	var (
		l         domain.Limit
		withdrawn *time.Time
	)
	if err := row.Scan(
		(*string)(&l.ID), &l.CreatedAt, (*string)(&l.Scope), &l.ScopeID,
		(*string)(&l.Kind), &l.Value, &withdrawn, &l.Revision,
	); err != nil {
		return domain.Limit{}, err
	}
	if withdrawn != nil {
		l.WithdrawnAt = *withdrawn
	}
	return l, nil
}

// Encode / Decode — the delta cursor codec, owned by the adapter that produced
// the revision it encodes.
//
// It is a separate codec from the page token because it encodes a DIFFERENT sort
// key (a revision, not a (created_at, id) pair), and re-using the page token would
// have made a token from one read silently acceptable to the other — accepted,
// decoded into the wrong dimension, and answered with a page that looks legitimate.
//
// The methods hang on the repo rather than living as free functions so the
// use-case holds ONE object for the delta: a second implementation of the cursor
// would agree with this one on every valid input and diverge exactly where
// divergence is invisible.
func (r *LimitRepo) Encode(rev int64) string {
	return base64URLEncode([]byte("rev|" + strconv.FormatInt(rev, 10)))
}

// Decode — an empty cursor means "from the beginning of time", which is what a
// projection that has never synchronised needs. Anything that is not empty and not
// a cursor this codec produced is INVALID_ARGUMENT: silently treating garbage as
// zero would replay the whole history and look like a healthy first run.
func (r *LimitRepo) Decode(cursor string) (int64, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64URLDecode(cursor)
	if err != nil {
		return 0, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument cursor")
	}
	rest, ok := strings.CutPrefix(string(raw), "rev|")
	if !ok {
		return 0, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument cursor")
	}
	rev, perr := strconv.ParseInt(rest, 10, 64)
	if perr != nil || rev < 0 {
		return 0, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument cursor")
	}
	return rev, nil
}
