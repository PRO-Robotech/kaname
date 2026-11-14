// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const bindingStagePage = 256

// BindingStageParticipant — bounded snapshot/atomic apply для настоящих full
// binding entrypoints. kaname#1034: не D1/D2/D3 и не неявная активация carrier.
type BindingStageParticipant struct {
	owner  *GroupMembershipParticipant
	engine *reconcile.Reconciler
	facts  *catalog.Facts
}

func (p *GroupMembershipParticipant) NewBindingStageParticipant(ctx context.Context, logger *slog.Logger) (*BindingStageParticipant, error) {
	if p == nil || p.repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := p.bundle.Validate(); err != nil {
		return nil, err
	}
	var protected bool
	if err := p.repo.master.QueryRow(ctx, `SELECT NOT pg_catalog.has_table_privilege(current_user,'kaname.authority_binding_epoch','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')`).Scan(&protected); err != nil {
		return nil, err
	}
	if !protected {
		return nil, errors.New("binding epochs require protected owner-only metadata")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var halves catalog.Halves
	if err := json.Unmarshal(p.bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return nil, err
	}
	return &BindingStageParticipant{owner: p, facts: facts, engine: reconcile.New(nil, logger, catalog.Fixed{F: facts})}, nil
}

func (p *BindingStageParticipant) ReconcileStagedBinding(ctx context.Context, id domain.AccessBindingID, converge bool, recorder reconcile.SizeRecorder) error {
	if p == nil || p.owner == nil || id == "" {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	var last error
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = p.once(ctx, id, converge, recorder)
		if last == nil {
			return nil
		}
		var pgerr *pgconn.PgError
		if !errors.Is(last, kaname.ErrAuthorityClassificationChanged) && (!errors.As(last, &pgerr) || (pgerr.Code != "40001" && pgerr.Code != "40P01")) {
			return last
		}
	}
	return fmt.Errorf("binding stage retry exhausted: %w", errors.Join(iamerr.ErrAborted, last))
}

type bindingStage struct {
	conn     *pgxpool.Conn
	binding  domain.AccessBinding
	epochs   map[string]json.RawMessage
	accounts map[string]bool
	global   bool
	objects  int
	tuples   int
}

func (s *bindingStage) ObserveBindingMaterialization(objects, tuples int) {
	s.objects += objects
	s.tuples += tuples
}

func (s *bindingStage) close() {
	if s == nil || s.conn == nil {
		return
	}
	// Соединение со spool не возвращается в pool: ни остаточного temp state, ни
	// зависимости cleanup от отменённого request context.
	c := s.conn.Hijack()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

func (p *BindingStageParticipant) once(ctx context.Context, id domain.AccessBindingID, converge bool, recorder reconcile.SizeRecorder) error {
	stage, err := p.stage(ctx, id, converge)
	if err != nil {
		return err
	}
	defer stage.close()
	if stage.binding.ID == "" || stage.binding.Status != domain.AccessBindingStatusActive {
		return nil
	}
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: p.owner.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	var accounts []string
	if !stage.global {
		for a := range stage.accounts {
			accounts = append(accounts, a)
		}
		slices.Sort(accounts)
		if len(accounts) == 0 || len(accounts) > kaname.MaxAuthorityFenceAccounts {
			return kaname.ErrInvalidAuthorityFencePlan
		}
		in.Plan.Mode = kaname.AuthorityFenceAccounts
		for _, a := range accounts {
			in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
			in.Owners = append(in.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: a})
		}
	}
	expected := stage.epochs
	if accounts != nil {
		expected = map[string]json.RawMessage{"": stage.epochs[""], "$generation": stage.epochs["$generation"]}
		for _, a := range accounts {
			v, ok := stage.epochs[a]
			if !ok {
				return kaname.ErrAuthorityClassificationChanged
			}
			expected[a] = v
		}
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	w, err := p.owner.repo.coordinatedAuthorityWriterWithBegin(ctx, in, "participant", stage.conn.BeginTx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	// Epoch locks закрывают legacy source writes даже в prepared/compatibility.
	// Время решения берётся ПОСЛЕ их ожидания, не из snapshot либо начала TX.
	var at time.Time
	if err = w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, encoded).Scan(&at); err != nil {
		return err
	}
	store := &reconcileStore{tx: w.tx, cat: p.facts, decisionAt: at}
	if err = store.AcquireBindingLock(ctx, id); err != nil {
		return err
	}
	if err = store.LockBindingsAndRoles(ctx, []domain.AccessBindingID{id}); err != nil {
		return err
	}
	// Legacy advisory/row waits тоже могут пересечь expiry. Читаем locked carrier,
	// повторно проверяем ТОТ ЖЕ удерживаемый epoch set и только затем берём время.
	// Никакого нового scope, discovery, lock upgrade или второй pool connection.
	current, err := (&abReader{tx: w.tx}).Get(ctx, id)
	if errors.Is(err, iamerr.ErrNotFound) {
		return kaname.ErrAuthorityClassificationChanged
	}
	if err != nil {
		return err
	}
	if err = grantMutationPreflight(ctx, w.tx, "binding"); err != nil {
		return err
	}
	if err = lockGrantChildren(ctx, w.tx); err != nil {
		return err
	}
	if err = prelockBindingCommands(ctx, w.tx); err != nil {
		return err
	}
	if err = w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, encoded).Scan(&at); err != nil {
		return err
	}
	w.fence.decisionAt = at.UTC()
	store.decisionAt = at.UTC()
	if current.Status != domain.AccessBindingStatusActive || (current.ExpiresAt != nil && !current.ExpiresAt.After(at)) {
		return nil
	}
	// Здесь читается только уже вычисленный spool, не inventory/normalizer.
	// Все batches — в одной TX; deletes после всех новых ledger claims.
	for phase := 0; phase < 2; phase++ {
		var after int64
		for {
			rows, e := w.tx.Query(ctx, `SELECT seq,body FROM pg_temp.kaname_binding_stage WHERE phase=$1 AND seq>$2 ORDER BY seq LIMIT $3`, phase, after, bindingStagePage)
			if e != nil {
				return e
			}
			var commands []reconcile.BindingCommand
			for rows.Next() {
				var seq int64
				var raw []byte
				if e = rows.Scan(&seq, &raw); e != nil {
					rows.Close()
					return e
				}
				var command reconcile.BindingCommand
				if e = json.Unmarshal(raw, &command); e != nil {
					rows.Close()
					return e
				}
				commands = append(commands, command)
				after = seq
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for _, command := range commands {
				if e = command.Apply(ctx, store); e != nil {
					return e
				}
			}
			if len(commands) < bindingStagePage {
				break
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = w.Commit(ctx); err != nil {
		return err
	}
	if recorder != nil {
		recorder.ObserveBindingMaterialization(stage.objects, stage.tuples)
	}
	return nil
}

func (p *BindingStageParticipant) stage(ctx context.Context, id domain.AccessBindingID, converge bool) (result *bindingStage, err error) {
	conn, err := p.owner.repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	stage := &bindingStage{conn: conn, accounts: map[string]bool{}}
	defer func() {
		if err != nil {
			stage.close()
		}
	}()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	// CREATE без IF NOT EXISTS: чужой заранее созданный temp spool не принимается.
	if _, err = tx.Exec(ctx, `CREATE TEMP TABLE kaname_binding_stage(seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,phase integer NOT NULL,body jsonb NOT NULL) ON COMMIT PRESERVE ROWS`); err != nil {
		return nil, err
	}
	if err = createGrantChildSpool(ctx, tx); err != nil {
		return nil, err
	}
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_read(ARRAY[]::text[])`).Scan(&raw); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &stage.epochs); err != nil {
		return nil, err
	}
	if _, ok := stage.epochs[""]; !ok {
		return nil, errors.New("binding epochs are uninitialized")
	}
	reader := &abReader{tx: tx}
	stage.binding, err = reader.Get(ctx, id)
	if errors.Is(err, iamerr.ErrNotFound) {
		err = nil
		return stage, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	if stage.binding.Subjects, err = reader.ListSubjects(ctx, id); err != nil {
		return nil, err
	}
	if err = captureGrantChildren(ctx, tx, id); err != nil {
		return nil, err
	}
	roles, err := loadRolesWithLifecycleMode(ctx, tx, []string{string(stage.binding.RoleID)}, rowLock(""))
	if err != nil {
		return nil, err
	}
	bs := bindingScopeFrom(p.facts, stage.binding, roles[stage.binding.RoleID])
	if !bs.Active {
		return stage, tx.Commit(ctx)
	}
	stage.global = bs.Scope.Type != "account" || len(bs.Target.Resources) > 0
	for _, sel := range bs.Selectors {
		if sel.Arm != domain.ArmAnchor || sel.Container != nil {
			stage.global = true
		}
	}
	if !stage.global {
		stage.accounts[bs.Scope.ID] = true
	}
	store := &bindingSnapshotStore{reconcileStore: &reconcileStore{tx: tx, cat: p.facts}}
	emit := func(command reconcile.BindingCommand) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Единственный пока локально классифицированный folded object — настоящий
		// group emitter. Остальные shapes безопасно требуют global до первого lock.
		for _, tuple := range command.Tuples {
			if !strings.HasPrefix(tuple.Object, "iam_group:") {
				stage.global = true
			}
		}
		data, e := json.Marshal(command)
		if e != nil {
			return e
		}
		phase := 0
		if command.Kind == "delete" {
			phase = 1
		}
		_, e = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_binding_stage(phase,body) VALUES($1,$2::jsonb)`, phase, data)
		return e
	}
	types := map[string]bool{}
	for _, sel := range bs.Selectors {
		for _, typ := range sel.ObjectTypes {
			types[typ] = true
		}
	}
	if len(bs.Selectors) > 0 {
		types["iam."+bs.Scope.Type] = true
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT object_type FROM kaname.access_binding_target_members WHERE binding_id=$1`, string(id))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var typ string
		if err = rows.Scan(&typ); err != nil {
			rows.Close()
			return nil, err
		}
		types[typ] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	ordered := make([]string, 0, len(types))
	for typ := range types {
		ordered = append(ordered, typ)
	}
	slices.Sort(ordered)
	for _, typ := range ordered {
		after := ""
		for {
			ids, e := bindingCoordinatePage(ctx, tx, bs, typ, after)
			if e != nil {
				return nil, e
			}
			for _, oid := range ids {
				var obj domain.MirrorObject
				var present bool
				if _, direct := iamDirectScanSpecs[typ]; direct {
					obj, present, e = store.GetIAMDirectObject(ctx, typ, oid)
				} else {
					obj, present, e = store.GetMirrorObject(ctx, typ, oid)
				}
				if e != nil {
					return nil, e
				}
				ancestors, e := store.AncestorObjects(ctx, typ, oid)
				if e != nil {
					return nil, e
				}
				if !stage.global && typ == "iam.group" {
					var scopes groupMembershipScope
					e = tx.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_group_object_scopes($1)`, oid).Scan(&scopes.accounts, &scopes.global)
					if e != nil {
						return nil, e
					}
					stage.global = scopes.global
					for _, a := range scopes.accounts {
						stage.accounts[a] = true
					}
					if len(stage.accounts) > kaname.MaxAuthorityFenceAccounts {
						stage.global = true
					}
				}
				if e = p.engine.StageBindingCoordinate(ctx, store, bs, reconcile.MemberCoord{ObjectType: typ, ObjectID: oid}, obj, present, ancestors, converge, emit, stage); e != nil {
					return nil, e
				}
			}
			if len(ids) < bindingStagePage {
				break
			}
			after = ids[len(ids)-1]
		}
	}
	// Всё ещё тот же RR snapshot, зафиксированный root-read ДО первой страницы.
	// Локальный путь читает лишь discovered epochs, global — scalar digest;
	// inventory и карта всех accounts в память процесса не материализуются.
	var accounts []string
	if !stage.global {
		for a := range stage.accounts {
			accounts = append(accounts, a)
		}
		slices.Sort(accounts)
	}
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, accounts).Scan(&raw); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &stage.epochs); err != nil {
		return nil, err
	}
	if _, ok := stage.epochs["$generation"]; !ok {
		return nil, errors.New("binding epochs are uninitialized")
	}
	return stage, tx.Commit(ctx)
}

// Keyset pages берут надмножество candidates и прежние coordinates, включая
// последнюю страницу и исчезнувший source. Нет OFFSET или inventory под fence.
func bindingCoordinatePage(ctx context.Context, tx pgx.Tx, bs reconcile.BindingScope, typ, after string) ([]string, error) {
	var scope any
	narrow := bs.Scope.Type == "account" && len(bs.Target.Resources) == 0
	for _, sel := range bs.Selectors {
		if sel.Arm != domain.ArmAnchor || sel.Container != nil {
			narrow = false
		}
	}
	if narrow {
		scope = bs.Scope.ID
	}
	source := `SELECT m.object_id AS id FROM kaname.resource_mirror m LEFT JOIN kaname.projects pj ON pj.id=m.parent_project_id WHERE m.object_type=$2 AND ($5::text IS NULL OR coalesce(nullif(m.parent_account_id,''),pj.account_id,'')=$5)`
	if spec, ok := iamDirectScanSpecs[typ]; ok {
		source = "SELECT o.id FROM " + spec.table + " o " + spec.join + " WHERE ($5::text IS NULL OR $5=ANY(" + spec.accountsExpr() + "))"
	}
	query := `SELECT id FROM (` + source + ` UNION SELECT object_id FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_type=$2) candidates WHERE id>$3 ORDER BY id LIMIT $4`
	rows, err := tx.Query(ctx, query, string(bs.BindingID), typ, after, bindingStagePage, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, bindingStagePage)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

type bindingSnapshotStore struct{ *reconcileStore }

func (s *bindingSnapshotStore) LockMirrorObjects(ctx context.Context, coords []reconcile.MemberCoord) (map[reconcile.MemberCoord]struct{}, error) {
	out := make(map[reconcile.MemberCoord]struct{}, len(coords))
	for _, coord := range coords {
		_, ok, err := s.GetMirrorObject(ctx, coord.ObjectType, coord.ObjectID)
		if err != nil {
			return nil, err
		}
		if ok {
			out[coord] = struct{}{}
		}
	}
	return out, nil
}
func (s *bindingSnapshotStore) AncestorObjects(ctx context.Context, typ, id string) ([]domain.MirrorObject, error) {
	rows, err := resource_mirror.AncestorsSnapshot(ctx, s.tx, typ, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MirrorObject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mirrorRowToDomain(row))
	}
	return out, nil
}

var _ reconcile.StagedBindingReconciler = (*BindingStageParticipant)(nil)

// kaname#1034: snapshot-порт не может случайно унаследовать старую блокировку
// после будущего изменения общего diff. Непредусмотренный путь закрыт ошибкой.
func (*bindingSnapshotStore) AcquireBindingLock(context.Context, domain.AccessBindingID) error {
	return errors.New("binding snapshot cannot acquire business locks")
}
func (*bindingSnapshotStore) AcquireBindingLocks(context.Context, []domain.AccessBindingID) error {
	return errors.New("binding snapshot cannot acquire business locks")
}
func (*bindingSnapshotStore) LockBindingsAndRoles(context.Context, []domain.AccessBindingID) error {
	return errors.New("binding snapshot cannot acquire business locks")
}
func (*bindingSnapshotStore) LockBindingForDeactivation(context.Context, domain.AccessBindingID) error {
	return errors.New("binding snapshot cannot acquire business locks")
}
func (*bindingSnapshotStore) LoadBinding(context.Context, domain.AccessBindingID) (reconcile.BindingScope, bool, error) {
	return reconcile.BindingScope{}, false, errors.New("binding snapshot cannot use locking loader")
}
func (*bindingSnapshotStore) LoadBindingForForward(context.Context, domain.AccessBindingID) (reconcile.BindingScope, bool, error) {
	return reconcile.BindingScope{}, false, errors.New("binding snapshot cannot use locking loader")
}
func (*bindingSnapshotStore) LoadBindingsForForward(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID]reconcile.BindingScope, error) {
	return nil, errors.New("binding snapshot cannot use locking loader")
}
