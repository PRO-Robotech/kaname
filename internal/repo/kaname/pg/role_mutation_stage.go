// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// roleMutationStage сохраняет только ограниченные страницы в памяти. Полный
// OLD/NEW набор живёт в private temp spool той же leased connection.
type roleMutationStage struct {
	request    kaname.RoleMutationRequest
	projection catalog.GrantProjection
	plan       *policyPlan
	epochs     json.RawMessage
	accounts   map[string]bool
	global     bool
	rows       int
	reads      int
}

func (s *roleMutationStage) charge(n int) error {
	if n < 0 || n > policyDiscoveryRows-s.rows {
		return kaname.ErrSourceReadLimit
	}
	s.rows += n
	return nil
}

// Считаем logical source reads до SQL. rows включает returned rows и уже
// ограниченные retained/generated tuple slots; это conservative work budget.
func (s *roleMutationStage) read(rows int) error {
	if s.reads >= 4096 {
		return kaname.ErrSourceReadLimit
	}
	s.reads++
	return s.charge(rows)
}
func (s *roleMutationStage) scopeAccounts() []string {
	if s.plan.global {
		return nil
	}
	accounts := make([]string, 0, len(s.plan.accounts))
	for a := range s.plan.accounts {
		accounts = append(accounts, a)
	}
	slices.Sort(accounts)
	return accounts
}
func (s *roleMutationStage) include(scopes groupMembershipScope) {
	s.global = s.global || scopes.global
	for _, a := range scopes.accounts {
		s.accounts[a] = true
	}
	if len(s.accounts) > kaname.MaxAuthorityFenceAccounts {
		s.global = true
	}
}

func (p *GrantPolicyWriters) RoleMutationWriter(ctx context.Context, request kaname.RoleMutationRequest, actor domain.Subject) (out kaname.SemanticAuthorityWriter, err error) {
	if p == nil || p.repo == nil || actor.Validate() != nil || request.Role.ID == "" || (request.Create && !request.Rules) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	conn, err := p.repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	// Spool соединение никогда не возвращается в pool с чужим temp state.
	transferred := false
	defer func() {
		if !transferred {
			closeRoleStageConnection(conn)
		}
	}()
	snapshot, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	stage, err := p.stageRoleMutation(ctx, snapshot, request, actor)
	if err != nil {
		return nil, errors.Join(err, policyRollback(ctx, snapshot))
	}
	if err = snapshot.Commit(ctx); err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !transferred {
			err = errors.Join(err, policyRollback(ctx, tx))
		}
	}()
	intent := stage.plan.intent(p.bundle)
	if err = validateAuthorityIntent(intent); err != nil {
		return nil, err
	}
	owners, err := json.Marshal(intent.Owners)
	if err != nil {
		return nil, err
	}
	w, err := p.repo.enterAuthority(ctx, tx, intent, owners, intent.Plan.Mode, intent.Plan.Accounts, false, "decision")
	if err != nil {
		return nil, err
	}
	if err = p.protectPolicyPlan(ctx, w, stage.plan); err != nil {
		return nil, err
	}
	// Signed role entry сначала держит closed DML table footprint, включая
	// private epoch/deferred tables; row prelock один не покрывает SHARE blocker.
	if err = stage.recheck(ctx, w); err != nil {
		return nil, err
	}
	if err = stage.lockMutation(ctx, w); err != nil {
		return nil, err
	}
	// Ни одной записи роли/проекции ещё нет. После ВСЕХ legacy row waits
	// сверяем оба снимка и берём final decision_at для исходного authority.
	if err = stage.recheck(ctx, w); err != nil {
		return nil, err
	}
	if err = p.protectPolicyPlan(ctx, w, stage.plan); err != nil {
		return nil, err
	}
	transferred = true
	return &preparedRoleWriteTx{semanticAuthorityWriteTx: newSemanticAuthorityWriter(w, p.bundle), conn: conn, stage: stage}, nil
}

func closeRoleStageConnection(conn *pgxpool.Conn) {
	if conn == nil {
		return
	}
	c := conn.Hijack()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

func (p *GrantPolicyWriters) stageRoleMutation(ctx context.Context, tx pgx.Tx, request kaname.RoleMutationRequest, actor domain.Subject) (*roleMutationStage, error) {
	s := &roleMutationStage{request: request, accounts: map[string]bool{}}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE kaname_role_stage_bindings(id text PRIMARY KEY,retier boolean NOT NULL) ON COMMIT PRESERVE ROWS;
CREATE TEMP TABLE kaname_role_stage_rows(seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,kind text NOT NULL,owner_id text NOT NULL,row_tid text NOT NULL,row_xmin text NOT NULL) ON COMMIT PRESERVE ROWS;
CREATE TEMP TABLE kaname_role_stage_tuples(binding_id text NOT NULL,side text NOT NULL,object text NOT NULL,fga_user text NOT NULL,relation text NOT NULL,PRIMARY KEY(binding_id,side,object,fga_user,relation)) ON COMMIT PRESERVE ROWS`); err != nil {
		return nil, err
	}
	if request.Create || request.Rules {
		var halves catalog.Halves
		if err := json.Unmarshal(p.bundle.CanonicalCatalog(), &halves); err != nil {
			return nil, err
		}
		facts, err := catalog.NewFacts(halves)
		if err != nil {
			return nil, err
		}
		s.projection, err = facts.ProjectGrantRules(request.Role.Rules, domain.PolicyOfRole(request.Role.IsSystem, request.Role.OwnerModule))
		if err != nil {
			return nil, err
		}
		s.request.Role.Permissions = s.projection.Permissions
	}
	if request.Create || request.Rules {
		for _, kind := range roleProjectionRowKinds {
			if err := s.stageRows(ctx, tx, kind, string(request.Role.ID)); err != nil {
				return nil, err
			}
		}
	}
	if !request.Create && request.Rules {
		after := ""
		for {
			if err := s.read(0); err != nil {
				return nil, err
			}
			rows, err := tx.Query(ctx, `SELECT id FROM kaname.access_bindings WHERE role_id=$1 AND id COLLATE "C">$2 COLLATE "C" ORDER BY id COLLATE "C" LIMIT $3`, string(request.Role.ID), after, policyDiscoveryPage)
			if err != nil {
				return nil, err
			}
			var ids []domain.AccessBindingID
			for rows.Next() {
				var id domain.AccessBindingID
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return nil, err
				}
				ids = append(ids, id)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
			if err = s.charge(len(ids)); err != nil {
				return nil, err
			}
			for _, id := range ids {
				if err = s.stageBinding(ctx, tx, id); err != nil {
					return nil, err
				}
			}
			if len(ids) < policyDiscoveryPage {
				break
			}
			after = string(ids[len(ids)-1])
		}
	}
	in := rolePolicyRequest(request.Role, request.Create, actor)
	in.roleNative = &roleNativeRequest{role: request.Role, create: request.Create, content: request.Create || request.Rules}
	in.consumedReads = s.reads
	in.global = in.global || s.global
	// GLOBAL уже покрывает полный сохранённый census. Локальный входной
	// список имеет отдельный предел 256: oversized список отвергался раньше
	// global handling. Ни spool, ни последующий source census не усекаются.
	if !in.global {
		for a := range s.accounts {
			in.additionalAccounts = append(in.additionalAccounts, domain.AccountID(a))
		}
	}
	var err error
	s.plan, err = p.discoverPolicyPlanWithRows(ctx, tx, in, s.rows)
	if errors.Is(err, errPolicyDiscoveryBudget) {
		return nil, kaname.ErrSourceReadLimit
	}
	if err != nil {
		return nil, err
	}
	if err = chargeNativePolicyBudget(s.plan.nativeBudget, 1, 1); err != nil {
		return nil, err
	}
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, s.scopeAccounts()).Scan(&s.epochs); err != nil {
		return nil, err
	}
	return s, ctx.Err()
}

func (s *roleMutationStage) stageBinding(ctx context.Context, tx pgx.Tx, id domain.AccessBindingID) error {
	reader := &abReader{tx: tx}
	if err := s.read(1); err != nil {
		return err
	}
	b, err := reader.Get(ctx, id)
	if err != nil {
		return err
	}
	// Сохраняем ТОЧНЫЙ прежний ListActiveByRole predicate, включая PENDING.
	retier := s.request.Tuples != nil && b.Status != domain.AccessBindingStatusRevoked
	if _, err = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_role_stage_bindings VALUES($1,$2)`, string(id), retier); err != nil {
		return err
	}
	var scopes groupMembershipScope
	if err = s.read(1); err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_binding_mutation_scopes($1)`, string(id)).Scan(&scopes.accounts, &scopes.global); err != nil {
		return err
	}
	s.include(scopes)
	if !retier {
		return nil
	}
	if err = s.stageRows(ctx, tx, "ledger", string(id)); err != nil {
		return err
	}
	if err = s.read(0); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT subject_type,subject_id FROM kaname.access_binding_subjects WHERE binding_id=$1 ORDER BY ordinal,subject_type,subject_id LIMIT $2`, string(id), domain.MaxSubjectsPerBinding+1)
	if err != nil {
		return err
	}
	var subjects []domain.Subject
	for rows.Next() {
		var subject domain.Subject
		if err = rows.Scan(&subject.Type, &subject.ID); err != nil {
			rows.Close()
			return err
		}
		subjects = append(subjects, subject)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if err = s.charge(len(subjects)); err != nil {
		return err
	}
	subjects, err = domain.NormalizeSubjects(subjects, b.SubjectType, b.SubjectID)
	if err != nil {
		return err
	}
	for _, tuple := range s.request.Tuples.BuildRoleTuples(b, subjects, s.request.Role) {
		if err = s.saveTuple(ctx, tx, id, "new", tuple); err != nil {
			return err
		}
	}
	cursor := ab.RelationTuple{}
	first := true
	for {
		if err = s.read(0); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT object,fga_user,relation FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND source='binding' AND ($2 OR (object COLLATE "C",fga_user COLLATE "C",relation COLLATE "C")>($3 COLLATE "C",$4 COLLATE "C",$5 COLLATE "C")) ORDER BY object COLLATE "C",fga_user COLLATE "C",relation COLLATE "C" LIMIT $6`, string(id), first, cursor.Object, cursor.User, cursor.Relation, policyDiscoveryPage)
		if err != nil {
			return err
		}
		var tuples []ab.RelationTuple
		for rows.Next() {
			var tuple ab.RelationTuple
			if err = rows.Scan(&tuple.Object, &tuple.User, &tuple.Relation); err != nil {
				rows.Close()
				return err
			}
			tuples = append(tuples, tuple)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, tuple := range tuples {
			if err = s.saveTuple(ctx, tx, id, "old", tuple); err != nil {
				return err
			}
		}
		if len(tuples) < policyDiscoveryPage {
			return nil
		}
		cursor = tuples[len(tuples)-1]
		first = false
	}
}
func (s *roleMutationStage) saveTuple(ctx context.Context, tx pgx.Tx, id domain.AccessBindingID, side string, tuple ab.RelationTuple) error {
	if err := s.charge(1); err != nil {
		return err
	}
	if tuple.Object == "" || tuple.User == "" || tuple.Relation == "" {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	payload, err := json.Marshal(map[string]any{"event_type": "fga.tuple.write", "payload": map[string]string{"user": tuple.User, "relation": tuple.Relation, "object": tuple.Object}})
	if err != nil {
		return err
	}
	var scopes groupMembershipScope
	if err = s.read(1); err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_protocol_row_scopes('fga_outbox',$1::jsonb)`, payload).Scan(&scopes.accounts, &scopes.global); err != nil {
		return err
	}
	s.include(scopes)
	_, err = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_role_stage_tuples VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, string(id), side, tuple.Object, tuple.User, tuple.Relation)
	return err
}
func (s *roleMutationStage) recheck(ctx context.Context, w *authorityWriteTx) error {
	var at time.Time
	if err := w.tx.QueryRow(ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, s.scopeAccounts(), []byte(s.epochs)).Scan(&at); err != nil {
		return err
	}
	return ctx.Err()
}

// Одна страница ключей вместо полного населения в Go. Порядок ID общий для
// advisory/row/apply проходов; чтение business inventory под fence не повторяется.
func (s *roleMutationStage) visitBindings(ctx context.Context, tx pgx.Tx, visit func(string, bool) error) error {
	after := ""
	for {
		rows, err := tx.Query(ctx, `SELECT id,retier FROM pg_temp.kaname_role_stage_bindings WHERE id COLLATE "C">$1 COLLATE "C" ORDER BY id COLLATE "C" LIMIT $2`, after, policyDiscoveryPage)
		if err != nil {
			return err
		}
		type header struct {
			id     string
			retier bool
		}
		var page []header
		for rows.Next() {
			var h header
			if err = rows.Scan(&h.id, &h.retier); err != nil {
				rows.Close()
				return err
			}
			page = append(page, h)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, h := range page {
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = visit(h.id, h.retier); err != nil {
				return err
			}
		}
		if len(page) < policyDiscoveryPage {
			return nil
		}
		after = page[len(page)-1].id
	}
}

// diff выбирается SQL anti-join по сохранённым OLD/NEW ключам. Общие факты
// других выдач остаются предметом штатного emitter/fold, а не новой копии SQL.
func (s *roleMutationStage) visitTuples(ctx context.Context, tx pgx.Tx, id, side string, diff bool, visit func([]ab.RelationTuple) error) error {
	cursor := ab.RelationTuple{}
	first := true
	for {
		rows, err := tx.Query(ctx, `SELECT t.object,t.fga_user,t.relation FROM pg_temp.kaname_role_stage_tuples t WHERE t.binding_id=$1 AND t.side=$2 AND (NOT $3 OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_role_stage_tuples x WHERE x.binding_id=t.binding_id AND x.side<>t.side AND (x.object,x.fga_user,x.relation)=(t.object,t.fga_user,t.relation))) AND ($4 OR (t.object COLLATE "C",t.fga_user COLLATE "C",t.relation COLLATE "C")>($5 COLLATE "C",$6 COLLATE "C",$7 COLLATE "C")) ORDER BY t.object COLLATE "C",t.fga_user COLLATE "C",t.relation COLLATE "C" LIMIT $8`, id, side, diff, first, cursor.Object, cursor.User, cursor.Relation, policyDiscoveryPage)
		if err != nil {
			return err
		}
		var page []ab.RelationTuple
		for rows.Next() {
			var tuple ab.RelationTuple
			if err = rows.Scan(&tuple.Object, &tuple.User, &tuple.Relation); err != nil {
				rows.Close()
				return err
			}
			page = append(page, tuple)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(page) > 0 {
			if err = visit(page); err != nil {
				return err
			}
		}
		if len(page) < policyDiscoveryPage {
			return nil
		}
		cursor = page[len(page)-1]
		first = false
	}
}

type preparedRoleWriteTx struct {
	*semanticAuthorityWriteTx
	conn    *pgxpool.Conn
	stage   *roleMutationStage
	applied bool
}

func (w *preparedRoleWriteTx) ApplyPreparedRoleTuples(ctx context.Context, id domain.RoleID) error {
	if w.stage == nil || w.applied || w.stage.request.Role.ID != id || w.stage.request.Tuples == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	err := w.stage.visitBindings(ctx, w.tx, func(id string, retier bool) error {
		if !retier {
			return nil
		}
		var changed bool
		if err := w.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_temp.kaname_role_stage_tuples t WHERE t.binding_id=$1 AND NOT EXISTS(SELECT 1 FROM pg_temp.kaname_role_stage_tuples x WHERE x.binding_id=t.binding_id AND x.side<>t.side AND (x.object,x.fga_user,x.relation)=(t.object,t.fga_user,t.relation)))`, id).Scan(&changed); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if _, err := w.tx.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND source='binding'`, id); err != nil {
			return err
		}
		if err := w.stage.visitTuples(ctx, w.tx, id, "new", false, func(page []ab.RelationTuple) error {
			return w.AccessBindingsW().InsertEmittedTuples(ctx, domain.AccessBindingID(id), page)
		}); err != nil {
			return err
		}
		if err := w.stage.visitTuples(ctx, w.tx, id, "old", true, func(page []ab.RelationTuple) error { return w.AccessBindingsW().EmitRelationDelete(ctx, page) }); err != nil {
			return err
		}
		return w.stage.visitTuples(ctx, w.tx, id, "new", true, func(page []ab.RelationTuple) error { return w.AccessBindingsW().EmitRelationWrite(ctx, page) })
	})
	if err == nil {
		w.applied = true
	}
	return err
}
func (w *preparedRoleWriteTx) Commit(ctx context.Context) error {
	// Вызов Commit завершает срок доказательства даже при отказе до SQL.
	// Lease остаётся доступен для Rollback, но proof больше не оживает.
	w.authorityWriteTx.closed = true
	if w.conn == nil {
		return pgx.ErrTxClosed
	}
	if w.stage.request.Tuples != nil && !w.applied {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	err := w.semanticAuthorityWriteTx.Commit(ctx)
	closeRoleStageConnection(w.conn)
	w.conn = nil
	return err
}
func (w *preparedRoleWriteTx) Rollback(ctx context.Context) error {
	if w.conn == nil {
		return nil
	}
	err := w.semanticAuthorityWriteTx.Rollback(ctx)
	closeRoleStageConnection(w.conn)
	w.conn = nil
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

var _ kaname.RoleMutationWriterFactory = (*GrantPolicyWriters)(nil)
var _ kaname.PreparedRoleTupleWriter = (*preparedRoleWriteTx)(nil)
