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
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// roleMutationStage сохраняет только ограниченные страницы в памяти. Полный
// OLD/NEW набор живёт в private temp spool той же leased connection.
type roleMutationStage struct {
	accessLabelMode roleAccessLabelMode
	selectorMove    *roleSelectorMoveStage
	request         kaname.RoleMutationRequest
	projection      catalog.GrantProjection
	plan            *policyPlan
	epochs          json.RawMessage
	accounts        map[string]bool
	global          bool
	rows            int
	reads           int
}

func (s *roleMutationStage) charge(n int) error {
	if n < 0 || n > policyDiscoveryRows-s.rows {
		return kaname.ErrSourceReadLimit
	}
	if s.selectorMove != nil {
		if err := chargeNativePolicyBudget(s.selectorMove.budget(), n, 0); err != nil {
			return err
		}
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
	if s.selectorMove != nil {
		if err := chargeNativePolicyBudget(s.selectorMove.budget(), 0, 1); err != nil {
			return err
		}
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
	if p == nil || p.repo == nil || actor.Validate() != nil || request.Role.ID == "" || (request.Create && !request.Rules) || (!request.Create && !request.Update) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	move := len(request.SelectorMoves) != 0
	if move && (request.Create || !request.Update || !request.Rules || request.ExpectedVersion == "" ||
		!slices.Equal(request.UpdateMask, []string{"rules"}) || request.Tuples == nil) {
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
	var stage *roleMutationStage
	if move {
		stage, err = p.stageRoleSelectorMove(ctx, snapshot, request.Role.ID, request.ExpectedVersion,
			request.SelectorMoves, actor, request.Tuples)
	} else {
		stage, err = p.stageRoleMutation(ctx, snapshot, request, actor, nil)
	}
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
	w, err := p.repo.enterAuthority(ctx, tx, intent, owners, intent.Plan.Mode, intent.Plan.Accounts, false, "decision", stage.plan)
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
	var authorization *roleSelectorMoveAuthorization
	if stage.selectorMove != nil {
		authorization, err = stage.holdSelectorMove(ctx, newSemanticAuthorityWriter(w, p.bundle))
	} else {
		err = stage.prepareSequenceProgram(ctx, w)
	}
	if err != nil {
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
	if stage.selectorMove != nil {
		// Checker привязан к границе native-чтения, обновлённой последним
		// protectPolicyPlan. Сама транзакция и бюджет остались прежними.
		final := newSemanticAuthorityWriter(w, p.bundle)
		decision, err := authorization.decide(ctx, final)
		if err != nil {
			return nil, err
		}
		prepared := &preparedRoleWriteTx{semanticAuthorityWriteTx: final, conn: conn, stage: stage}
		// До Grant и подтверждения слота writer остаётся внутри фабрики.
		if err = prepared.finalizePendingSelectorMove(ctx, decision); err != nil {
			return nil, err
		}
		transferred = true
		return prepared, nil
	}
	if _, err = w.tx.Exec(ctx, `SELECT kaname.authority_role_sequence_finalize_v3()`); err != nil {
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

// Получателя определяет тот же объект, что и authority_protocol_require_owner.
// LOGIN выдаёт только SELECT на собственную временную таблицу в этой RR-транзакции.
const roleMoveStageTupleGrantSQL = `DO $grant$
DECLARE
    owner_oid oid;
    owner_name name;
    spool_oid oid;
    prior_path text:=pg_catalog.current_setting('search_path');
BEGIN
    PERFORM pg_catalog.set_config('search_path','pg_catalog,pg_temp',true);
    IF current_user IS DISTINCT FROM session_user OR kaname.authority_role_actor_login_ready_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move tuple stage requires enrolled login' USING ERRCODE='42501';
    END IF;
    SELECT root.relowner,r.rolname,spool.oid INTO owner_oid,owner_name,spool_oid
    FROM pg_catalog.pg_class root
    JOIN pg_catalog.pg_namespace ns ON ns.oid=root.relnamespace AND ns.nspowner=root.relowner
    JOIN pg_catalog.pg_roles r ON r.oid=root.relowner
    JOIN pg_catalog.pg_proc guard ON guard.pronamespace=ns.oid AND guard.proowner=root.relowner
    JOIN pg_catalog.pg_class spool ON spool.relnamespace=pg_catalog.pg_my_temp_schema()
    WHERE root.oid='kaname.authority_writer_protocol'::pg_catalog.regclass
        AND guard.oid='kaname._authority_role_move_stage_tuple_census_v1(boolean,integer,integer)'::pg_catalog.regprocedure
        AND spool.relname='kaname_role_stage_tuples' AND spool.relpersistence='t' AND spool.relkind='r'
        AND spool.relowner=current_user::pg_catalog.regrole AND spool.relowner<>root.relowner;
    IF NOT FOUND THEN RAISE EXCEPTION 'selector move tuple stage owner differs' USING ERRCODE='42501';END IF;

    EXECUTE pg_catalog.format('GRANT SELECT ON TABLE pg_temp.kaname_role_stage_tuples TO %I',owner_name);
    -- Проверяем фактический OID получателя и отсутствие посторонних default grants
    -- до записи первого кортежа. Ошибка откатывает GRANT вместе с созданием spool.
    IF (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(a.grantee=owner_oid AND a.grantor=c.relowner
            AND a.privilege_type='SELECT' AND NOT a.is_grantable)
        FROM pg_catalog.pg_class c CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
        WHERE c.oid=spool_oid AND a.grantee<>c.relowner) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move tuple stage read grant differs' USING ERRCODE='42501';
    END IF;
    PERFORM pg_catalog.set_config('search_path',prior_path,true);
END;
$grant$`

func (p *GrantPolicyWriters) stageRoleMutation(ctx context.Context, tx pgx.Tx, request kaname.RoleMutationRequest, actor domain.Subject, move *roleSelectorMoveStage) (*roleMutationStage, error) {
	s := &roleMutationStage{request: request, selectorMove: move, accounts: map[string]bool{}}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE kaname_role_stage_bindings(id text PRIMARY KEY,retier boolean NOT NULL) ON COMMIT PRESERVE ROWS;
CREATE TEMP TABLE kaname_role_stage_rows(seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,kind text NOT NULL,owner_id text NOT NULL,row_tid text NOT NULL,row_xmin text NOT NULL) ON COMMIT PRESERVE ROWS;
CREATE TEMP TABLE kaname_role_stage_tuples(binding_id text NOT NULL,side text NOT NULL,object text NOT NULL,fga_user text NOT NULL,relation text NOT NULL,PRIMARY KEY(binding_id,side,object,fga_user,relation)) ON COMMIT PRESERVE ROWS`); err != nil {
		return nil, err
	}
	if move != nil {
		// Проверки LOGIN, владельца и выданного ACL расходуют общий бюджет переноса.
		for range 3 {
			if err := s.read(1); err != nil {
				return nil, err
			}
		}
		if _, err := tx.Exec(ctx, roleMoveStageTupleGrantSQL); err != nil {
			return nil, err
		}
	}
	if request.Create || request.Rules {
		var facts *catalog.Facts
		var err error
		if move == nil {
			facts, err = p.roleMutationCatalog()
			if err != nil {
				return nil, err
			}
		} else {
			facts = move.facts
		}
		s.projection, err = facts.ProjectRoleMutationRules(request.Role.Rules, domain.PolicyOfRole(request.Role.IsSystem, request.Role.OwnerModule))
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
	var shared []*relverdict.AdministrativeReadBudget
	if move == nil {
		in.consumedReads = s.reads
	} else {
		in.roleNative.selectorMove = &move.captured
		shared = append(shared, move.budget())
		// SQL аттестует перенос только под глобальной оградой. Это также
		// удерживает источники других ролей, затронутых возможной копией.
		in.global = true
	}
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
	s.plan, err = p.discoverPolicyPlanWithRows(ctx, tx, in, s.rows, shared...)
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
	if s.selectorMove != nil {
		// Перенос удерживает одну глобальную эпоху. Её повторная сверка
		// расходует тот же бюджет источников, что и RR и owner prepare.
		if err := chargeNativePolicyBudget(w.producerBudget, 1, 1); err != nil {
			return err
		}
	}
	var at time.Time
	if err := w.tx.QueryRow(ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, s.scopeAccounts(), []byte(s.epochs)).Scan(&at); err != nil {
		return err
	}
	if s.selectorMove != nil {
		// SQL уже записал именно эти часы в аттестацию текущей транзакции.
		if at.IsZero() {
			return kaname.ErrSourceUnconfirmed
		}
		w.fence.decisionAt = at.UTC()
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
	conn                      *pgxpool.Conn
	stage                     *roleMutationStage
	applied                   bool
	roleWriteStarted          bool
	contentApprovalAttempted  bool
	contentApprovalRecorded   bool
	selectorMoveFinalized     bool
	roleWriteSucceeded        bool
	grantCapabilitiesReplaced bool
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
		if err := w.stage.visitTuples(ctx, w.tx, id, "old", true, func(page []ab.RelationTuple) error { return emitPreparedBindingDelete(ctx, w.authorityWriteTx, page) }); err != nil {
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
