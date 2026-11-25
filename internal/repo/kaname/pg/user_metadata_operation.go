// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto/toproto"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// Создание этого адаптера принадлежит проверке полного контракта User.Update.
type userAccessLabelsWriter struct{ factory *MetadataMutationWriters }

var _ kaname.UserAccessLabelsWriter = (*userAccessLabelsWriter)(nil)

func (w *userAccessLabelsWriter) hasFullContract() bool {
	return w != nil && w.factory != nil && w.factory.policy != nil && w.factory.policy.repo.fullContractMatches(w.factory.policy.bundle)
}

type userMetadataOperation struct {
	pending operations.Operation
	actor   domain.Subject
	account string
}

func newUserMetadataOperation(ctx context.Context, pending operations.Operation) (userMetadataOperation, error) {
	caller, err := authzguard.RequirePublicPrincipalACR(ctx, "1")
	if err != nil {
		return userMetadataOperation{}, err
	}
	if caller.Type != pending.Principal.Type || caller.ID != pending.Principal.ID {
		return userMetadataOperation{}, iamerr.ErrPermissionDenied
	}
	metadata, err := operations.MetadataFor[*iamv1.UpdateUserMetadata](&pending)
	if err != nil || !metadata.GetProtectedLabels() || !nativeQuestionToken(metadata.GetUserId()) || pending.ResourceID != metadata.GetUserId() ||
		pending.CreatedBy != caller.ID || pending.ID == "" || pending.CreatedAt.IsZero() || pending.Description != "Update user "+pending.ResourceID ||
		pending.Done || pending.Error != nil || pending.Response != nil || !pending.ModifiedAt.Equal(pending.CreatedAt) ||
		pending.Metadata.TypeUrl != "type.googleapis.com/kaname.cloud.iam.v1.UpdateUserMetadata" {
		return userMetadataOperation{}, iamerr.ErrFailedPrecondition
	}
	pending.Metadata = proto.CloneOf(pending.Metadata)
	return userMetadataOperation{pending: pending, actor: domain.Subject{Type: domain.SubjectType(caller.Type), ID: domain.SubjectID(caller.ID)}, account: metadata.GetAccountId()}, nil
}

func (w *userAccessLabelsWriter) CreateUserAccessLabelsOperation(ctx context.Context, pending operations.Operation) error {
	op, err := newUserMetadataOperation(ctx, pending)
	if err != nil {
		return err
	}
	if !w.hasFullContract() {
		return kaname.ErrSemanticIdentityUnavailable
	}
	repo := w.factory.policy.repo
	return pgx.BeginTxFunc(ctx, repo.master, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		// Владелец публикации берёт этот ключ в исключительном режиме. Отдельный
		// SELECT после получения общей блокировки видит фиксацию новой головы.
		if err := lockMetadataAuthority(ctx, tx); err != nil {
			return errors.Join(iamerr.ErrUnavailable, err)
		}
		if err := repo.fullContract.profile.ConfirmPublication(ctx, tx); err != nil {
			return err
		}
		// Ручное закрытие владельцем оставляет прежнюю запись в журнале.
		// Проверяем действующую семантику до создания операции.
		identity := w.factory.policy.bundle.Identity()
		var active bool
		if err := tx.QueryRow(ctx, `SELECT kaname.authority_full_contract_validate_v3($1,$2,$3)`,
			identity.ModelID, identity.CatalogID, identity.ProjectorVersion).Scan(&active); err != nil {
			return err
		}
		if !active {
			return errors.Join(iamerr.ErrUnavailable, kaname.ErrSemanticIdentityUnavailable)
		}
		_, err := tx.Exec(ctx, `SELECT kaname.authority_user_access_labels_operation_create_v1($1,$2,$3,$4,$5,$6,$7,$8)`,
			pending.ID, pending.CreatedAt, pending.ResourceID, op.account, op.pending.Metadata.Value, op.actor.Type, op.actor.ID, pending.Principal.DisplayName)
		return err
	})
}

func (w *userAccessLabelsWriter) UpdateUserAccessLabels(ctx context.Context, id domain.UserID, labels, access domain.Labels, actor domain.Subject, pending operations.Operation) (operations.Operation, bool, error) {
	op, err := newUserMetadataOperation(ctx, pending)
	if err != nil {
		return operations.Operation{}, false, err
	}
	if op.actor != actor || actor.Validate() != nil {
		return operations.Operation{}, false, iamerr.ErrPermissionDenied
	}
	if pending.ResourceID != string(id) || access == nil {
		return operations.Operation{}, false, iamerr.ErrFailedPrecondition
	}
	if !w.hasFullContract() {
		return operations.Operation{}, false, kaname.ErrSemanticIdentityUnavailable
	}
	patch := metadataMutationPatch{}
	if err = access.Validate(); err != nil {
		return operations.Operation{}, false, err
	}
	patch.AccessLabels, err = marshalLabels(access)
	if err != nil {
		return operations.Operation{}, false, err
	}
	if labels != nil {
		if err = labels.Validate(); err != nil {
			return operations.Operation{}, false, err
		}
		patch.Labels, err = marshalLabels(labels)
		if err != nil {
			return operations.Operation{}, false, err
		}
	}
	payload, err := json.Marshal(patch)
	if err != nil {
		return operations.Operation{}, false, err
	}
	var result operations.Operation
	var changed bool
	work := metadataProtectedWorkLimit
	err = executePreparedAttempts(ctx, func(ctx context.Context) (*userMetadataAttempt, error) {
		return w.open(ctx, op, patch)
	}, func(ctx context.Context, a *userMetadataAttempt) error {
		actual, e := a.execute(ctx, w.factory, op, payload, &work)
		if e != nil {
			return e
		}
		result = actual
		changed = a.mode != "noop"
		return nil
	})
	if err != nil {
		return operations.Operation{}, false, err
	}
	return result, changed, nil
}

type userMetadataStage struct {
	metadataStage
	members json.RawMessage
	mode    string
}

func (p *MetadataMutationWriters) stageUserMetadata(ctx context.Context, rr pgx.Tx, op userMetadataOperation, patch metadataMutationPatch) (*userMetadataStage, error) {
	id := op.pending.ResourceID
	request := metadataMutation{kind: "user", table: "users", typ: "iam_user", id: id, mode: metadataMutationAccessLabels}
	s := &userMetadataStage{metadataStage: metadataStage{request: request}, mode: "noop"}
	budget := preparedAdministrativeReadBudget(ctx)
	if budget.RemainingRows() < 1 {
		return nil, kaname.ErrSourceReadLimit
	}
	if err := chargeNativePolicyBudget(budget, 0, 2); err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, preparedReadBudgetKey{}, budget)
	maxMembers := min(kaname.MaxAuthorityFenceAccounts, budget.RemainingRows()-1)
	err := rr.QueryRow(ctx, `SELECT u.xmin::text,u.ctid::text,to_jsonb(u),
        (SELECT coalesce(jsonb_agg(s.image ORDER BY s.image::text COLLATE "C"),'[]'::jsonb)
         FROM (SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) image
            FROM ONLY kaname.memberships m WHERE m.user_id=u.id LIMIT $2) s)
        FROM ONLY kaname.users u WHERE u.id=$1`, id, maxMembers+1).Scan(&s.xmin, &s.ctid, &s.old, &s.members)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iamerr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var members [][]json.RawMessage
	if err = json.Unmarshal(s.members, &members); err != nil {
		return nil, err
	}
	if members == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if len(members) > maxMembers {
		return nil, kaname.ErrSourceReadLimit
	}
	questions := newNativePolicyQuestions()
	if err = questions.add(op.actor, "record_writer", "iam_user", id); err != nil {
		return nil, err
	}
	in := policyWriteRequest{actor: op.actor, kind: kaname.AuthorityResource, global: true, nativeQuestions: questions,
		mutationSubjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(id)}}}
	for _, state := range members {
		var m struct {
			User    string `json:"user_id"`
			Account string `json:"account_id"`
		}
		if len(state) != 3 || json.Unmarshal(state[2], &m) != nil || m.User != id || !nativeQuestionToken(m.Account) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		in.additionalAccounts = append(in.additionalAccounts, domain.AccountID(m.Account))
	}
	rootRows := 1 + len(members)
	s.grant, err = captureMetadataGrant(ctx, rr, p.policy.bundle, s.request, mirrorMetadataScope{}, rootRows, s.old, patch.Labels, patch.AccessLabels)
	if err != nil {
		return nil, err
	}
	if s.grant == nil {
		if err = chargeNativePolicyBudget(budget, rootRows, 0); err != nil {
			return nil, err
		}
	} else {
		grant := s.grant
		defer func() {
			if s.plan == nil {
				grant.source.lifetime.close()
			}
		}()
		budget = grant.source.budget
		s.mode = "ordinary"
		s.auditID = domain.AuditEventID(newAuditEventID())
		in.readRoles = grant.roles
		if grant.retained != nil {
			s.mode = "access_labels"
			if err = grant.retained.extendRequest(&in); err != nil {
				return nil, err
			}
		}
		for key := range grant.source.entries {
			switch key.kind {
			case resourceSourceUserMemberships:
				if key.id != id {
					in.membershipReaders = append(in.membershipReaders, domain.UserID(key.id))
				}
			case resourceSourceAccount:
				in.additionalAccounts = append(in.additionalAccounts, domain.AccountID(key.id))
			}
		}
		for _, b := range grant.bindings {
			if b.Changes {
				if err = questions.bindingRole(op.actor, b.Binding.Scope, b.Binding.Role); err != nil {
					return nil, err
				}
			}
		}
	}
	slices.Sort(in.additionalAccounts)
	in.additionalAccounts = slices.Compact(in.additionalAccounts)
	slices.Sort(in.membershipReaders)
	in.membershipReaders = slices.Compact(in.membershipReaders)
	s.plan, err = p.policy.discoverPolicyPlanWithRows(ctx, rr, in, rootRows, budget)
	if err != nil {
		return nil, err
	}
	return s, nil
}

type userMetadataAttempt struct {
	*policyLeaseTx
	*userMetadataStage
	writer *authorityWriteTx
}

func (a *userMetadataAttempt) Commit(ctx context.Context) error {
	if a.grant != nil {
		a.grant.source.lifetime.close()
	}
	a.writer.closed = true
	return a.policyLeaseTx.Commit(ctx)
}
func (a *userMetadataAttempt) Rollback(ctx context.Context) error {
	if a.grant != nil {
		a.grant.source.lifetime.close()
	}
	a.writer.closed = true
	return a.policyLeaseTx.Rollback(ctx)
}

func (w *userAccessLabelsWriter) open(ctx context.Context, op userMetadataOperation, patch metadataMutationPatch) (*userMetadataAttempt, error) {
	repo := w.factory.policy.repo
	conn, err := repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			conn.Release()
		}
	}()
	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	stage, err := w.factory.stageUserMetadata(ctx, rr, op, patch)
	defer func() {
		if !transferred && stage != nil && stage.grant != nil {
			stage.grant.source.lifetime.close()
		}
	}()
	if err = preparedEntryFailure(err, policyRollback(ctx, rr)); err != nil {
		return nil, err
	}
	intent := stage.plan.intent(w.factory.policy.bundle)
	if intent.Plan.Mode != kaname.AuthorityFenceGlobal || len(intent.Owners) != 0 {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err = validateAuthorityIntent(intent); err != nil {
		return nil, err
	}
	rc, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	writer, err := repo.enterAuthority(ctx, rc, intent, []byte("[]"), intent.Plan.Mode, intent.Plan.Accounts, false, "decision", stage.plan)
	if err != nil {
		return nil, preparedEntryFailure(err, policyRollback(ctx, rc))
	}
	transferred = true
	return &userMetadataAttempt{policyLeaseTx: &policyLeaseTx{Tx: rc, conn: conn}, userMetadataStage: stage, writer: writer}, nil
}

func (a *userMetadataAttempt) execute(ctx context.Context, p *MetadataMutationWriters, op userMetadataOperation, patch json.RawMessage, work *int) (operations.Operation, error) {
	budget := a.plan.nativeBudget
	var cost protectedMetadataCost
	err := a.QueryRow(ctx, `SELECT used_rows,used_reads,used_work FROM kaname.authority_metadata_user_prepare_v1(
        $1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7,$8,$9::jsonb,$10,$11,$12)`,
		a.request.id, a.xmin, a.ctid, a.old, a.members, patch, op.actor.Type, op.actor.ID, a.plan.epochs,
		budget.RemainingRows(), budget.RemainingReads(), *work).Scan(&cost.Rows, &cost.Reads, &cost.Work)
	if err != nil {
		return operations.Operation{}, mapProtectedMetadataErr(err)
	}
	if err = a.chargeProtected(cost, work); err != nil {
		return operations.Operation{}, err
	}
	if err = p.policy.protectPolicyPlanAt(ctx, a.writer, a.plan, policyPlanBeforeMetadataFreeze); err != nil {
		return operations.Operation{}, err
	}
	var desired json.RawMessage
	if a.mode == "access_labels" {
		var inputs json.RawMessage
		err = a.QueryRow(ctx, `SELECT kaname.authority_metadata_user_retention_inputs_v1($1,$2,$3,$4,$5)`,
			op.actor.Type, op.actor.ID, budget.RemainingRows(), budget.RemainingReads(), *work).Scan(&inputs)
		if err != nil {
			return operations.Operation{}, mapProtectedMetadataErr(err)
		}
		desired, err = a.compileProtectedDesired(ctx, p.policy.bundle, inputs, work)
		if err != nil {
			return operations.Operation{}, err
		}
	}
	var audit *string
	if a.mode != "noop" {
		id := string(a.auditID)
		audit = &id
	}
	var retained json.RawMessage
	var mode, nonce string
	err = a.QueryRow(ctx, `WITH reserved AS MATERIALIZED (SELECT kaname.authority_metadata_user_reserve_v1(
        $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12) v)
        SELECT v->>'mode',v->>'nonce',v->'user',(v->>'rows')::int,(v->>'reads')::int,(v->>'work')::int FROM reserved WHERE v->'user'=($13::jsonb || $14::jsonb)`,
		op.pending.ID, op.pending.CreatedAt, op.pending.Metadata.Value, op.account, op.actor.Type, op.actor.ID,
		op.pending.Principal.DisplayName, audit, desired, budget.RemainingRows(), budget.RemainingReads(), *work, a.old, patch).
		Scan(&mode, &nonce, &retained, &cost.Rows, &cost.Reads, &cost.Work)
	if errors.Is(err, pgx.ErrNoRows) {
		return operations.Operation{}, kaname.ErrSourceUnconfirmed
	}
	if err != nil {
		return operations.Operation{}, mapProtectedMetadataErr(err)
	}
	if mode != a.mode || nonce == "" || len(retained) == 0 {
		return operations.Operation{}, kaname.ErrSourceUnconfirmed
	}
	if err = a.chargeProtected(cost, work); err != nil {
		return operations.Operation{}, err
	}
	// Сверка RR/RC и проекций завершается до последнего DecisionAt.
	// Grant и record_writer оцениваются в native checker этой транзакции.
	if _, err = p.finalizeMetadataAuthorization(ctx, a.writer, &a.metadataStage, policyPlanBeforeMetadataWrite); err != nil {
		return operations.Operation{}, err
	}
	decision := a.writer.AuthorityFence().DecisionAt()
	var user domain.User
	err = scanUserInto(a.QueryRow(ctx, `WITH applied AS MATERIALIZED (SELECT kaname.authority_metadata_user_apply_v1($1,$2,$3,$4,$5,$6) v)
        SELECT `+userCols+`,(v->>'rows')::int,(v->>'reads')::int,(v->>'work')::int FROM applied
        CROSS JOIN LATERAL jsonb_populate_record(NULL::kaname.users,v->'user') u
        WHERE v->>'mode'=$7 AND v->'user'=$8::jsonb`, op.pending.ID, nonce, decision,
		budget.RemainingRows(), budget.RemainingReads(), *work, mode, retained), &user, &cost.Rows, &cost.Reads, &cost.Work)
	if errors.Is(err, pgx.ErrNoRows) {
		return operations.Operation{}, kaname.ErrSourceUnconfirmed
	}
	if err != nil {
		return operations.Operation{}, mapProtectedMetadataErr(err)
	}
	if string(user.ID) != op.pending.ResourceID || string(user.AccountID) != op.account {
		return operations.Operation{}, kaname.ErrSourceUnconfirmed
	}
	if err = a.chargeProtected(cost, work); err != nil {
		return operations.Operation{}, err
	}
	response, err := toproto.MarshalUserOperationResponse(user)
	if err != nil {
		return operations.Operation{}, err
	}
	// Терминальный CAS, deferred receipt и сверка версий используют
	// остаток той же попытки. Списываем верхнюю границу до SQL-вызова.
	if err = a.chargeProtected(protectedMetadataCost{Rows: 12, Reads: 14, Work: 1}, work); err != nil {
		return operations.Operation{}, err
	}
	saved := op.pending
	err = a.QueryRow(ctx, `SELECT o.created_at,o.modified_at FROM kaname.authority_metadata_user_complete_v1($1,$2,$3,$4) o
        WHERE o.id=$1 AND o.user_access_labels AND o.done AND o.created_at=$5 AND o.description=$6
            AND o.resource_id=$7 AND o.account_id IS NOT DISTINCT FROM nullif($8,'') AND o.created_by=$9
            AND o.principal_type=$10 AND o.principal_id=$9 AND o.principal_display_name=$11
            AND o.metadata_type=$12 AND o.metadata_data=$13 AND o.response_type=$14 AND o.response_data=$4
            AND num_nonnulls(o.error_code,o.error_message,o.error_details)=0`,
		saved.ID, nonce, decision, response.Value, saved.CreatedAt, saved.Description, saved.ResourceID, op.account, saved.CreatedBy,
		saved.Principal.Type, saved.Principal.DisplayName, saved.Metadata.TypeUrl, saved.Metadata.Value, response.TypeUrl).Scan(&saved.CreatedAt, &saved.ModifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return operations.Operation{}, kaname.ErrSourceUnconfirmed
	}
	if err != nil {
		return operations.Operation{}, mapProtectedMetadataErr(err)
	}
	saved.Done = true
	saved.Response = response
	return saved, nil
}
