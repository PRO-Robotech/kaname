// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

// grant_admin.go — GrantAdminUseCase (InternalClusterService.GrantAdmin).
//
// Flow (synchronous within Execute):
//  1. Sync validations: subject_type (USER | SERVICE_ACCOUNT), per-type
//     subject_id format, subject exists in kaname.{users,service_accounts}.
//  2. Persist Operation (done=false) so the returned id is always queryable.
//  3. Begin TX → Grant → if !created && !active → Reactivate →
//     EmitWriteTx (FGA outbox) → commit. On failure → MarkError the op.
//  4. Complete the Operation (done=true) with the FULL metadata (the grant id is
//     knowable only now) and the declared response (ClusterAdminGrant), then
//     return the same terminal envelope to the caller.
//
// Idempotency:
//   - Grant returns (row, false, nil) if ON CONFLICT fires.
//   - If the existing row IsActive → no further write, return it.
//   - If the existing row !IsActive (revoked history) → Reactivate within
//     the same TX (re-activates in-place, same id).
//
// Operation: persisted done=false BEFORE the mutation (mirroring the async
// mutations) then flipped to done=true — the caller receives a terminal (done)
// envelope, and the op row is durable even if the terminal write is retried.

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// GrantAdminUseCase — orchestrates GrantAdmin synchronously.
type GrantAdminUseCase struct {
	writer    grantWriter
	reader    grantReader
	relations relationOutboxEmitter
	txb       service.TxBeginner
	opsRepo   operationRepo
	// subjectState — состояние субъекта выдачи. nil → fail-closed
	// (assertSubjectMayHoldGrant отказывает), как и nil adminCheck.
	subjectState subjectStateReader
	// adminCheck — defense-in-depth ReBAC system_admin@cluster gate. nil →
	// fail-closed (requireClusterSystemAdmin denies). See admin_authz.go.
	adminCheck adminChecker
	// audit — durable audit_outbox emitter. nil → no audit row
	// (purely-additive; mutation contract unchanged). See WithAuditEmitter.
	audit auditEmitter
}

// NewGrantAdminUseCase — constructor (subject-state guard wired separately via
// WithSubjectStateReader).
func NewGrantAdminUseCase(
	w grantWriter,
	r grantReader,
	relations relationOutboxEmitter,
	txb service.TxBeginner,
	opsRepo operationRepo,
) *GrantAdminUseCase {
	return &GrantAdminUseCase{writer: w, reader: r, relations: relations, txb: txb, opsRepo: opsRepo}
}

// WithAuditEmitter — wires the durable audit_outbox emitter.
// Composition-root only. nil emitter → audit emit is skipped.
func (uc *GrantAdminUseCase) WithAuditEmitter(a auditEmitter) *GrantAdminUseCase {
	uc.audit = a
	return uc
}

// WithSubjectStateReader — wires the subject-state guard.
func (uc *GrantAdminUseCase) WithSubjectStateReader(c subjectStateReader) *GrantAdminUseCase {
	uc.subjectState = c
	return uc
}

// WithAdminChecker — wires the defense-in-depth ReBAC system_admin gate.
// Composition-root only (cmd/kaname/wiring.go). nil checker stays
// fail-closed.
func (uc *GrantAdminUseCase) WithAdminChecker(c adminChecker) *GrantAdminUseCase {
	uc.adminCheck = c
	return uc
}

// Execute — sync validation + sync domain mutation + Operation envelope.
func (uc *GrantAdminUseCase) Execute(
	ctx context.Context,
	subjectType iamv1.ClusterGrantSubjectType,
	subjectID string,
) (*operationpb.Operation, error) {
	// Defense-in-depth authZ FIRST (before any validation or DB access):
	// require an authenticated principal holding system_admin@cluster. Fail-
	// closed on empty principal / nil checker / backend error / not-allowed.
	if err := requireClusterSystemAdmin(ctx, uc.adminCheck); err != nil {
		return nil, err
	}
	// Subject: USER or SERVICE_ACCOUNT, with a per-type id-format check.
	// Grant accepts the machine type for symmetry with Revoke: an asymmetric
	// pair (grant one shape, revoke another) is precisely how an unrevocable
	// grant is manufactured. See resolveSubject.
	styp, sid, err := resolveSubject(subjectType, subjectID)
	if err != nil {
		return nil, err
	}

	// Субъект обязан не только существовать, но и быть в состоянии, которое
	// допускает выдачу. Право уровня кластера, выданное личности, которой
	// запрещено аутентифицироваться, не аннулируется вместе с запретом: оно
	// лежит и срабатывает в тот день, когда запрет снимут — то есть выдача
	// пережила решение, которого никто не принимал. Поэтому запрет отвергается
	// здесь, ДО записи, и отказ называет причину, а не выдаёт себя за
	// отсутствие строки (тогда администратор «чинил» бы несуществующую опечатку
	// в идентификаторе).
	//
	// Чтение — по типу, т.к. subject_id полиморфен и FK его не покрывает.
	if err := uc.assertSubjectMayHoldGrant(ctx, styp, subjectID); err != nil {
		return nil, err
	}

	// Principal for granted_by field. The authZ gate above already proved a
	// non-empty authenticated principal — so granted_by is the verified caller,
	// never coerced to 'bootstrap' (that anonymous→bootstrap coercion silently
	// accepted unauthenticated callers and is removed). The legitimate bootstrap
	// startup grant runs via seed.RunBootstrapAdmin (DB-direct, granted_by=
	// 'bootstrap'), not through this use-case.
	principal := authzguard.PrincipalUserID(ctx)

	// Persist the Operation (done=false) BEFORE the mutation — mirroring every
	// async mutation in this service, so the operation id the caller receives is
	// ALWAYS durably queryable. The previous order (mutate → persist op, persist
	// failure non-fatal) left the committed grant with NO pollable Operation row →
	// OperationService.Get(id) returned NotFound forever (CWE-662). The grant.ID
	// is not yet known here, so the initial metadata carries only subject_id; the
	// full metadata (with grant.ID) is written by the terminal transition below —
	// which is why this use-case needs MarkDoneWithMetadata and not MarkDone
	// (MarkDone's third parameter is the RESPONSE; it does not touch metadata, so
	// with it the contract's cluster_admin_grant_id stayed empty forever).
	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Grant cluster admin to %s %s", styp, subjectID),
		&iamv1.GrantClusterAdminMetadata{SubjectId: subjectID},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	// Perform domain mutation synchronously.
	grant, err := uc.doGrant(ctx, styp, sid, principal)
	if err != nil {
		// Record the terminal failure on the already-persisted op so a poll sees a
		// real error, not NotFound; still surface the gRPC error to the caller.
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}

	// Complete the Operation: done=true, metadata replaced by the full one (the
	// grant id exists only now), response = the declared ClusterAdminGrant.
	meta, resp, merr := grantOperationPayload(subjectID, grant)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDoneWithMetadata(ctx, op.ID, meta, resp); err != nil {
		// Non-fatal for the caller: the grant committed and the row exists, so a
		// poll answers (done=false) and never NotFound. It is NOT self-healing —
		// the IAM orphan-resolver has no arm for cluster-admin metadata and skips
		// such rows — so this is logged loudly, never swallowed (CWE-390).
		slog.ErrorContext(ctx, "cluster GrantAdmin: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done = true
	op.Metadata = meta
	op.Response = resp

	return shared.OperationToProto(&op), nil
}

// assertSubjectMayHoldGrant — вердикт о состоянии субъекта выдачи.
//
// Предикат тот же, что спрашивают пути выдачи токена
// (`InviteStatus.MayAuthenticate` / `ServiceAccount.MayAuthenticate`), и это не
// совпадение: право имеет смысл ровно постольку, поскольку им можно
// воспользоваться. Личность, которой аутентификация запрещена, не «получит
// право попозже» — она получит его молча и целиком в момент снятия запрета.
//
// Отсутствие строки остаётся InvalidArgument «<Resource> %s not found»
// (вызывающий назвал несуществующего субъекта); запрет — FailedPrecondition
// с названной причиной. Два разных ответа на два разных вопроса.
func (uc *GrantAdminUseCase) assertSubjectMayHoldGrant(
	ctx context.Context, styp domain.GrantSubjectType, subjectID string,
) error {
	// Непровязанная проверка — это отказ, а не разрешение (так же устроен
	// соседний гейт ReBAC этого же RPC). Иначе композиция, забывшая её
	// подключить, поднимает сервис, выдающий права уровня кластера кому угодно,
	// и заметить это нечем. Текст называет основание — его читает оператор,
	// поднимающий стенд.
	if uc.subjectState == nil {
		return shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"subject state is not verifiable"))
	}
	switch styp {
	case domain.GrantSubjectTypeServiceAccount:
		// `enabled` — и есть предикат domain.ServiceAccount.MayAuthenticate;
		// колонка прочитана запросом выше, поэтому судить есть по чему.
		enabled, err := uc.subjectState.ServiceAccountEnabled(ctx, subjectID)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		if !enabled {
			return shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"ServiceAccount %s is disabled", subjectID))
		}
	default:
		st, err := uc.subjectState.UserInviteStatus(ctx, subjectID)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		if !st.MayAuthenticate() {
			// Причина называется точно. PENDING — приглашение, которое ещё
			// никто не подтвердил: его строка не несёт external_id, а
			// подтверждает его тот, кто первым войдёт по этому адресу почты.
			// Право уровня кластера, повешенное на такую строку, достаётся
			// именно ему — поэтому отказ здесь тот же, а текст другой.
			reason := "is not active"
			if st == domain.InviteStatusBlocked {
				reason = "is blocked"
			}
			return shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"User %s %s", subjectID, reason))
		}
	}
	return nil
}

// grantOperationPayload — the terminal (metadata, response) pair declared by
// `InternalClusterService.GrantAdmin` (metadata: GrantClusterAdminMetadata,
// response: ClusterAdminGrant).
func grantOperationPayload(subjectID string, grant domain.ClusterAdminGrant) (meta, resp *anypb.Any, err error) {
	meta, err = anypb.New(&iamv1.GrantClusterAdminMetadata{
		ClusterAdminGrantId: string(grant.ID),
		SubjectId:           subjectID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal grant metadata: %w", err)
	}
	resp, err = anypb.New(clusterAdminGrantToProto(grant))
	if err != nil {
		return nil, nil, fmt.Errorf("marshal grant response: %w", err)
	}
	return meta, resp, nil
}

// doGrant — runs grant (and optional reactivate) within a single TX.
func (uc *GrantAdminUseCase) doGrant(
	ctx context.Context,
	subjectType domain.GrantSubjectType,
	subject domain.SubjectID,
	grantedBy string,
) (domain.ClusterAdminGrant, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	grant, created, gerr := uc.writer.Grant(ctx, tx, subjectType, subject, grantedBy)
	if gerr != nil {
		return domain.ClusterAdminGrant{}, gerr
	}

	// changed — true iff this call actually committed a state change to the
	// cluster_admin_grants row (fresh INSERT or a reactivate of revoked
	// history). A repeat of an already-active grant changes nothing → no write,
	// and so MUST NOT emit an audit row (audit = log of committed changes, not
	// of RPC calls).
	changed := created
	if !created && !grant.IsActive() {
		// Reactivate: revoked history row — update in-place.
		grant, gerr = uc.writer.Reactivate(ctx, tx, subjectType, subject, grantedBy)
		if gerr != nil {
			return domain.ClusterAdminGrant{}, gerr
		}
		changed = true
	}

	// Emit FGA outbox row (write in same TX for atomicity — запрет #10).
	if err := uc.relations.EmitWriteTx(ctx, tx, systemAdminTuples(subjectType, string(subject))); err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("fga emit write: %w", err)
	}

	// Emit the durable audit_outbox compliance row in the SAME tx (запрет #10)
	// — atomic with the grant + fga-outbox row. Reactivate emits the same
	// iam.cluster_admin.granted type as a fresh grant (compliance: "admin
	// granted again"); an idempotent no-op (already active) emits nothing.
	if changed && uc.audit != nil {
		if err := uc.audit.EmitTx(ctx, tx, service.AuditEvent{
			EventType: auditEventClusterAdminGranted,
			Payload: clusterAdminAuditPayload(
				grantedBy, string(subject), string(grant.ID)),
		}); err != nil {
			return domain.ClusterAdminGrant{}, fmt.Errorf("audit emit grant: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("commit: %w", err)
	}
	return grant, nil
}
