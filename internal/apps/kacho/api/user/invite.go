// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite.go — UserService.Invite use-case.
//
// Flow:
//  1. sync: validate AccountID + email; permission-check через
//     `canInviteUsers` (invite_authz.go — один Check(editor) через
//     cascade-traversal покрывает editor/admin/owner; viewer не может).
//  2. (sync) validate project_id + role_id consistency; peer-check project
//     принадлежит указанному account.
//  3. async (LRO worker): найти existing user-row через GetByAccountEmail —
//     если есть ACTIVE → idempotent (если project+role указаны → создать AB);
//     если есть PENDING → idempotent; если нет → InsertPending в TX
//     (+ optionally INSERT AccessBinding).
//  4. response = User; metadata = {user_id, account_id}.
//
// The Kratos admin magic-link step was removed (Kratos client deleted). Invite
// still creates a PENDING user row + optional AccessBinding; how the invitee
// activates the row (magic-link / IdP login / admin assist) is left to the
// broker layer.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// InviteUserInput — параметры use-case'а (resolved из gRPC request).
type InviteUserInput struct {
	AccountID   domain.AccountID
	Email       domain.Email
	DisplayName domain.DisplayName // optional; если "" — defaults к email
	ProjectID   domain.ProjectID   // optional; если set → role_id обязателен
	RoleID      domain.RoleID      // required IFF ProjectID set
}

// ObjectReconciler — narrow port: SYNCHRONOUSLY
// materialize the per-object access of every binding whose selector matches the
// invite-flow's freshly-created iam-native objects (the project-scoped
// AccessBinding + a brand-new invitee user), right after the invite tx commits.
// Under the flat rights model the `from <scope>` ACCESS cascade on these leaf
// types is gone, so the owner/account-admin per-object tuple is materialized
// per-object; the sync call closes the GET-after-create race the async drain would
// otherwise lose. Implemented by reconcile.Reconciler. nil-safe (the co-committed
// reconcile event + periodic sweep are the at-least-once backstop).
type ObjectReconciler interface {
	// ReconcileObjectForward is the ADDITIVE forward fast-path for the invite-flow's
	// freshly-created iam-native objects (iam.user + the project-scoped iam.accessBinding):
	// it materializes ONLY that new object's per-object owner/admin tuples across the
	// matching bindings while holding NO advisory lock at all (neither EXCLUSIVE nor SHARE,
	// no O(scope) recompute),
	// the throughput fix for the owner-tuple materialization lag under a parallel
	// invite burst. It transparently delegates to the FULL ReconcileObject if the object
	// already has members (delete-stale guard).
	ReconcileObjectForwardNoStale(ctx context.Context, objectType, objectID string) error
	// ReconcileObjectForward — СТОРОЖЕВОЙ вход того же прохода: он сперва читает,
	// есть ли у объекта члены, и при непустом наборе уходит на полный проход ради
	// снятия устаревших. Пути СОЗДАНИЯ он не нужен (доказательство — выше), но
	// остаётся в порту: его зовёт правка того же пакета, где прежние факты есть
	// и снятие устаревших — как раз предмет.
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
	// ReconcileObject is the FULL EXCLUSIVE object-fan-out (async at-least-once backstop —
	// delete-stale / audit / sweep), driven by the reconcile worker off the co-committed
	// reconcile-outbox event, not the invite hot-path.
	ReconcileObject(ctx context.Context, objectType, objectID string) error
	// ReconcileBinding materializes the invite-flow AccessBinding's OWN grant
	// membership through the unified reconciler — the per-object verb-bearing v_*
	// (+ back-compat tier) tuples derived from the granted role's verbs. Under
	// Design-B (flat-authz verb-bearing) enforcement resolves get→v_get,
	// update→v_update, … so the grant MUST carry v_* — a tier-only emit (the old
	// writeInviteBindingTuples path) leaves the invitee with `editor` but no
	// `v_get`/`v_update`, denied on GET/PATCH of the granted project. This is the
	// SAME materialization path
	// AccessBindingService.Create drives, so the invite-flow grant is identical to a
	// direct binding.
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// InviteUserUseCase — invite-or-bind use-case.
type InviteUserUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	authz   AuthzChecker
	// relations — клиент движка прав. Кортежи им БОЛЬШЕ НЕ ПИШУТСЯ: указатели
	// на предков со-коммичены строкой журнала в самой транзакции приглашения
	// (см. doInvite), а членство выдачи материализует реконсайлер. Поле
	// остаётся ради второй своей роли — проверки права приглашать: тот же
	// клиент удовлетворяет узкому AuthzChecker, и WithRelationStore
	// перенаправляет на него `uc.authz`.
	relations  clients.RelationStore
	reconciler ObjectReconciler // optional, nil-safe
	logger     *slog.Logger
}

func NewInviteUserUseCase(
	r Repo,
	opsRepo operations.Repo,
	authz AuthzChecker,
) *InviteUserUseCase {
	return &InviteUserUseCase{
		repo:    r,
		opsRepo: opsRepo,
		authz:   authz,
	}
}

// WithObjectReconciler wires the post-commit synchronous per-object materializer.
// nil-safe.
func (uc *InviteUserUseCase) WithObjectReconciler(r ObjectReconciler) *InviteUserUseCase {
	uc.reconciler = r
	return uc
}

// WithRelationStore wires the invite-flow AccessBinding FGA tuple writer.
//
// It also re-points the `CanInviteUsers` permission checker at the real FGA
// client: NewInviteUserUseCase is constructed with the no-op authzStub, so
// without this the invite permission gate always denies even for an account
// admin ("Permission denied to invite users" for the account owner).
// RelationStore satisfies the narrow AuthzChecker interface (both expose
// Check), so the same client backs the permission gate and the tuple writer.
func (uc *InviteUserUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *InviteUserUseCase {
	uc.relations = relations
	uc.authz = relations
	uc.logger = logger
	return uc
}

// Execute — основной entry-point.
//
// **Sync validation** (все до Operation):
//   - AccountID required.
//   - Email format (RFC 5321 lite via domain.Email.Validate).
//   - ProjectID+RoleID consistency.
//   - Permission check (CanInviteUsers cascade). 401/PERMISSION_DENIED — НЕ
//     создаем Operation.
//
// **Async work** в LRO worker'е:
//   - GetByAccountEmail → idempotent path или INSERT PENDING.
//   - Optionally AB-Insert (idempotent через ON CONFLICT).
//   - Magic-link generation.
func (uc *InviteUserUseCase) Execute(ctx context.Context, in InviteUserInput) (*operations.Operation, error) {
	// 1. Sync validation.
	if in.AccountID == "" {
		return nil, shared.InvalidArg("account_id", "Illegal argument account_id: required")
	}
	if err := in.Email.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	if in.DisplayName != "" {
		if err := in.DisplayName.Validate(); err != nil {
			return nil, shared.MapValidationErr(err)
		}
	}
	if in.ProjectID != "" && in.RoleID == "" {
		return nil, shared.InvalidArg("role_id", "Illegal argument role_id: required when project_id is set")
	}
	if in.ProjectID == "" && in.RoleID != "" {
		return nil, shared.InvalidArg("project_id", "Illegal argument project_id: required when role_id is set")
	}

	// 2. Permission check через cascade Check(editor).
	principal := operations.PrincipalFromContext(ctx)
	if principal.ID == "" {
		return nil, status.Error(codes.Unauthenticated, "principal required")
	}
	allowed, err := canInviteUsers(ctx, uc.authz, string(in.AccountID))
	if err != nil {
		return nil, fmt.Errorf("authz check: %w", err)
	}
	if !allowed {
		return nil, status.Errorf(codes.PermissionDenied,
			"Permission denied to invite users in account %s", in.AccountID)
	}

	// 3. Peer-check project (если указан) — он должен принадлежать тому же
	// Account. Same-DB read (Project — ресурс kacho-iam, нет cross-service hop).
	if in.ProjectID != "" {
		rd, rerr := uc.repo.Reader(ctx)
		if rerr != nil {
			return nil, shared.MapRepoErr(rerr)
		}
		prj, perr := rd.Projects().Get(ctx, in.ProjectID)
		_ = rd.Rollback(ctx)
		if perr != nil {
			return nil, shared.MapRepoErr(perr)
		}
		if prj.AccountID != in.AccountID {
			return nil, status.Error(codes.FailedPrecondition,
				"project_id belongs to different account")
		}

		// The role must be assignable on the scope this invitation binds it to —
		// the same question AccessBinding.Create asks, asked here because this flow
		// is the OTHER writer of the same table and used to insert without asking.
		//
		// The account boundary is what it protects: a custom role belongs to the
		// account that defined it. Binding a foreign account's role does not hand
		// the inviter anything of that account's (the scope is their own project),
		// but it PINS the role in the other account for ever — the reference is
		// restrict-on-delete, so its owner is refused deletion while the listing
		// that would explain the refusal filters that binding out, because it lives
		// in a scope they hold no authority over.
		//
		// The database refuses this too (migration 0072), for every writer. This
		// gate is what makes the refusal say WHY, in the platform's contract tone,
		// instead of surfacing a constraint violation.
		if rerr := uc.assertRoleAssignableOnProject(ctx, in.RoleID, in.ProjectID, in.AccountID); rerr != nil {
			return nil, rerr
		}
	}

	// 4. Pre-allocate user-id (на случай INSERT в async path; при idempotent
	// возврате existing-row id игнорируется).
	candidateUserID := domain.UserID(ids.NewID(domain.PrefixUser))

	// `users.invited_by` is a foreign key into `users(id)` — it names the USER who
	// invited, and nothing else can be named there. Stamping it from the principal
	// id regardless of the principal's TYPE wrote `sva…` into that column for a
	// machine caller, and the insert died on the constraint; the failure reached
	// the caller as the unmapped-FK fallback text, which names neither the column
	// nor the cause.
	//
	// A service account is a legitimate inviter — it simply is not a user, so there
	// is no inviting user to record. The column is left NULL, and the actor is not
	// lost: the Operation carries `principalType`/`principalId`, which is where a
	// non-user actor belongs. Same question the authz model answers through
	// authzguard.SubjectFromPrincipal — name the principal by the type it has,
	// never by a type that merely fits the column.
	invitedBy := domain.UserID(authzguard.HumanUserID(ctx))

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Invite user %s to account %s", in.Email, in.AccountID),
		&iamv1.InviteUserMetadata{
			UserId:    string(candidateUserID),
			AccountId: string(in.AccountID),
		},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doInvite(ctx, op.ID, candidateUserID, invitedBy, in)
	})
	return &op, nil
}

// doInvite — async-часть. Возвращает marshalled User для Operation.response.
// assertRoleAssignableOnProject refuses an invitation whose role may not be bound on
// the invited project.
//
// It asks the same predicate AccessBinding.Create asks: a system role goes anywhere;
// a custom role of THIS account goes on its own account and on projects nested in it;
// a project role goes on its own project; nothing else. The account boundary is never
// crossed.
//
// A role that is not visible from this scope collapses to the absent-role text —
// byte-identical to a genuine miss — so a foreign account's role cannot be told apart
// from one that does not exist (the same hide-existence contract RoleService.Get
// keeps). Otherwise the refusal names the role and its tier, because the caller can
// act on that.
func (uc *InviteUserUseCase) assertRoleAssignableOnProject(
	ctx context.Context, roleID domain.RoleID, projectID domain.ProjectID, accountID domain.AccountID,
) error {
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	roles := rd.Roles()
	if roles == nil {
		// Fail closed: an unwired catalog must refuse, never skip the question.
		return status.Error(codes.Unavailable, "role catalog unavailable")
	}
	role, err := roles.Get(ctx, roleID)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return status.Errorf(codes.FailedPrecondition, "Role %s not found", roleID)
		}
		return shared.MapRepoErr(err)
	}
	if domain.IsRoleAssignableInAccount(role, "project", string(projectID), string(accountID)) {
		return nil
	}
	// Not assignable. Visible from this scope means: a system catalog role, or a role
	// of this account's own tree. Anything else must not be distinguishable from
	// absent.
	if !role.IsSystem && string(role.AccountID) != string(accountID) && role.ProjectID == "" {
		return status.Errorf(codes.FailedPrecondition, "Role %s not found", roleID)
	}
	if role.ProjectID != "" && string(role.ProjectID) != string(projectID) {
		return status.Errorf(codes.FailedPrecondition, "Role %s not found", roleID)
	}
	return status.Errorf(codes.FailedPrecondition,
		"role %s is not assignable on project:%s", roleID, projectID)
}

func (uc *InviteUserUseCase) doInvite(
	ctx context.Context, opID string, candidateID, invitedBy domain.UserID, in InviteUserInput,
) (*anypb.Any, error) {
	// 4.1 Read-side check (быстрый path для idempotent ACTIVE/PENDING).
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	existing, exErr := rd.Users().GetByAccountEmail(ctx, in.AccountID, in.Email)
	_ = rd.Rollback(ctx)

	dn := in.DisplayName
	if dn == "" {
		dn = defaultDisplayName(in.Email)
	}

	// 4.2 INSERT (или Get-existing) + AB-INSERT в одной TX.
	type inviteTxResult struct {
		user      domain.User
		userIsNew bool
		createdAB domain.AccessBinding
		haveAB    bool
	}
	res, err := shared.DoWithWriteTx(ctx, uc.repo,
		func(ctx context.Context, w Writer) (inviteTxResult, error) {
			var out inviteTxResult
			if exErr == nil {
				// Idempotent: row already exists (ACTIVE / PENDING / BLOCKED).
				out.user = existing
			} else {
				// «Человек существует и приглашён СЮДА». Признак заведения —
				// несущий, и отбрасывать его больше нельзя: с глобальным ключом
				// идентичности конфликт означает не «эта строка уже есть в этом
				// аккаунте» (такую ловит быстрый путь выше), а «человек уже есть
				// в платформе» — его приглашают во ВТОРОЙ аккаунт. Приняв это за
				// заведение, вызывающий эмитировал бы указатель на предка и
				// материализацию для строки, которая не заводилась, и объявил бы
				// её аккаунтом тот, что назван приглашением, — тогда как её
				// аккаунтов теперь несколько, а звено цепи областей берётся из
				// членств.
				ins, insertedNow, err := w.UsersW().InsertPending(ctx, domain.User{
					ID:           candidateID,
					AccountID:    in.AccountID,
					Email:        in.Email,
					DisplayName:  dn,
					InviteStatus: domain.InviteStatusPending,
					InvitedBy:    invitedBy,
				})
				if err != nil {
					return inviteTxResult{}, err
				}
				out.user = ins
				out.userIsNew = insertedNow
			}

			// Optional bind-to-Project. The insert is STRICT create, NOT idempotent:
			// the `ON CONFLICT DO UPDATE SET id = access_bindings.id` this comment used
			// to describe was deliberately removed (see abWriter.Insert in
			// internal/repo/kacho/pg/access_binding_repo.go — the silent upsert hid a
			// real duplicate grant and polluted the audit chain). Re-inviting into a
			// project the subject already holds an ACTIVE grant on collides on the
			// partial UNIQUE access_bindings_active_grant_uniq (migration 0003, the
			// 5-tuple + target digest WHERE revoked_at IS NULL) → SQLSTATE 23505 →
			// ErrAlreadyExists, and since this runs inside the invite writer-tx the
			// WHOLE invite rolls back with it. Do not "restore" idempotency here.
			//
			// The AccessBinding subject must be the SAME user-row that the
			// api-gateway resolves the invitee's JWT to (InternalIAMService.
			// LookupSubject → the oldest row of the identity that may
			// authenticate). With the
			// user-per-Account model one identity has N user-rows (one per Account):
			// `user` above is the per-Account row in `in.AccountID` (a fresh PENDING
			// row, or an existing row in that Account). If the invitee is ALREADY
			// ACTIVE in another Account (e.g. their bootstrap personal Account), the
			// gateway resolves the JWT to that older row, NOT this one — so a
			// project-grant tuple on `user.ID` would be `no path` for the
			// gateway-resolved subject. AccessBinding.subject_id is Account-agnostic
			// (it grants ANY user a role on ANY resource), so resolve the canonical
			// (gateway-visible) identity row and bind the project-scoped grant to it.
			if in.ProjectID != "" {
				subjectID := uc.resolveCanonicalSubjectID(ctx, out.user, in.Email)
				ab := domain.AccessBinding{
					ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
					SubjectType:  domain.SubjectTypeUser,
					SubjectID:    subjectID,
					RoleID:       in.RoleID,
					ResourceType: domain.ResourceType("project"),
					ResourceID:   string(in.ProjectID),
					// F8: whole-project invite grant (explicit allInScope).
					Target: domain.AccessTarget{AllInScope: true},
				}
				ins, abErr := w.AccessBindingsW().Insert(ctx, ab)
				if abErr != nil {
					return inviteTxResult{}, abErr
				}
				// Состав субъектов выдачи ОБЯЗАН быть записан вместе с ней.
				// Форма вердикта заходит в выдачи с пары «субъект + область»
				// через дочернюю таблицу: выдача без неё невидима вердикту
				// целиком — право записано, читается списками и не действует.
				// Отличить это состояние от «права не выдавали» нечем, поэтому
				// оно и прожило незамеченным, пока право вычислял внешний
				// движок: ему кортежи писались другим путём.
				if serr := w.AccessBindingsW().InsertSubjects(ctx, ins.ID,
					[]domain.Subject{{Type: domain.SubjectTypeUser, ID: subjectID}}); serr != nil {
					return inviteTxResult{}, serr
				}
				out.createdAB = ins
				out.haveAB = true
				// Co-commit a reconcile
				// event for the NEW access_binding object so the owner `*.*` binding
				// materializes admin on iam_access_binding:<id> (the flat model dropped
				// the `from <scope>` access cascade). ban #10 co-commit.
				if err := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.accessBinding", string(ins.ID)); err != nil {
					return inviteTxResult{}, err
				}
				// Указатель на предка для объекта привязки
				// (`iam_access_binding:<id>#project@project:<id>`), без которого
				// iam_access_binding-scoped Get/Delete не резолвится.
				//
				// СО-КОММИТ, а не запись после коммита. Прежде тут стоял
				// post-commit best-effort прямо в движок: он терял кортеж на
				// недоступности движка И — что тише и потому хуже — клал в движок
				// строку, которой НЕТ в журнале `kacho_iam.fga_outbox`. Состояние
				// движка обязано быть свёрткой журнала (миграция 0098): кортеж мимо
				// журнала проекция `relation_fact` не увидит никогда, и форма E
				// ответит «нет» там, где движок отвечает «да», — молча, потому что
				// пустая проекция неотличима от честного отказа.
				if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{{
					User:     fmt.Sprintf("project:%s", ins.ResourceID),
					Relation: "project",
					Object:   fmt.Sprintf("iam_access_binding:%s", ins.ID),
				}}); ferr != nil {
					return inviteTxResult{}, ferr
				}
			}
			// A freshly-inserted invitee user row must forward-materialize under the
			// owner `*.*` binding. Co-commit the reconcile event in the SAME writer-tx
			// as the InsertPending (ban #10).
			//
			// ЗДЕСЬ СТОЯЛО «the flat model dropped the iam_user `from account` access
			// cascade» — И ЭТО НЕВЕРНО. Модель объявляет `define super_admin: admin from
			// account` у типа `iam_user` и сегодня, а компилятор плана даёт от неё два
			// источника всем семи отношениям типа. Плоская модель сняла ЯРУСНЫЙ каскад
			// (`viewer`/`editor` от аккаунта), а не уровень супер-доступа. Комментарий,
			// объявляющий каскад снятым, ведёт к правке модели «раз его всё равно нет» —
			// и она отняла бы доступ у владельца аккаунта и у делегированного
			// администратора (измерено вердиктом, обе стороны).
			if out.userIsNew {
				if err := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.user", string(out.user.ID)); err != nil {
					return inviteTxResult{}, err
				}
				// Указатель `iam_user:<id>#account@account:<acc>`: без него
				// per-resource UserService.Get на приглашённом — FGA `no path`.
				// Со-коммит по той же причине, что и у привязки выше; форма
				// кортежа байт-идентична пути активации приглашения
				// (internal_upsert.go), который ушёл с post-commit-записи раньше.
				if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{{
					User:     fmt.Sprintf("account:%s", out.user.AccountID),
					Relation: "account",
					Object:   fmt.Sprintf("iam_user:%s", out.user.ID),
				}}); ferr != nil {
					return inviteTxResult{}, ferr
				}
				// ПИСЬМО ПРИГЛАШЕНИЯ — намерение в очередь, В ЭТОЙ ЖЕ транзакции
				// (Р23/Р25 приёмки ID-MAIL-1). Атомарность несущая: при откате
				// приглашения намерения нет ВОВСЕ, поэтому письма о приглашении,
				// которого не случилось, не бывает by construction. Прямой вызов
				// ретранслятора отсюда не дал бы ни этого, ни переживания
				// намерением смерти процесса.
				//
				// ПОЧЕМУ ТОЛЬКО НА ЗАВЕДЕНИИ СТРОКИ, а не на каждом вызове.
				// Повторное приглашение того же адреса в тот же аккаунт
				// идемпотентно и сюда не доходит (быстрый путь выше отдаёт
				// существующую строку) — значит письмо уходит РОВНО ОДНО на
				// (аккаунт, адрес), и предел этот держится построением, а не
				// ручкой. Эмиссия на каждом вызове сделала бы приглашение
				// средством рассылки: обладатель права приглашать слал бы на
				// произвольный адрес со скоростью вызовов API. Повторная отправка
				// — предмет СВОЕГО глагола со своим ограничением частоты (§10
				// пп. 9 и 17 приёмки), и она не заводится здесь молча.
				//
				// Адрес страницы входа намеренно НЕ передаётся: он величина
				// установки, а не сведение use-case'а, и подставляет его
				// отправитель из своей настройки.
				if merr := w.EmitInviteMail(ctx,
					string(out.user.ID), string(out.user.AccountID), string(in.Email), "",
				); merr != nil {
					return inviteTxResult{}, merr
				}
			}
			return out, nil
		})
	if err != nil {
		return nil, err
	}
	user := res.user
	userIsNew := res.userIsNew
	createdAB := res.createdAB
	haveAB := res.haveAB

	// Указатели на предков (привязка→проект, пользователь→аккаунт) СО-КОММИЧЕНЫ
	// строкой журнала в транзакции выше — здесь их больше не пишут. Членство
	// выдачи (project-scoped v_* + tier) по-прежнему материализует общий
	// реконсайлер ниже, а не рука.

	// SYNCHRONOUSLY materialize the
	// per-object access on the just-committed invite-flow objects so the owner /
	// account-admin per-object admin/v_* tuple is observable when the Operation
	// reports done — closing the GET-after-create race the async event drain (the
	// co-committed EmitReconcileEvent rows above) would otherwise lose under the flat
	// model. Best-effort/non-fatal: rows are durably committed; reconcile event +
	// sweep backstop. nil-safe.
	if haveAB {
		// Materialize the invite grant's OWN membership (per-object v_* + tier from the
		// role's verbs) through the unified reconciler — Design-B verb-bearing parity
		// with AccessBindingService.Create (the invitee gets v_get/v_update on the
		// granted project, not just `editor`). nil-safe / non-fatal (sweep
		// backstops).
		uc.reconcileBinding(ctx, createdAB.ID)
		// Also reconcile the iam_access_binding OBJECT so the owner/account-admin's
		// per-object admin tuple on the new binding materializes (flat model).
		uc.reconcileObject(ctx, "iam.accessBinding", string(createdAB.ID))
	}
	if userIsNew {
		uc.reconcileObject(ctx, "iam.user", string(user.ID))
	}

	// The Kratos magic-link
	// step that used to run here was removed; activation of the freshly
	// invited PENDING row is now the broker's responsibility.
	_ = opID

	return marshalUser(user)
}

// reconcileObject runs the post-commit synchronous per-object materialization via the
// ADDITIVE forward fast-path (nil-safe, non-fatal — logs and proceeds; the co-committed
// reconcile event + periodic sweep are the at-least-once backstop). Both invite-flow
// objects it materializes (the brand-new iam.user + the project-scoped iam.accessBinding)
// have NO prior members, so the forward path stays additive — the throughput hot-path —
// instead of the FULL EXCLUSIVE ReconcileObject that serialized on the account's single
// owner binding under a parallel invite burst. The FULL ReconcileObject REMAINS the async
// at-least-once backstop, driven by the co-committed reconcile events emitted in doInvite.
func (uc *InviteUserUseCase) reconcileObject(ctx context.Context, objectType, objectID string) {
	if uc.reconciler == nil {
		return
	}
	if rerr := uc.reconciler.ReconcileObjectForwardNoStale(ctx, objectType, objectID); rerr != nil && uc.logger != nil {
		uc.logger.Error("invite user: object forward reconcile failed (event/sweep will retry)",
			"object_type", objectType, "object_id", objectID, "err", rerr)
	}
}

// reconcileBinding runs the post-commit synchronous grant-membership materialization
// for the invite-flow AccessBinding (nil-safe, non-fatal). It drives the unified
// reconciler so the grant emits the per-object verb-bearing v_* (+ back-compat tier)
// tuples derived from the granted role's verbs — Design-B parity with
// AccessBindingService.Create. The periodic sweep + the binding's reconcile-event
// backstop a transient failure.
func (uc *InviteUserUseCase) reconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) {
	if uc.reconciler == nil {
		return
	}
	if rerr := uc.reconciler.ReconcileBinding(ctx, bindingID); rerr != nil && uc.logger != nil {
		uc.logger.Error("invite user: binding grant reconcile failed (sweep will retry)",
			"binding_id", string(bindingID), "err", rerr)
	}
}

// resolveCanonicalSubjectID returns the user-row id the api-gateway resolves
// the invitee's JWT to — the subject a project-scoped AccessBinding (and its
// FGA tuple) must be granted to so the per-RPC authz Check finds a path.
//
// The gateway resolves a JWT via InternalIAMService.LookupSubject, which reads
// the identity's rows by external_id ordered created_at ASC and answers with
// the first one that may authenticate (the oldest ACTIVE row of the identity).
// With the user-per-Account model one identity has N rows (one per Account);
// the invite-flow works on the per-Account row in `in.AccountID`, which is
// NOT necessarily that oldest ACTIVE row:
//
//   - the invitee may ALREADY be ACTIVE in another Account (e.g. a bootstrap
//     personal Account) — that older row carries the external_id and is what
//     the gateway resolves; the just-created per-Account PENDING row has an
//     empty external_id, so the identity lookup never reaches it;
//   - so a project-grant on the per-Account row's id would be `no path` for
//     the gateway-resolved subject.
//
// AccessBinding.subject_id is Account-agnostic, so this resolves the canonical
// (gateway-visible) identity row by EMAIL (the invitee identifier the invite
// request carries — the per-Account row's external_id may still be empty at
// AB-creation time): the oldest ACTIVE user-row with that email. When the
// invitee has no ACTIVE row anywhere (a genuinely new invitee who has never
// signed in), it falls back to the per-Account row's own id — once that
// PENDING row is activated by first-login it becomes the identity's row.
// Best-effort: any lookup error falls back to `perAccountRow.ID`.
func (uc *InviteUserUseCase) resolveCanonicalSubjectID(
	ctx context.Context, perAccountRow domain.User, email domain.Email,
) domain.SubjectID {
	fallback := domain.SubjectID(perAccountRow.ID)
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return fallback
	}
	defer func() { _ = rd.Rollback(ctx) }()
	actives, err := rd.Users().FindActiveByEmail(ctx, email)
	if err != nil || len(actives) == 0 {
		return fallback
	}
	// FindActiveByEmail is ordered created_at ASC — actives[0] is the oldest
	// ACTIVE row, exactly the row LookupSubject (and thus the gateway) resolves
	// the invitee's JWT to.
	canonical := domain.SubjectID(actives[0].ID)
	if uc.logger != nil && string(canonical) != string(perAccountRow.ID) {
		uc.logger.Info("invite: project-grant bound to canonical identity row",
			"per_account_row", string(perAccountRow.ID),
			"canonical_row", string(canonical),
			"email", string(email))
	}
	return canonical
}

// defaultDisplayName — extract local-part из email (до '@'); usable как
// placeholder display_name для PENDING-row до first-login.
func defaultDisplayName(email domain.Email) domain.DisplayName {
	s := string(email)
	if i := strings.IndexByte(s, '@'); i > 0 {
		return domain.DisplayName(s[:i])
	}
	return domain.DisplayName(s)
}
