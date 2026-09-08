// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// internal_upsert.go — InternalUserService.UpsertFromIdentity.
//
// **PENDING-aware flow**:
//
//   step 1: FindPendingByEmail(payload.Email)
//           → если N PENDING-rows: ActivateInvite каждой (set external_id +
//             display_name, status='ACTIVE'); emit member-outbox events.
//
//   step 2: FindActiveByExternalID(payload.ExternalID)
//           → собираем ACTIVE-rows (включая только что активированные) для
//             resolve user-row и owns-zero-accounts gate (D-9 primary context).
//
//   step 3 (RC-2): активация invite (step 1) co-commit'ит в ТОЙ ЖЕ writer-tx
//           member-hierarchy-tuple `account:<A>#account@iam_user:<id>` через
//           w.EmitFGARelationWrite (рядом с ActivateInvite UPDATE + iam.user.updated
//           audit, до Commit; запрет #10). Без него member не виден в account инвайтера.
//
//   step 4 (RC-5 bootstrap): срабатывает ВСЕГДА, когда у разрешенного/активированного
//           user-row число owned-account-ов (accounts.owner_user_id==userID) == 0 —
//           bootstrapPersonalResources:
//             - genuinely-new identity → INSERT user (DEFERRABLE FK) + personal Account/Project.
//             - invited+activated → user-row УЖЕ существует → Get (БЕЗ повторного
//               InsertActive — иначе 23505 на UNIQUE(external_id)) + только personal
//               Account/Project/AB/bootstrapTuples для существующего user-id.
//             - INSERT personal account (owner_user_id=user.id, name="personal-cloud-<tail>").
//             - INSERT "default" project + 2 self-admin AB (account + project).
//             - bootstrapTuples co-committed intent'ами в bootstrap-tx.
//           Идемпотентно: повторная активация → owns-zero==false → второй bootstrap НЕ срабатывает.
//
// Returns: User (bootstrap-row либо firstActivated/existing).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// OwnerBindingReconciler — narrow port (rbac-contract-a-flat-fallout): materialize
// the bootstrap user's owner-binding per-object membership (scope-self verb-bearing
// tuples on account:<A> + the owner `*.*` ARM_ANCHOR forward over the account's
// content — project, iam-native, cross-service) after the bootstrap tx commits.
// Implemented by reconcile.Reconciler — the SAME single materialization path as
// Account.Create's owner auto-binding (account/create.go OwnerBindingReconciler).
// Under the FLAT rights model the hierarchy parent-pointers grant no access, so
// without this the bootstrap user is 403 on the content of their own account.
// nil-safe: when unwired the periodic sweep materializes it, just not synchronously.
type OwnerBindingReconciler interface {
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// UpsertFromIdentityInput — параметры (ExternalID required для non-bootstrap
// path; Email обязателен для PENDING-matching).
type UpsertFromIdentityInput struct {
	ExternalID  domain.ExternalSubject
	Email       domain.Email
	DisplayName domain.DisplayName
}

type UpsertFromIdentityUseCase struct {
	repo    Repo
	opsRepo operations.Repo

	// logger — диагностика необязательных пост-коммитных шагов (активация
	// приглашения, материализация собственнической выдачи).
	//
	// Рядом стояло поле двери решения. На bootstrap-пути этот use-case создаёт
	// User + Account + Project + две выдачи в обход соседних use-case'ов и обязан
	// сам эмитить всё, что те пишут, — но эмитит он это СТРОКАМИ ЖУРНАЛА в своей
	// writer-tx, а не через дверь. После снятия внешнего движка поле перестало
	// читаться какой-либо веткой вовсе и снято: значение, которое присваивают и
	// не читают, выглядит как провязанная зависимость и ею не является.
	logger *slog.Logger
	// reconciler — rbac-contract-a-flat-fallout: post-commit owner-binding
	// materialization for the bootstrap path (parity with Account.Create). nil-safe.
	reconciler OwnerBindingReconciler
	// activations — счётчик исходов активации приглашения. nil-safe.
	activations ActivationObserver
}

// Исходы активации приглашения. Набор ЗАКРЫТ и приходит из этих констант,
// никогда из запроса, поэтому кардинальность метки не растёт с трафиком.
//
// Три исхода, а не один: счётчик ОДНИХ ОТКАЗОВ не отличает «отказов не было» от
// «активаций не было вовсе», и «ноль за всю жизнь» читалось бы как здоровье там,
// где путь мёртв (security.md §Hardening-инварианты п.8).
const (
	// activationOutcomeActivated — приглашение активировано.
	activationOutcomeActivated = "activated"
	// activationOutcomeAlreadyActive — строку уже активировал конкурент.
	// Ожидаемый исход гонки первого входа, а НЕ отказ: считается отдельно
	// именно затем, чтобы не разбавлять счётчик отказов штатным событием.
	activationOutcomeAlreadyActive = "already_active"
	// activationOutcomeFailed — активация не удалась. Вход прерывается.
	activationOutcomeFailed = "failed"
)

// ActivationObserver — наблюдатель исходов активации приглашения.
//
// Порт объявлен здесь, а реализация живёт в слое наблюдаемости: use-case не
// знает про prometheus (иначе адаптер протёк бы в бизнес-логику).
type ActivationObserver interface {
	IncInviteActivation(outcome string)
}

// WithActivationObserver wires the invite-activation outcome counter. nil-safe.
func (uc *UpsertFromIdentityUseCase) WithActivationObserver(obs ActivationObserver) *UpsertFromIdentityUseCase {
	uc.activations = obs
	return uc
}

func (uc *UpsertFromIdentityUseCase) observeActivation(outcome string) {
	if uc.activations != nil {
		uc.activations.IncInviteActivation(outcome)
	}
}

func NewUpsertFromIdentityUseCase(r Repo, opsRepo operations.Repo) *UpsertFromIdentityUseCase {
	return &UpsertFromIdentityUseCase{repo: r, opsRepo: opsRepo}
}

// WithReconciler wires the post-commit owner-binding materializer for the bootstrap
// path (rbac-contract-a-flat-fallout). Without it the bootstrap user's owner-binding
// is only materialized by the periodic sweep (not synchronously) — under the flat
// model the user is then 403 on their own account's content until the sweep runs.
// nil-safe.
func (uc *UpsertFromIdentityUseCase) WithReconciler(r OwnerBindingReconciler) *UpsertFromIdentityUseCase {
	uc.reconciler = r
	return uc
}

// WithLogger провязывает диагностику необязательных пост-коммитных шагов.
//
// Прежде метод назывался `WithRelationStore` и принимал дверь решения вторым
// параметром — но исхода она не меняла, а после снятия внешнего движка перестала
// читаться вовсе. Имя, обещающее провязку источника вердикта, на такой функции
// вводит в заблуждение сильнее, чем отсутствие функции.
func (uc *UpsertFromIdentityUseCase) WithLogger(logger *slog.Logger) *UpsertFromIdentityUseCase {
	uc.logger = logger
	return uc
}

func (uc *UpsertFromIdentityUseCase) Execute(ctx context.Context, in UpsertFromIdentityInput) (*operations.Operation, error) {
	if in.ExternalID == "" {
		return nil, shared.InvalidArg("external_id", "external_id required")
	}
	if err := in.ExternalID.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	if in.Email != "" {
		if err := in.Email.Validate(); err != nil {
			return nil, shared.MapValidationErr(err)
		}
	}
	if in.DisplayName != "" {
		if err := in.DisplayName.Validate(); err != nil {
			return nil, shared.MapValidationErr(err)
		}
	}

	// Operation.metadata.user_id ОБЯЗАН содержать id того row, который
	// use-case реально вернет. (A naïve throwaway `ids.NewID()` would
	// diverge from the existing-row id returned on the conflict-path →
	// consumers like fixture-script would see a stale id.)
	//
	// Решение: синхронно (до создания Operation) определить, существует ли уже
	// ACTIVE-row по external_id. Если да — metadata.user_id = existing id и
	// created=false. Если нет — кандидат на bootstrap, metadata.user_id =
	// новый id, created=true. doUpsert ниже принимает этот же id и для
	// bootstrap-path использует его, для conflict-path возвращает existing
	// (тот же, что мы уже резолвнули синхронно).
	resolvedID, willCreate, err := uc.resolveUserID(ctx, in)
	if err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Upsert user from identity ext=%s", in.ExternalID),
		&iamv1.UpsertFromIdentityMetadata{UserId: resolvedID, Created: willCreate},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	// Audit actor: the verified principal when one is present (admin-tooling
	// Upsert with a JWT); for the Kratos provision-hook there is no user
	// principal, so the actor is the system/bootstrap identity — recorded, never
	// fabricated (5.2-14). Captured sync (the async worker ctx may not carry it).
	actor := authzguard.PrincipalUserID(ctx)
	if actor == "" {
		actor = "system"
	}

	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doUpsert(ctx, resolvedID, in, actor)
	})
	return &op, nil
}

// resolveUserID синхронно определяет id user-row, который вернет UpsertFromIdentity,
// и флаг created (true → новый bootstrap-row). Это нужно, чтобы Operation.metadata
// сразу нес верный (existing-либо-новый) user_id, а не throwaway-id.
//
// Логика зеркалит doUpsert:
//   - если по external_id уже есть ACTIVE-row → возвращаем его id, created=false;
//   - если есть PENDING-row(ы) по email (будут активированы) → возвращаем id
//     первого PENDING-row, created=false (Activate сохраняет существующий id);
//   - иначе → новый id (bootstrap), created=true.
//
// Между resolveUserID и doUpsert возможна гонка (другой login активирует тот же
// invite). Это допустимо: doUpsert остается источником истины для самого row,
// а metadata — best-effort hint; критичный для consumers сценарий «conflict →
// existing id» детерминирован, т.к. ACTIVE/PENDING-row'ы уже в БД.
func (uc *UpsertFromIdentityUseCase) resolveUserID(ctx context.Context, in UpsertFromIdentityInput) (string, bool, error) {
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return "", false, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	// Читаем строки КАК ЕСТЬ и судим по состоянию — не спрашиваем «дай активные».
	//
	// Фильтр `invite_status='ACTIVE'` отвечает пустым множеством на
	// ЗАБЛОКИРОВАННУЮ личность, а пустое множество здесь означает «личности не
	// существует» и ведёт в ветку bootstrap'а: заблокированному выдавалась
	// свежая ACTIVE-строка, а вместе с ней аккаунт, проект и админские права на
	// них. Хук срабатывает и на ВХОДЕ, не только на регистрации, — то есть
	// блокировку снимал сам заблокированный, просто войдя ещё раз. Индекс
	// уникальности этому не мешает: он покрывает только ACTIVE-строки.
	existing, err := rd.Users().FindByExternalIDInStatuses(ctx, in.ExternalID,
		[]domain.InviteStatus{domain.InviteStatusActive, domain.InviteStatusBlocked})
	if err != nil {
		return "", false, shared.MapRepoErr(err)
	}
	for _, u := range existing {
		// Членство может быть разным по аккаунтам: первая строка, которой
		// аутентификация разрешена, и есть действующая личность.
		if u.InviteStatus.MayAuthenticate() {
			return string(u.ID), false, nil
		}
	}
	// Есть PENDING-invite(ы) по email → Activate сохранит существующий row-id.
	//
	// Проверяется ДО отказа ниже, и это не порядок ради порядка: блокировка
	// живёт на строке МЕМБЕРШИПА, то есть внутри конкретного аккаунта.
	// Приглашение в другой аккаунт — отдельное членство, которое тот аккаунт
	// выдал сам; отказать здесь значило бы позволить одному аккаунту запереть
	// человека везде, где его блокировать никто не собирался. PENDING-строка ещё
	// не несёт external_id (DB-CHECK), поэтому по нему она и не нашлась выше.
	if in.Email != "" {
		pendings, err := rd.Users().FindPendingByEmail(ctx, in.Email)
		if err != nil {
			return "", false, shared.MapRepoErr(err)
		}
		if len(pendings) > 0 {
			return string(pendings[0].ID), false, nil
		}
	}

	if len(existing) > 0 {
		// Личность есть, ни одному её членству аутентификация не разрешена, и
		// приглашения, которое завело бы новое, тоже нет. Это не «нет такой» — и
		// ответ обязан отличаться, иначе он снова уедет в ветку, которая заведёт
		// её заново.
		return "", false, status.Errorf(codes.FailedPrecondition,
			"identity %s is blocked and cannot be provisioned", in.ExternalID)
	}

	// Ни ACTIVE, ни BLOCKED, ни PENDING — bootstrap нового identity, новый id.
	return ids.NewID(domain.PrefixUser), true, nil
}

func (uc *UpsertFromIdentityUseCase) doUpsert(ctx context.Context, candidateUserID string, in UpsertFromIdentityInput, actor string) (*anypb.Any, error) {
	// Step 1: activate any PENDING-rows by email. firstActivated != nil ⇒ an
	// activation happened (its id is the resolved/activated user-row; RC-5 bootstrap
	// gate no longer keys off a separate activatedAny flag — owns-zero-accounts on
	// the resolved id is the sole predicate).
	var firstActivated *domain.User
	if in.Email != "" {
		rd, err := uc.repo.Reader(ctx)
		if err != nil {
			return nil, shared.MapRepoErr(err)
		}
		pendings, err := rd.Users().FindPendingByEmail(ctx, in.Email)
		_ = rd.Rollback(ctx)
		if err != nil {
			return nil, shared.MapRepoErr(err)
		}

		for _, p := range pendings {
			w, werr := uc.repo.Writer(ctx)
			if werr != nil {
				return nil, shared.MapRepoErr(werr)
			}
			activated, aerr := w.UsersW().ActivateInvite(ctx, p.ID, in.ExternalID, in.DisplayName)
			if aerr != nil {
				_ = w.Rollback(ctx)
				// Строку уже активировал конкурент (она больше не PENDING) — это
				// ожидаемый исход гонки первого входа, и он пропускается намеренно.
				if errors.Is(aerr, iamerr.ErrNotFound) {
					uc.observeActivation(activationOutcomeAlreadyActive)
					continue
				}
				// Всё остальное — ОТКАЗ, и он не проглатывается. Прежняя редакция
				// делала `continue` безусловно, обещая в комментарии обратное:
				// вход завершался успехом, приглашение оставалось неактивированным,
				// и узнать об этом было неоткуда.
				uc.observeActivation(activationOutcomeFailed)
				if uc.logger != nil {
					// Коррелируем по идентификатору строки: почта end-user'а в лог
					// не пишется ни на успешном, ни на отказном пути.
					uc.logger.Error("invite activation failed",
						"user_id", string(p.ID), "error", aerr.Error())
				}
				return nil, shared.MapRepoErr(aerr)
			}
			// Activate-invite is the User update branch (mirror-fields email/
			// display_name applied) — emit iam.user.updated atomically with the
			// activation, in the SAME writer-tx (запрет #10), before Commit.
			if eerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventUserUpdated,
				TenantAccountID: string(activated.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "user",
					"resource_id":    string(activated.ID),
					"account_id":     string(activated.AccountID),
					"changed_fields": []string{"external_id", "display_name", "invite_status"},
				},
			}); eerr != nil {
				_ = w.Rollback(ctx)
				return nil, shared.MapRepoErr(eerr)
			}
			// RC-2: co-commit the member hierarchy-tuple intent in the SAME Step-1
			// writer-tx as the ActivateInvite UPDATE + the iam.user.updated audit-event
			// (запрет #10 / SEC-D). Без него активированный member не имеет FGA-ребра
			// в account инвайтера → его AccountService.List не видит этот account.
			// Tuple-форма byte-идентична bootstrapTuples hierarchy-блоку
			// (account:<A>#account@iam_user:<id>). It is the SAME in-tx outbox
			// mechanism the bootstrap path uses — NOT post-commit best-effort
			// записью ПОСЛЕ коммита (снята; она теряла кортеж при недоступности FGA
			// outage and is not co-commit-able, violating ban #10). Idempotent:
			// re-activation re-emits the same intent → at-least-once + idempotent
			// drain → exactly one FGA edge.
			if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{{
				User:     fmt.Sprintf("account:%s", activated.AccountID),
				Relation: "account",
				Object:   fmt.Sprintf("iam_user:%s", activated.ID),
			}}); ferr != nil {
				_ = w.Rollback(ctx)
				return nil, shared.MapRepoErr(ferr)
			}
			// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event in
			// the SAME activation writer-tx (ban #10) so the now-ACTIVE invitee user
			// forward-materializes under the inviter-account's owner `*.*` binding —
			// the flat rights model dropped the iam_user `from account` ACCESS cascade,
			// so the parent-pointer above no longer grants the owner Get on the user.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.user", string(activated.ID)); rerr != nil {
				_ = w.Rollback(ctx)
				return nil, shared.MapRepoErr(rerr)
			}
			if cerr := w.Commit(ctx); cerr != nil {
				_ = w.Rollback(ctx)
				return nil, shared.MapRepoErr(cerr)
			}
			uc.observeActivation(activationOutcomeActivated)
			if firstActivated == nil {
				ac := activated
				firstActivated = &ac
			}
		}
	}

	// Step 2: lookup ACTIVE rows by external_id (после step 1 они могут включать
	// activated-rows; нам нужен count для bootstrap-decision).
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	allRows, err := rd.Users().FindByExternalIDInStatuses(ctx, in.ExternalID,
		[]domain.InviteStatus{domain.InviteStatusActive, domain.InviteStatusBlocked})
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Тот же вердикт, что и в синхронном гейте выше, повторён здесь намеренно:
	// между резолвом и этим шагом строку могли заблокировать, и без проверки
	// worker снова прочитал бы пустое множество ACTIVE как «личности нет» и
	// завёл бы её заново — ровно тем путём, который гейт закрывает.
	var existing []domain.User
	for _, u := range allRows {
		if u.InviteStatus.MayAuthenticate() {
			existing = append(existing, u)
		}
	}
	if len(existing) == 0 && len(allRows) > 0 && firstActivated == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"identity %s is blocked and cannot be provisioned", in.ExternalID)
	}

	// RC-5 (owner-mandated, переворачивает прежний by-design D-7): bootstrap
	// personal Account + "default" Project + 2 self-admin AB + bootstrapTuples
	// срабатывает ВСЕГДА, когда у разрешенного/активированного user-row число
	// owned-account-ов (accounts.owner_user_id == userID) == 0 — независимо от
	// activatedAny. Раньше gate был `!activatedAny && len(existing)==0`, из-за
	// чего активированный invitee (activatedAny=true) НЕ получал собственный
	// base Account/Project. Любой пользователь, включая приглашенного, должен
	// иметь дефолтный проект и аккаунт.
	//
	// Тонкость invited-vs-new-identity:
	//   - genuinely-new identity (нет PENDING, нет ACTIVE) → resolvedUserID =
	//     candidateUserID (новый id), insertUser=true (INSERT user-row + bootstrap).
	//   - invited+activated user → user-row УЖЕ существует (InsertPending +
	//     ActivateInvite сохранили его id) → resolvedUserID = activated id,
	//     insertUser=false. Повторный InsertActive вызвал бы 23505 на
	//     UNIQUE(external_id) — поэтому bootstrap создает только personal Account/
	//     Project/AB/bootstrapTuples для СУЩЕСТВУЮЩЕГО user-id.
	resolvedUserID, newIdentity := uc.resolveBootstrapTarget(candidateUserID, firstActivated, existing)

	ownedAccounts, err := uc.countOwnedAccounts(ctx, domain.UserID(resolvedUserID))
	if err != nil {
		return nil, err
	}
	if ownedAccounts == 0 {
		bootstrap, err := uc.bootstrapPersonalResources(ctx, resolvedUserID, in, actor, newIdentity)
		if err != nil {
			return nil, err
		}
		return marshalUser(bootstrap)
	}

	// Вернуть тот же row, чей id уже записан в Operation.metadata
	// (resolveUserID синхронно зафиксировал его). Иначе metadata.user_id
	// и response.user разъезжаются.
	if firstActivated != nil && string(firstActivated.ID) == candidateUserID {
		return marshalUser(*firstActivated)
	}
	for i := range existing {
		if string(existing[i].ID) == candidateUserID {
			return marshalUser(existing[i])
		}
	}
	// Fallback (гонка между resolveUserID и doUpsert): сохраняем прежний
	// priority — firstActivated (D-9), затем любой existing ACTIVE-row.
	if firstActivated != nil {
		return marshalUser(*firstActivated)
	}
	return marshalUser(existing[0])
}

// resolveBootstrapTarget определяет, для какого user-id выполняется
// owns-zero-accounts gate (RC-5), и является ли он genuinely-new identity
// (требует INSERT user-row) либо уже-существующим (invited+activated → row уже
// есть, повторный INSERT запрещен).
//
//   - genuinely-new identity (нет activated, нет existing) → candidateUserID,
//     newIdentity=true.
//   - invited+activated → id первого активированного row, newIdentity=false.
//   - existing ACTIVE без активации → matching existing id (либо первый),
//     newIdentity=false.
func (uc *UpsertFromIdentityUseCase) resolveBootstrapTarget(
	candidateUserID string, firstActivated *domain.User, existing []domain.User,
) (userID string, newIdentity bool) {
	if firstActivated == nil && len(existing) == 0 {
		return candidateUserID, true
	}
	if firstActivated != nil {
		return string(firstActivated.ID), false
	}
	for i := range existing {
		if string(existing[i].ID) == candidateUserID {
			return candidateUserID, false
		}
	}
	return string(existing[0].ID), false
}

// countOwnedAccounts — число account'ов, владельцем которых является userID
// (RC-5 owns-zero-accounts gate-предикат). Над существующей колонкой
// accounts.owner_user_id (не новая таблица/колонка). Read через own reader-tx.
func (uc *UpsertFromIdentityUseCase) countOwnedAccounts(ctx context.Context, userID domain.UserID) (int, error) {
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return 0, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	n, err := rd.Accounts().CountAccountsByOwner(ctx, userID)
	if err != nil {
		return 0, shared.MapRepoErr(err)
	}
	return n, nil
}

// bootstrapPersonalResources — bootstrap TX с DEFERRABLE FK (RC-5).
//
// Любой пользователь (genuinely-new identity ИЛИ invited+activated) без
// собственного account'а получает один personal Account + один "default" Project
// + 2 self-grant AccessBinding (account-admin + project-admin) + bootstrapTuples.
//
//   - newIdentity=true  — genuinely-new identity: INSERT user-row первым (FK на
//     account отложен, DEFERRABLE chicken-and-egg), затем personal Account/Project.
//     Emits iam.user.created audit.
//   - newIdentity=false — invited+activated user: user-row УЖЕ существует
//     (ActivateInvite сохранил id) — повторный InsertActive вызвал бы 23505 на
//     UNIQUE(external_id). Поэтому загружаем существующий row через Get, НЕ
//     вставляем повторно; создаем только personal Account/Project/AB/tuples для
//     существующего user-id. iam.user.created НЕ эмитится (user-identity не нова —
//     активация уже эмитировала iam.user.updated в Step-1).
//
// Кластерное право администратора этот путь не эмитит вовсе: его ставит отдельный
// реконсайлер старта (`seed.RunBootstrapAdmin`) по адресу почты из настроек.
func (uc *UpsertFromIdentityUseCase) bootstrapPersonalResources(
	ctx context.Context, candidateUserID string, in UpsertFromIdentityInput, actor string, newIdentity bool,
) (domain.User, error) {
	userID := domain.UserID(candidateUserID)
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	prjID := domain.ProjectID(ids.NewID(domain.PrefixProject))

	// rbac-contract-a-flat-fallout: the account-scoped self-binding is the OWNER
	// binding (parity with Account.Create doCreate) — the signup user IS the owner
	// of their personal account. The owner role (OwnerRoleID, migration 0035)
	// carries the `*.*.*` wildcard whose ARM_ANCHOR forward-materializes per-object
	// access over the account's content (project, iam-native, cross-service). Under
	// the flat rights model the prior admin-role binding (plus inert hierarchy
	// pointers) granted the user NO access on their own account's content → 403.
	ownerAB := domain.AccessBinding{
		ID:                 domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:        domain.SubjectTypeUser,
		SubjectID:          domain.SubjectID(userID),
		RoleID:             domain.OwnerRoleID,
		ResourceType:       domain.ResourceType("account"),
		ResourceID:         string(accID),
		Scope:              domain.ScopeAccount,
		GrantedByUserID:    domain.UserID(actor),
		DeletionProtection: true,
		Subjects:           []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(userID)}},
		// F8: whole-account owner grant (explicit allInScope).
		Target: domain.AccessTarget{AllInScope: true},
	}
	// project-scoped self-grant stays the "admin" system-role (explicit
	// project-admin grant). The user's ACCESS on the project (and its content) is
	// ALSO covered by the owner ARM_ANCHOR forward-mat over iam.project — this row
	// is the explicit binding parity (so the project shows in the user's grants).
	// The pinned deterministic id of the system `admin` role is the single source
	// of truth in domain; project vs cluster privilege is keyed on binding Scope,
	// not the id (so reusing the constant is not a privilege bug).
	projectAB := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(userID),
		RoleID:       domain.RoleID(domain.ClusterAdminRoleID),
		ResourceType: domain.ResourceType("project"),
		ResourceID:   string(prjID),
		// F8: whole-project grant (explicit allInScope).
		Target: domain.AccessTarget{AllInScope: true},
	}
	// Self-validating-domain (parity with account/create.go): the internally-built
	// owner-binding must be well-formed BEFORE Insert. A failure means field drift,
	// not bad input — fail-closed (the worker-tx rolls back).
	if verr := ownerAB.Validate(); verr != nil {
		return domain.User{}, shared.MapValidationErr(verr)
	}

	// Captured from inside the writer-tx so the post-commit owner-binding reconcile
	// (forward-mat over the account's content) can drive the committed binding id.
	ownerBindingID := ownerAB.ID

	user, err := shared.DoWithWriteTx(ctx, uc.repo,
		func(ctx context.Context, w Writer) (domain.User, error) {
			// 0. ban #10 — close the owns-zero-accounts TOCTOU. The outer
			// countOwnedAccounts pre-check (uc.countOwnedAccounts above) runs in
			// its OWN reader-tx, so two concurrent bootstraps for the SAME resolved
			// user-id both read count==0 and both INSERT a distinct personal
			// account (random 'personal-cloud-<rand>' name → accounts_name_unique
			// never fires; owner_user_id has no cardinality bound). "One personal
			// account per user" cannot be a partial UNIQUE (a user may legitimately
			// own many accounts), so we serialize same-user bootstraps with a
			// tx-scoped advisory lock and RE-CHECK the owned-account count INSIDE
			// this writer-tx: the loser blocks until the winner commits, then sees
			// count>0 and returns the already-bootstrapped user without inserting a
			// duplicate. (newIdentity=true callers each carry a distinct fresh id →
			// different lock key; they are serialized instead by UNIQUE(external_id)
			// on InsertActive below — unchanged.)
			if lerr := w.AdvisoryXactLock(ctx, "iam:bootstrap:"+candidateUserID); lerr != nil {
				return domain.User{}, lerr
			}
			if owned, cerr := w.Accounts().CountAccountsByOwner(ctx, userID); cerr != nil {
				return domain.User{}, cerr
			} else if owned > 0 {
				// A concurrent bootstrap won the lock and already created this
				// user's personal account — return the existing user-row.
				return w.Users().Get(ctx, userID)
			}

			// 1. Resolve the user-row.
			//   - newIdentity=true → INSERT user первым (FK на account отложен).
			//   - newIdentity=false → invited+activated row уже существует; Get его,
			//     БЕЗ повторного InsertActive (иначе 23505 на UNIQUE(external_id)).
			var (
				user domain.User
				err  error
			)
			if newIdentity {
				dn := in.DisplayName
				if dn == "" {
					dn = defaultDisplayName(in.Email)
				}
				user, err = w.UsersW().InsertActive(ctx, domain.User{
					ID:           userID,
					AccountID:    accID,
					ExternalID:   in.ExternalID,
					Email:        in.Email,
					DisplayName:  dn,
					InviteStatus: domain.InviteStatusActive,
				})
				if err != nil {
					// Concurrency contract (migration 0002): DB UNIQUE(email) +
					// UNIQUE(external_id WHERE !='') enforce one user-row per
					// identity. Concurrent bootstraps for the same Kratos
					// identity lose the race here with 23505 (mapped to
					// ErrAlreadyExists). Operator-facing recovery: the client
					// retries UpsertFromIdentity, and the second attempt hits the
					// fast-path SELECT by external_id and returns the
					// already-bootstrapped row. This is complete as-is — the DB
					// constraint is the authoritative dup guard; a single
					// ON CONFLICT statement would be an equivalent alternative,
					// not a missing piece.
					return domain.User{}, err
				}
			} else {
				// invited+activated: переиспользуем существующий user-row (его id =
				// candidateUserID; account_id = account инвайтера — НЕ меняется,
				// остается primary context). НЕ вызываем InsertActive повторно.
				user, err = w.Users().Get(ctx, userID)
				if err != nil {
					return domain.User{}, err
				}
			}

			// 2. INSERT account. Name = "personal-cloud-<6-char tail>"
			// ("Personal cloud"). Имя ВЫБРАНО, а не подставлено умолчанием:
			// личный аккаунт заводится без участия арендатора, и «personal-cloud-…»
			// он прочтёт, а идентификатор — нет. Форме дерева оно отвечает как
			// есть (`pkg/validate/nameform`): строчные, дефис в середине, хвост —
			// крокфордово тело идентификатора.
			tail := strings.ToLower(string(accID[len(accID)-6:]))
			if _, err := w.AccountsW().Insert(ctx, domain.Account{
				ID:          accID,
				Name:        domain.AccountName("personal-cloud-" + tail),
				OwnerUserID: userID,
				Labels:      domain.Labels{},
			}); err != nil {
				return domain.User{}, err
			}

			// 3. INSERT default project.
			if _, err := w.ProjectsW().Insert(ctx, domain.Project{
				ID:        prjID,
				AccountID: accID,
				Name:      domain.ProjectName("default"),
				Labels:    domain.Labels{},
			}); err != nil {
				return domain.User{}, err
			}

			// 4. INSERT the owner (account-scoped) + project-admin self-grant rows.
			//   - owner-binding: + multi-subject set + OWNER-BINDING-lifecycle ledger
			//     (so a symmetric revoke removes exactly what was emitted) + grant audit,
			//     mirroring account/create.go doCreate.
			createdOwner, oerr := w.AccessBindingsW().Insert(ctx, ownerAB)
			if oerr != nil {
				return domain.User{}, oerr
			}
			if serr := w.AccessBindingsW().InsertSubjects(ctx, createdOwner.ID, ownerAB.Subjects); serr != nil {
				return domain.User{}, serr
			}
			// Record the OWNER-BINDING-lifecycle tuples in the emitted-tuple ledger
			// (review #7 symmetric revoke — parity with account/create.go
			// ownerBindingLedgerTuples): the owner self-grant + the binding-object
			// hierarchy pointer. The SEC-L cluster pointer is account-lifecycle and is
			// intentionally NOT part of the owner-binding's revoke set (survives revoke).
			if lerr := w.AccessBindingsW().InsertEmittedTuples(ctx, createdOwner.ID, []abrepo.RelationTuple{
				{User: "user:" + string(userID), Relation: "owner", Object: "account:" + string(accID)},
				{User: "account:" + string(accID), Relation: "account", Object: "iam_access_binding:" + string(createdOwner.ID)},
			}); lerr != nil {
				return domain.User{}, lerr
			}
			if aerr := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
				EventType:       abrepo.AuditEventTypeGranted,
				Actor:           actor,
				SubjectType:     string(domain.SubjectTypeUser),
				SubjectID:       string(userID),
				ResourceType:    "account",
				ResourceID:      string(accID),
				RoleID:          domain.OwnerRoleID,
				BindingID:       string(createdOwner.ID),
				TenantAccountID: string(accID),
			}); aerr != nil {
				return domain.User{}, aerr
			}
			ownerBindingID = createdOwner.ID
			createdProjectAB, err := w.AccessBindingsW().Insert(ctx, projectAB)
			if err != nil {
				return domain.User{}, err
			}
			// Состав субъектов записывается вместе с выдачей — иначе она
			// невидима форме вердикта, и человек не имеет прав на проекте,
			// который сам же и завёл. Замер на живом стенде: из 111 выдач без
			// состава 110 пришли отсюда.
			if serr := w.AccessBindingsW().InsertSubjects(ctx, createdProjectAB.ID,
				[]domain.Subject{{Type: projectAB.SubjectType, ID: projectAB.SubjectID}}); serr != nil {
				return domain.User{}, serr
			}

			// 5. Durable audit_outbox iam.user.created in the SAME bootstrap tx
			// (запрет #10) — atomic with the user INSERT. ТОЛЬКО для genuinely-new
			// identity: создается новая user-identity → iam.user.created scoped к
			// ее personal Account. Для invited+activated user (newIdentity=false)
			// user-identity НЕ нова — Step-1 уже эмитировал iam.user.updated; здесь
			// мы лишь добавляем personal-resource'ы существующему user-id, поэтому
			// второй iam.user.created был бы ложным дублем identity-creation.
			if newIdentity {
				if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
					EventType:       auditEventUserCreated,
					TenantAccountID: string(accID),
					Payload: map[string]any{
						"actor":         actor,
						"resource_type": "user",
						"resource_id":   string(user.ID),
						"account_id":    string(accID),
						"email":         string(user.Email),
						"display_name":  string(user.DisplayName),
					},
				}); aerr != nil {
					return domain.User{}, aerr
				}
			}

			// 6. Эмитим ВСЕ FGA-tuples bootstrap-графа intent'ами в kaname.fga_outbox
			// в ТОЙ ЖЕ bootstrap-tx (SEC-D, запрет #10).
			// Bootstrap идет в обход CreateAccount/CreateProject/CreateAccessBinding
			// use-case'ов (которые обычно пишут эти tuples), поэтому без этого блока
			// новый User / Account / Project недоступны через per-resource RPC — FGA
			// Check `no path`. Раньше блок был best-effort post-commit «Non-fatal»
			// (терялся на любом FGA-сбое); теперь intent co-committed in-tx и
			// доставляется live drainer'ом at-least-once + идемпотентно — owner-self-
			// grant (D-4: невосстановим reconciler'ом) гарантирован.
			if ferr := w.EmitFGARelationWrite(ctx,
				bootstrapTuples(userID, accID, prjID, ownerBindingID, projectAB)); ferr != nil {
				return domain.User{}, ferr
			}

			return user, nil
		})
	if err != nil {
		return domain.User{}, err
	}

	// Post-commit: materialize the owner-binding's per-object membership (scope-self
	// verb-bearing on account:<A> + the owner `*.*` ARM_ANCHOR forward over the
	// account's content — the "default" project, the bootstrap iam-native rows, and
	// any cross-service content). Parity with Account.Create doCreate. nil-safe; the
	// co-committed reconcile-event drain + periodic sweep are the at-least-once
	// backstop. Non-fatal to bootstrap — the account + owner-binding are durably
	// committed; a sweep retries on any reconcile error.
	if uc.reconciler != nil {
		if rerr := uc.reconciler.ReconcileBinding(ctx, ownerBindingID); rerr != nil && uc.logger != nil {
			uc.logger.Error("bootstrap: owner-binding reconcile failed (sweep will retry)",
				"account_id", string(accID), "binding_id", string(ownerBindingID), "err", rerr)
		}
	}

	return user, nil
}

// bootstrapTuples строит ВСЕ FGA-tuples bootstrap-графа identity для co-commit
// intent'ами в kaname.fga_outbox (SEC-D). Раньше эти
// tuples писались best-effort post-commit (`WriteTuples` + снятый с тех пор писатель
// «Non-fatal») — теперь это чистый builder, а emit делает writer-tx:
//
//	user:<usr>#owner            @account:<acc> — owner grant (зеркалит CreateAccount;
//	                                             D-4: невосстановим reconciler'ом)
//	user:<usr>#admin            @account:<acc> — account-admin self-grant (AB row)
//	user:<usr>#admin            @project:<prj> — project-admin self-grant (AB row)
//	iam_user:<usr>#account      @account:<acc> — user→account hierarchy
//	project:<prj>#account       @account:<acc> — project→account hierarchy
//	account:<acc>#cluster       @cluster:root  — SEC-L cluster pointer (account)
//	project:<prj>#cluster       @cluster:root  — SEC-L cluster pointer (project)
//	iam_access_binding:<ab>#project@project:<prj> — project-scoped AB hierarchy
//
// Account-scoped AccessBinding (accountAB) НЕ получает iam_access_binding
// hierarchy-tuple: FGA-тип `iam_access_binding` имеет только `project`-parent —
// account-scoped binding'и per-resource Get авторизуются через grant-tuples выше.
// ЗДЕСЬ СТОЯЛО «без `iam_user`-hierarchy-tuple per-resource UserService.Get/
// Update/Delete никогда не авторизуется» — И ЭТО НЕВЕРНО СО ДНЯ СНЯТИЯ ВНЕШНЕГО
// ДВИЖКА. Предка личности называет не этот кортеж, а цепь областей
// (`kaname.resource_scope_edge`), и берёт она его из таблицы членств (#944;
// прежде — из колонки строки). Читателя у самого кортежа на пути решения нет:
// атом плана ищет `admin`/`owner` НА ОБЪЕКТЕ-ПРЕДКЕ, а не отношение `account` на
// личности. Кортеж пишется тремя местами и не читается ни одним — предмет
// заведён отдельно (#946), здесь он назван, а не снят: уборка и отрыв — разные
// изменения.
//
// rbac-contract-a-flat-fallout: the `admin@account` self-grant tuple is DROPPED —
// the account-scoped binding is now the OWNER binding (OwnerRoleID), whose tier
// (admin via `*.*`) + per-object content access is materialized by the post-commit
// ReconcileBinding (the single materialization path, D-4). The `owner@account`
// grant tuple is retained (D-4 class — not reconstructible by the reconciler, the
// owner standing). TWO new tuples are added under the flat model:
//   - iam_user:<usr>#subject @ user:<usr> — the self-tuple so the user can GET
//     themselves (model `iam_user.v_get = … or subject or super_admin`; D-4 class —
//     emitted explicitly at user creation, NOT reconstructible by the reconciler).
//     ЧИТАЮЩИЙ ГЛАГОЛ НАЗВАН ТОЧНО, и это не педантизм: здесь стояло `viewer`,
//     а гейт чтения — `v_get`, и `subject` в нём отсутствовал. Кортеж писался,
//     проверкой не читался, самочтение не работало ни у кого. Восстановлено
//     в модели (#715-follow-up); комментарий обязан называть то отношение, от
//     которого зависит исход, иначе следующий читатель снова сверит не с тем.
//   - account:<acc>#account @ iam_access_binding:<ownerBindingID> — the owner-
//     binding OBJECT hierarchy parent-pointer (parity with account/create.go
//     ownerBindingHierarchyTuples; lineage edge, access is per-object via reconcile).
//
// Tuple-формат (User/Relation/Object) совпадает с путём приглашения
// и CreateAccount/CreateProject/CreateAccessBinding — единый owner-tuple контракт.
func bootstrapTuples(
	userID domain.UserID, accID domain.AccountID, prjID domain.ProjectID,
	ownerBindingID domain.AccessBindingID, projectAB domain.AccessBinding,
) []service.RelationTuple {
	return []service.RelationTuple{
		// Grant-tuples. owner@account is the D-4 owner standing (зеркалит CreateAccount
		// ownerTuples); admin@account is DROPPED (owner-binding reconcile materializes
		// the tier). project admin@project kept as the explicit project-admin self-grant.
		{User: fmt.Sprintf("user:%s", userID), Relation: "owner", Object: fmt.Sprintf("account:%s", accID)},
		{User: fmt.Sprintf("user:%s", userID), Relation: "admin", Object: fmt.Sprintf("project:%s", prjID)},
		// Self-tuple (flat-model get-self, D-4): iam_user.v_get включает `subject`.
		{User: fmt.Sprintf("user:%s", userID), Relation: "subject", Object: fmt.Sprintf("iam_user:%s", userID)},
		// Hierarchy parent-pointer tuples (та же форма, что на пути приглашения).
		{User: fmt.Sprintf("account:%s", accID), Relation: "account", Object: fmt.Sprintf("iam_user:%s", userID)},
		{User: fmt.Sprintf("account:%s", accID), Relation: "account", Object: fmt.Sprintf("project:%s", prjID)},
		// Owner-binding OBJECT hierarchy parent-pointer (parity with account/create.go).
		{User: fmt.Sprintf("account:%s", accID), Relation: "account", Object: fmt.Sprintf("iam_access_binding:%s", ownerBindingID)},
		// SEC-L cluster parent-pointer tuples (зеркалит account.Create / project.Create).
		{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: fmt.Sprintf("account:%s", accID)},
		{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: fmt.Sprintf("project:%s", prjID)},
		// Project-scoped AB hierarchy (iam_access_binding имеет лишь project-parent).
		{User: fmt.Sprintf("project:%s", prjID), Relation: "project", Object: fmt.Sprintf("iam_access_binding:%s", projectAB.ID)},
	}
}
