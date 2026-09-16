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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
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
// где путь мёртв (§Hardening-инварианты п.8).
const (
	// activationOutcomeActivated — приглашение активировано.
	activationOutcomeActivated = "activated"
	// activationOutcomeAlreadyActive — строку уже активировал конкурент.
	// Ожидаемый исход гонки первого входа, а НЕ отказ: считается отдельно
	// именно затем, чтобы не разбавлять счётчик отказов штатным событием.
	activationOutcomeAlreadyActive = "already_active"
	// activationOutcomeFailed — активация не удалась. Вход прерывается.
	activationOutcomeFailed = "failed"
	// activationOutcomeExpired — строка пережила свой срок (приёмка ID-MAIL-1,
	// MAIL-23). Вход НЕ прерывается: личность человека существует и он входит,
	// просто участником этого аккаунта не становится. Прервать вход значило бы
	// наказать человека за чужую забывчивость — и наказать отказом, из которого
	// не видно, что делать.
	activationOutcomeExpired = "expired"
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
			activated, aerr := ActivateInviteTx(ctx, w, p, in.ExternalID, in.DisplayName, actor)
			if aerr != nil {
				_ = w.Rollback(ctx)
				// Строку уже активировал конкурент (она больше не PENDING) — это
				// ожидаемый исход гонки первого входа, и он пропускается намеренно.
				if errors.Is(aerr, iamerr.ErrNotFound) {
					uc.observeActivation(activationOutcomeAlreadyActive)
					continue
				}
				// Строка пережила свой срок. Это ШТАТНЫЙ исход, а не отказ:
				// вход продолжается, участником аккаунта человек не становится.
				//
				// ТЕКСТ ОТКАЗА ХРАНИЛИЩА СЮДА НЕ ДОХОДИТ, и это сказано прямо,
				// чтобы следующий читатель не искал его на экране. Полоса —
				// провизион-хук поставщика личности: показать человеку нечего,
				// а уронить его вход значило бы наказать за чужую забывчивость.
				// Текст («попросите пригласить заново») адресован тому, кто
				// зовёт активацию НАПРЯМУЮ, и оператору — через след и счётчик.
				//
				// Считается СВОЕЙ клеткой — иначе систематически истекающие
				// приглашения выглядели бы поломкой, а мёртвая доставка письма —
				// здоровьем.
				if errors.Is(aerr, iamerr.ErrInviteExpired) {
					uc.observeActivation(activationOutcomeExpired)
					if uc.logger != nil {
						// Коррелируем по идентификатору строки: почта в лог не
						// пишется ни на успешном, ни на отказном пути.
						uc.logger.Info("invite expired, row not activated",
							"user_id", string(p.ID))
					}
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
// Тело транзакции — `BootstrapPersonalResourcesTx`: его же зовёт регистрация
// нашей полосой ИЗНУТРИ своей транзакции (Ф4 Р1). Здесь — транзакция этого
// глагола и пост-коммитная материализация.
func (uc *UpsertFromIdentityUseCase) bootstrapPersonalResources(
	ctx context.Context, candidateUserID string, in UpsertFromIdentityInput, actor string, newIdentity bool,
) (domain.User, error) {
	res, err := shared.DoWithWriteTx(ctx, uc.repo,
		func(ctx context.Context, w Writer) (BootstrapResult, error) {
			return BootstrapPersonalResourcesTx(ctx, w, BootstrapInput{
				CandidateUserID: candidateUserID,
				ExternalID:      in.ExternalID,
				Email:           in.Email,
				DisplayName:     in.DisplayName,
				Actor:           actor,
				NewIdentity:     newIdentity,
			})
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
		if rerr := uc.reconciler.ReconcileBinding(ctx, res.OwnerBindingID); rerr != nil && uc.logger != nil {
			uc.logger.Error("bootstrap: owner-binding reconcile failed (sweep will retry)",
				"account_id", string(res.AccountID), "binding_id", string(res.OwnerBindingID), "err", rerr)
		}
	}

	return res.User, nil
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
