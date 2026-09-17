// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// mirror_tx.go — ЗЕРКАЛО ПОЛЬЗОВАТЕЛЯ ОДНОЙ ТРАНЗАКЦИЕЙ ВЫЗЫВАЮЩЕГО.
//
// Тело заведения зеркала (строка человека, личный аккаунт, проект по умолчанию,
// две самопривязки, ведомость кортежей, событие аудита, намерения материализации)
// и тело активации приглашения вынесены из `UpsertFromIdentity` в функции над
// writer'ом ВЫЗЫВАЮЩЕГО. Зовут их двое:
//
//   - `UpsertFromIdentity` (провизион-хук поставщика) — своей транзакцией, как и
//     прежде; поведение и состав эмитируемого сохранены дословно;
//   - регистрация нашей полосой (Ф4 Р1, `internal/apps/kaname/api/registration`)
//     — ИЗНУТРИ транзакции, которая тем же writer'ом пишет строку способа входа
//     и строку сессии. Отказ любого из трёх следствий откатывает все три
//     (Ф4-02…Ф4-04); отдельный вызов по сети этого не даёт.
//
// Функции НЕ коммитят и НЕ откатывают: транзакция принадлежит вызывающему.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// BootstrapInput — что приносит вызывающий заведения зеркала.
type BootstrapInput struct {
	// CandidateUserID — идентификатор строки человека: новый (NewIdentity) либо
	// существующей активированной строки.
	CandidateUserID string
	ExternalID      domain.ExternalSubject
	Email           domain.Email
	DisplayName     domain.DisplayName
	// Actor — кто заводит, для аудита: субъект либо "system".
	Actor string
	// NewIdentity — строку человека вставлять (true) либо она уже есть —
	// приглашённый, активированный в этой же либо прежней транзакции (false).
	NewIdentity bool
}

// BootstrapResult — что заведено; идентификаторы нужны пост-коммитной
// материализации и наблюдению.
type BootstrapResult struct {
	User           domain.User
	AccountID      domain.AccountID
	ProjectID      domain.ProjectID
	OwnerBindingID domain.AccessBindingID
}

// BootstrapPersonalResourcesTx — заведение зеркала ОДНИМ writer'ом вызывающего
// (RC-5). Идемпотентно на уровне транзакции: под транзакционной блокировкой
// по идентификатору человека повторно читается число собственных аккаунтов, и
// при ненулевом — возвращается существующая строка без второго заведения.
//
//   - NewIdentity=true  — genuinely-new identity: INSERT user-row первым (FK на
//     account отложен, DEFERRABLE chicken-and-egg), затем personal Account/Project.
//     Emits iam.user.created audit.
//   - NewIdentity=false — invited+activated user: user-row УЖЕ существует
//     (ActivateInvite сохранил id) — повторный InsertActive вызвал бы 23505 на
//     UNIQUE(external_id). Поэтому загружаем существующий row через Get, НЕ
//     вставляем повторно; создаем только personal Account/Project/AB/tuples для
//     существующего user-id. iam.user.created НЕ эмитится (user-identity не нова —
//     активация уже эмитировала iam.user.updated).
//
// Кластерное право администратора этот путь не эмитит вовсе: его ставит отдельный
// реконсайлер старта (`seed.RunBootstrapAdmin`) по адресу почты из настроек.
func BootstrapPersonalResourcesTx(ctx context.Context, w Writer, in BootstrapInput) (BootstrapResult, error) {
	userID := domain.UserID(in.CandidateUserID)
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
		GrantedByUserID:    domain.UserID(in.Actor),
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
	// not bad input — fail-closed (the caller's tx rolls back).
	if verr := ownerAB.Validate(); verr != nil {
		return BootstrapResult{}, shared.MapValidationErr(verr)
	}

	// 0. ban #10 — close the owns-zero-accounts TOCTOU. A pre-check in a separate
	// reader-tx lets two concurrent bootstraps for the SAME resolved user-id both
	// read count==0 and both INSERT a distinct personal account (random
	// 'personal-cloud-<rand>' name → accounts_name_unique never fires; owner_user_id
	// has no cardinality bound). "One personal account per user" cannot be a partial
	// UNIQUE (a user may legitimately own many accounts), so same-user bootstraps
	// are serialized with a tx-scoped advisory lock and the owned-account count is
	// RE-CHECKED INSIDE this writer-tx: the loser blocks until the winner commits,
	// then sees count>0 and returns the already-bootstrapped user without inserting
	// a duplicate. (NewIdentity=true callers each carry a distinct fresh id →
	// different lock key; they are serialized instead by the UNIQUE keys of
	// InsertActive below — unchanged.)
	if lerr := w.AdvisoryXactLock(ctx, "iam:bootstrap:"+in.CandidateUserID); lerr != nil {
		return BootstrapResult{}, lerr
	}
	if owned, cerr := w.Accounts().CountAccountsByOwner(ctx, userID); cerr != nil {
		return BootstrapResult{}, cerr
	} else if owned > 0 {
		// A concurrent bootstrap won the lock and already created this user's
		// personal account — return the existing user-row.
		existing, gerr := w.Users().Get(ctx, userID)
		if gerr != nil {
			return BootstrapResult{}, gerr
		}
		return BootstrapResult{User: existing}, nil
	}

	// 1. Resolve the user-row.
	var (
		user domain.User
		err  error
	)
	if in.NewIdentity {
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
			// UNIQUE(external_id WHERE !='') enforce one user-row per identity.
			// Concurrent bootstraps for the same identity lose the race here
			// with 23505 (mapped to ErrAlreadyExists). The DB constraint is the
			// authoritative dup guard; a single ON CONFLICT statement would be an
			// equivalent alternative, not a missing piece.
			return BootstrapResult{}, err
		}
	} else {
		// invited+activated: переиспользуем существующий user-row (его id =
		// CandidateUserID; account_id = account инвайтера — НЕ меняется,
		// остается primary context). НЕ вызываем InsertActive повторно.
		user, err = w.Users().Get(ctx, userID)
		if err != nil {
			return BootstrapResult{}, err
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
		return BootstrapResult{}, err
	}

	// 3. INSERT default project.
	if _, err := w.ProjectsW().Insert(ctx, domain.Project{
		ID:        prjID,
		AccountID: accID,
		Name:      domain.ProjectName("default"),
		Labels:    domain.Labels{},
	}); err != nil {
		return BootstrapResult{}, err
	}

	// 4. INSERT the owner (account-scoped) + project-admin self-grant rows.
	//   - owner-binding: + multi-subject set + OWNER-BINDING-lifecycle ledger
	//     (so a symmetric revoke removes exactly what was emitted) + grant audit,
	//     mirroring account/create.go doCreate.
	createdOwner, oerr := w.AccessBindingsW().Insert(ctx, ownerAB)
	if oerr != nil {
		return BootstrapResult{}, oerr
	}
	if serr := w.AccessBindingsW().InsertSubjects(ctx, createdOwner.ID, ownerAB.Subjects); serr != nil {
		return BootstrapResult{}, serr
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
		return BootstrapResult{}, lerr
	}
	if aerr := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
		EventType:       abrepo.AuditEventTypeGranted,
		Actor:           in.Actor,
		SubjectType:     string(domain.SubjectTypeUser),
		SubjectID:       string(userID),
		ResourceType:    "account",
		ResourceID:      string(accID),
		RoleID:          domain.OwnerRoleID,
		BindingID:       string(createdOwner.ID),
		TenantAccountID: string(accID),
	}); aerr != nil {
		return BootstrapResult{}, aerr
	}
	ownerBindingID := createdOwner.ID
	createdProjectAB, err := w.AccessBindingsW().Insert(ctx, projectAB)
	if err != nil {
		return BootstrapResult{}, err
	}
	// Состав субъектов записывается вместе с выдачей — иначе она
	// невидима форме вердикта, и человек не имеет прав на проекте,
	// который сам же и завёл. Замер на живом стенде: из 111 выдач без
	// состава 110 пришли отсюда.
	if serr := w.AccessBindingsW().InsertSubjects(ctx, createdProjectAB.ID,
		[]domain.Subject{{Type: projectAB.SubjectType, ID: projectAB.SubjectID}}); serr != nil {
		return BootstrapResult{}, serr
	}

	// 5. Durable audit_outbox iam.user.created in the SAME bootstrap tx
	// (запрет #10) — atomic with the user INSERT. ТОЛЬКО для genuinely-new
	// identity: создается новая user-identity → iam.user.created scoped к
	// ее personal Account. Для invited+activated user (NewIdentity=false)
	// user-identity НЕ нова — активация уже эмитировала iam.user.updated; здесь
	// мы лишь добавляем personal-resource'ы существующему user-id, поэтому
	// второй iam.user.created был бы ложным дублем identity-creation.
	if in.NewIdentity {
		if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
			EventType:       auditEventUserCreated,
			TenantAccountID: string(accID),
			// Ни почты, ни отображаемого имени: приёмник журнала кладёт
			// ВСЕ поля нагрузки как есть — шага сокрытия нет ни одного,
			// — поэтому личное поле уезжает в поток службы, а срок
			// хранения потока становится сроком хранения личных данных
			// (`kacho#2483`). Субъект назван `resource_id`: он
			// неизменяем и остаётся правдой через год, тогда как оба
			// снятых поля меняются свободно.
			Payload: map[string]any{
				"actor":         in.Actor,
				"resource_type": "user",
				"resource_id":   string(user.ID),
				"account_id":    string(accID),
			},
		}); aerr != nil {
			return BootstrapResult{}, aerr
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
		return BootstrapResult{}, ferr
	}

	return BootstrapResult{User: user, AccountID: accID, ProjectID: prjID, OwnerBindingID: ownerBindingID}, nil
}

// ActivateInviteTx — активация ОДНОЙ строки приглашения writer'ом вызывающего:
// сама активация, событие аудита `iam.user.updated`, намерение кортежа членства
// и событие реконсайла — одним исходом (RC-2, ban #10).
//
// Отказы адаптера возвращаются как есть — вызывающий различает их по сентинелу:
// `ErrNotFound` — строку уже активировал конкурент (она больше не PENDING);
// `ErrInviteExpired` — строка пережила свой срок (приёмка ID-MAIL-1, MAIL-23);
// прочее — отказ.
func ActivateInviteTx(ctx context.Context, w Writer, pending domain.User,
	externalID domain.ExternalSubject, displayName domain.DisplayName, actor string,
) (domain.User, error) {
	activated, err := w.UsersW().ActivateInvite(ctx, pending.ID, externalID, displayName)
	if err != nil {
		return domain.User{}, err
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
		return domain.User{}, eerr
	}
	// RC-2: co-commit the member hierarchy-tuple intent in the SAME writer-tx as
	// the ActivateInvite UPDATE + the iam.user.updated audit-event (запрет #10 /
	// SEC-D). Без него активированный member не имеет FGA-ребра в account
	// инвайтера → его AccountService.List не видит этот account. Tuple-форма
	// byte-идентична bootstrapTuples hierarchy-блоку (account:<A>#account@iam_user:<id>).
	// Idempotent: re-activation re-emits the same intent → at-least-once +
	// idempotent drain → exactly one FGA edge.
	if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{{
		User:     fmt.Sprintf("account:%s", activated.AccountID),
		Relation: "account",
		Object:   fmt.Sprintf("iam_user:%s", activated.ID),
	}}); ferr != nil {
		return domain.User{}, ferr
	}
	// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event in
	// the SAME activation writer-tx (ban #10) so the now-ACTIVE invitee user
	// forward-materializes under the inviter-account's owner `*.*` binding —
	// the flat rights model dropped the iam_user `from account` ACCESS cascade,
	// so the parent-pointer above no longer grants the owner Get on the user.
	if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.user", string(activated.ID)); rerr != nil {
		return domain.User{}, rerr
	}
	return activated, nil
}

// MirrorInput — что приносит регистрация нашей полосой (Ф4).
type MirrorInput struct {
	Email domain.Email
	// ExternalID — идентичность, отчеканенная нашей полосой (F4d-52).
	ExternalID domain.ExternalSubject
	// CandidateUserID — идентификатор для НОВОЙ строки; у приглашённого
	// сохраняется идентификатор его строки.
	CandidateUserID domain.UserID
	Actor           string
}

// MirrorResult — исход заведения зеркала регистрацией.
type MirrorResult struct {
	User           domain.User
	OwnerBindingID domain.AccessBindingID
	AccountID      domain.AccountID
	// Activated — адрес нёс приглашение, и оно активировано (Ф4-23).
	Activated bool
}

// RegisterMirrorTx — зеркало пользователя для регистрации нашей полосой, ОДНИМ
// writer'ом вызывающего (Ф4 Р1, Р6).
//
// Порядок: приглашение по адресу → активация ТОЙ ЖЕ полосой (Р6: второго
// личного аккаунта не заводится, третьей полосы нет) → заведение личных
// ресурсов. Без приглашения — новая строка человека. Занятость адреса судит
// ключ базы (`users_identity_email_uniq`), не проверка-перед-вставкой: два
// одновременных заведения дают ровно одно `ACTIVE`, второе — 23505 (Ф1-62).
//
// Отказы возвращаются сентинелами адаптера — вызывающий облекает их в единый
// отказ регистрации:
//   - ErrAlreadyExists — адрес принадлежит действующей либо заблокированной
//     личности (ключ почты), либо приглашение уже активировал конкурент
//     (строка больше не PENDING — тот же смысл: адрес занят);
//   - ErrInviteExpired — приглашение пережило срок. Строка остаётся PENDING и
//     держит ключ почты, поэтому регистрация этим адресом невозможна до
//     уборки строки — паритет с полосой поставщика (ID-MAIL-1, MAIL-23), где
//     истёкшая строка не активируется; для вызывающего это тот же отказ.
func RegisterMirrorTx(ctx context.Context, w Writer, in MirrorInput) (MirrorResult, error) {
	pendings, err := w.Users().FindPendingByEmail(ctx, in.Email)
	if err != nil {
		return MirrorResult{}, err
	}
	if len(pendings) > 0 {
		// Ключ почты полный (`lower(email)`), поэтому строка приглашения по
		// адресу ровно одна.
		activated, aerr := ActivateInviteTx(ctx, w, pendings[0], in.ExternalID, "", in.Actor)
		if aerr != nil {
			if errors.Is(aerr, iamerr.ErrNotFound) {
				return MirrorResult{}, iamerr.Wrapf(iamerr.ErrAlreadyExists, "invite already activated")
			}
			return MirrorResult{}, aerr
		}
		res, berr := BootstrapPersonalResourcesTx(ctx, w, BootstrapInput{
			CandidateUserID: string(activated.ID), ExternalID: in.ExternalID, Email: in.Email,
			DisplayName: activated.DisplayName, Actor: in.Actor, NewIdentity: false,
		})
		if berr != nil {
			return MirrorResult{}, berr
		}
		return MirrorResult{User: res.User, OwnerBindingID: res.OwnerBindingID, AccountID: res.AccountID, Activated: true}, nil
	}
	res, err := BootstrapPersonalResourcesTx(ctx, w, BootstrapInput{
		CandidateUserID: string(in.CandidateUserID), ExternalID: in.ExternalID, Email: in.Email,
		Actor: in.Actor, NewIdentity: true,
	})
	if err != nil {
		return MirrorResult{}, err
	}
	return MirrorResult{User: res.User, OwnerBindingID: res.OwnerBindingID, AccountID: res.AccountID}, nil
}
