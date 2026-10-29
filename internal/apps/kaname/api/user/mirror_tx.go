// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// mirror_tx.go — ЗЕРКАЛО ПОЛЬЗОВАТЕЛЯ ОДНОЙ ТРАНЗАКЦИЕЙ ВЫЗЫВАЮЩЕГО.
//
// Тело заведения зеркала (строка человека, личный аккаунт, проект по умолчанию,
// две самопривязки, ведомость кортежей, событие аудита, намерения материализации)
// и тело активации приглашения — функции над writer'ом ВЫЗЫВАЮЩЕГО. Зовут их
// двое (третий, глагол заведения личности по внешнему удостоверению, снят
// kaname#929 по приёмке AWI-09):
//
//   - активация приглашения в исходе подтверждения адреса
//     (`ActivateInviteOnVerificationTx`, kaname#456);
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
	"time"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
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
	return bootstrapPersonalResources(ctx, w, in, nil)
}

// bootstrapPersonalResources — тело BootstrapPersonalResourcesTx. carried — кортежи
// журнала, которые вызывающий уже назвал в ЭТОЙ транзакции (указатель личности
// активации): они ложатся тем же оператором журнала, что и кортежи личных
// ресурсов, — один оператор на транзакцию (kaname#617). Заведение, которое
// ничего не заводит (личные ресурсы уже есть), кладёт их одни.
func bootstrapPersonalResources(ctx context.Context, w Writer, in BootstrapInput, carried []service.RelationTuple) (BootstrapResult, error) {
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
		if len(carried) > 0 {
			if ferr := w.EmitFGARelationWrite(ctx, carried); ferr != nil {
				return BootstrapResult{}, ferr
			}
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

	// 2. INSERT account. Имя — `personal-cloud-<хвост>` из зарезервированного
	// пространства (`domain.PersonalAccountNamePrefix`): его ВЫБИРАЕТ система, не
	// арендатор, и «personal-cloud-…» человек прочтёт, а идентификатор — нет. Форме
	// дерева оно отвечает как есть (`pkg/validate/nameform`): строчные, дефис в
	// середине.
	//
	// Столкновение по accounts_name_unique разрешается ПЕРЕБОРОМ СВОБОДНОГО имени
	// ТОЙ ЖЕ транзакцией через само ограничение базы (ban #10 — не проверка-перед-
	// вставкой): адаптер отвечает на занятое имя нолём строк (ON CONFLICT), не
	// обрывая транзакцию, поэтому следующая попытка берёт свежий хвост.
	// Идентификатор аккаунта между попытками НЕ меняется — на него уже ссылается
	// строка человека отложенным ключом; меняется только имя.
	//
	// Исчерпание попыток — НЕВЫПОЛНЕНИЕ (`ErrPersonalAccountNameUnavailable`), а не
	// занятость: имя выбирает система, зарегистрированный адрес свободен, и отказ
	// занятости солгал бы о нём (Ф4 Р9, Р3). Занятое имя личного аккаунта
	// регистрацию свободного адреса НЕ заканчивает.
	allocated := false
	for attempt := 0; attempt < personalAccountNameAttempts; attempt++ {
		_, insErr := w.AccountsW().Insert(ctx, domain.Account{
			ID:          accID,
			Name:        personalAccountName(accID, attempt),
			OwnerUserID: userID,
			Labels:      domain.Labels{},
		})
		if insErr == nil {
			allocated = true
			break
		}
		if !errors.Is(insErr, iamerr.ErrAlreadyExists) {
			return BootstrapResult{}, insErr
		}
	}
	if !allocated {
		// Текст клиент-безопасен: оба вызывающих перехватывают признак до
		// провода, но канонический переводчик отдал бы его как есть, поэтому
		// детали перебора (число попыток) в него не выносятся.
		return BootstrapResult{}, iamerr.Wrapf(iamerr.ErrPersonalAccountNameUnavailable,
			"personal account name could not be allocated")
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
	// Ведомость выпущенных кортежей проектной самовыдачи — тем же источником,
	// что их эмиссия ниже (projectBindingTuples), и в той же транзакции. Без неё
	// снятие выдачи (штатное и дренажом области при удалении проекта) снимало
	// строку, а оба кортежа оставались фактами модели прав на снятый проект
	// (kaname#665): снятие симметрично ВЕДОМОСТИ, а ведомость была пуста.
	if lerr := w.AccessBindingsW().InsertEmittedTuples(ctx, createdProjectAB.ID,
		ledgerTuples(projectBindingTuples(userID, prjID, createdProjectAB.ID))); lerr != nil {
		return BootstrapResult{}, lerr
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
		append(bootstrapTuples(userID, accID, prjID, ownerBindingID, projectAB), carried...)); ferr != nil {
		return BootstrapResult{}, ferr
	}

	return BootstrapResult{User: user, AccountID: accID, ProjectID: prjID, OwnerBindingID: ownerBindingID}, nil
}

// ledgerTuples — те же кортежи в форме строки ведомости выдачи.
func ledgerTuples(in []service.RelationTuple) []abrepo.RelationTuple {
	out := make([]abrepo.RelationTuple, 0, len(in))
	for _, tp := range in {
		out = append(out, abrepo.RelationTuple{User: tp.User, Relation: tp.Relation, Object: tp.Object})
	}
	return out
}

// personalAccountNameAttempts — сколько имён личного аккаунта перебрать против
// accounts_name_unique, прежде чем признать пространство имён недоступным.
// Столкновение системно-выбранного имени крайне маловероятно (хвост нулевой
// попытки берётся у идентификатора, последующих — свежий крокфордов), поэтому
// одной повторной попытки со свежим хвостом достаточно; исчерпание есть системная
// аномалия (`ErrPersonalAccountNameUnavailable` → 503, вызывающий повторит с новым
// идентификатором). Перебор держим коротким намеренно: длинный маскировал бы такую
// аномалию видимостью нормальной работы.
//
// Важно для наблюдаемости: столкнувшаяся попытка НЕ вставляет строки (ON CONFLICT
// DO NOTHING), поэтому перебор не расходует потолок темпа заведения (Р5) — его
// заряжает лишь СОСТОЯВШАЯСЯ вставка.
const personalAccountNameAttempts = 2

// personalAccountName — имя личного аккаунта на попытке attempt. Нулевая попытка
// берёт хвост у идентификатора аккаунта (детерминизм в норме); последующие берут
// свежий крокфордов хвост, чтобы уйти со столкнувшегося имени. Идентификатор
// аккаунта при этом НЕ меняется — меняется только имя. Форме имени дерева
// (`pkg/validate/nameform`) отвечает как есть: строчные, дефис в середине.
func personalAccountName(accID domain.AccountID, attempt int) domain.AccountName {
	tail := string(accID[len(accID)-6:])
	if attempt > 0 {
		fresh := ids.NewID(domain.PrefixAccount)
		tail = string(fresh[len(fresh)-6:])
	}
	return domain.AccountName(domain.PersonalAccountNamePrefix + strings.ToLower(tail))
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
	activated, pointer, err := activateInvite(ctx, w, pending, externalID, displayName, actor)
	if err != nil {
		return domain.User{}, err
	}
	if ferr := w.EmitFGARelationWrite(ctx, pointer); ferr != nil {
		return domain.User{}, ferr
	}
	return activated, nil
}

// activateInvite — тело ActivateInviteTx БЕЗ записи журнала: указатель личности
// возвращается вызывающему, и тот кладёт его одним оператором журнала со всеми
// кортежами своей транзакции (kaname#617).
func activateInvite(ctx context.Context, w Writer, pending domain.User,
	externalID domain.ExternalSubject, displayName domain.DisplayName, actor string,
) (domain.User, []service.RelationTuple, error) {
	activated, err := w.UsersW().ActivateInvite(ctx, pending.ID, externalID, displayName)
	if err != nil {
		return domain.User{}, nil, err
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
		return domain.User{}, nil, eerr
	}
	// RC-2: co-commit the member hierarchy-tuple intent in the SAME writer-tx as
	// the ActivateInvite UPDATE + the iam.user.updated audit-event (запрет #10 /
	// SEC-D). Без него активированный member не имеет FGA-ребра в account
	// инвайтера → его AccountService.List не видит этот account. Tuple-форма
	// byte-идентична bootstrapTuples hierarchy-блоку (account:<A>#account@iam_user:<id>).
	// Idempotent: re-activation re-emits the same intent → at-least-once +
	// idempotent drain → exactly one FGA edge.
	pointer := []service.RelationTuple{{
		User:     fmt.Sprintf("account:%s", activated.AccountID),
		Relation: "account",
		Object:   fmt.Sprintf("iam_user:%s", activated.ID),
	}}
	// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event in
	// the SAME activation writer-tx (ban #10) so the now-ACTIVE invitee user
	// forward-materializes under the inviter-account's owner `*.*` binding —
	// the flat rights model dropped the iam_user `from account` ACCESS cascade,
	// so the parent-pointer above no longer grants the owner Get on the user.
	if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.user", string(activated.ID)); rerr != nil {
		return domain.User{}, nil, rerr
	}
	return activated, pointer, nil
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
	// Invited — адрес нёс живое приглашение: регистрация записала способ входа и
	// сессию на строку приглашения, а приглашение НЕ активировала — его
	// активирует подтверждение адреса (kaname#456, Р11 п. 1).
	Invited bool
}

// RegisterMirrorTx — зеркало пользователя для регистрации нашей полосой, ОДНИМ
// writer'ом вызывающего (Ф4 Р1, Р6; kaname#456, Р11 п. 1).
//
// Приглашение по адресу регистрация НЕ активирует: личность и личные ресурсы
// приглашённому пишет активация в исходе подтверждения адреса. Годное
// приглашение — строка остаётся PENDING и становится строкой, на которую
// вызывающий пишет способ входа и сессию; личности на ней нет (строка PENDING
// её не несёт по ограничению схемы). Без приглашения — новая строка человека.
// Занятость адреса судит ключ базы (`users_identity_email_uniq`), не
// проверка-перед-вставкой: два одновременных заведения дают ровно одно
// `ACTIVE`, второе — 23505 (Ф1-62).
//
// Отказы возвращаются сентинелами адаптера — вызывающий облекает их в единый
// отказ регистрации:
//   - ErrAlreadyExists — адрес принадлежит действующей либо заблокированной
//     личности (ключ почты); либо строка PENDING по адресу — не приглашение
//     (её никто не приглашал: посеянная строка установки), и присвоить её
//     регистрацией нельзя ни при каком сроке; либо способ входа на строку
//     приглашения уже записан первой регистрацией — это отвергает вставка
//     способа вызывающего (простая вставка без замещения);
//   - ErrInviteExpired — приглашение пережило срок (либо снято: снятие выражено
//     сроком строки). Строка остаётся PENDING и держит ключ почты.
func RegisterMirrorTx(ctx context.Context, w Writer, in MirrorInput) (MirrorResult, error) {
	pendings, err := w.Users().FindPendingByEmail(ctx, in.Email)
	if err != nil {
		return MirrorResult{}, err
	}
	if len(pendings) > 0 {
		// Ключ почты полный (`lower(email)`), поэтому строка приглашения по
		// адресу ровно одна.
		p := pendings[0]
		if p.InvitedBy == "" {
			// Строку PENDING без пригласившего завела установка, а не
			// распорядитель: она не приглашение, и регистрация её не присваивает.
			return MirrorResult{}, iamerr.Wrapf(iamerr.ErrAlreadyExists, "address is held by a row that is not an invitation")
		}
		// Срок судится по часам службы тем же сравнением, что у строки
		// (`User.InviteExpired`); окончательное суждение выносит оператор
		// активации в исходе подтверждения — часами базы, одним оператором.
		if p.InviteExpired(time.Now().UTC()) {
			return MirrorResult{}, iamerr.Wrapf(iamerr.ErrInviteExpired, "invite expired")
		}
		return MirrorResult{User: p, AccountID: p.AccountID, Invited: true}, nil
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

// ActivateInviteOnVerificationTx — активация приглашения В ИСХОДЕ
// ПОДТВЕРЖДЕНИЯ адреса, ОДНИМ writer'ом вызывающего (kaname#456, Р10 п. 5,
// Р11 п. 2): тот же оператор активации, что сегодня, — состояние PENDING, живой
// срок и отметка подтверждения, поставленная той же транзакцией раньше, стоят
// в его условии, — затем личность, отчеканенная нашей полосой в момент
// подтверждения (форма та же, что у регистрации, F4d-52), и личные ресурсы.
//
// Отказы — сентинелами адаптера, как у [ActivateInviteTx]: ErrInviteExpired —
// приглашение истекло либо снято; ErrNotFound — строка уже не PENDING. Функция
// НЕ коммитит и НЕ откатывает: транзакция принадлежит вызывающему.
func ActivateInviteOnVerificationTx(ctx context.Context, w Writer, pending domain.User, actor string) (BootstrapResult, error) {
	externalID := domain.NewOwnLaneSubject()
	// Указатель личности активации и кортежи личных ресурсов — ОДНИМ оператором
	// журнала транзакции (kaname#617): активация его не кладёт, а передаёт
	// заведению личных ресурсов.
	activated, pointer, err := activateInvite(ctx, w, pending, externalID, "", actor)
	if err != nil {
		return BootstrapResult{}, err
	}
	return bootstrapPersonalResources(ctx, w, BootstrapInput{
		CandidateUserID: string(activated.ID), ExternalID: externalID, Email: activated.Email,
		DisplayName: activated.DisplayName, Actor: actor, NewIdentity: false,
	}, pointer)
}

// ActivateInviteForLane — активация приглашения на полосе формы одним writer'ом
// вызывающего, в форме порта полосы (`humansession.InviteActivation`): исход
// подтверждения адреса (kaname#456, Р11 п. 2) и переход записи к владельцу
// ящика (kaname#458, Р3 п. 4) зовут ОДНУ функцию. Актор — сам человек строки.
// Срок и снятие приглашения, как и строка, уже не PENDING, — один исход «не
// активируется»: humansession.ErrInviteNotValid (Р11 п. 3, Р6 kaname#458).
// Прочие отказы — как есть. Функция НЕ коммитит и НЕ откатывает.
func ActivateInviteForLane(ctx context.Context, w Writer, pending domain.User) (humansession.InviteActivation, error) {
	res, err := ActivateInviteOnVerificationTx(ctx, w, pending, string(pending.ID))
	if err != nil {
		if errors.Is(err, iamerr.ErrInviteExpired) || errors.Is(err, iamerr.ErrNotFound) {
			return humansession.InviteActivation{}, humansession.ErrInviteNotValid
		}
		return humansession.InviteActivation{}, err
	}
	return humansession.InviteActivation{User: res.User, OwnerBindingID: res.OwnerBindingID}, nil
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
// Две строки проектной самовыдачи (admin@project и указатель её объекта) берутся
// из projectBindingTuples — того же источника, что ведомость этой выдачи.
//
// Account-scoped AccessBinding (accountAB) НЕ получает iam_access_binding
// hierarchy-tuple: FGA-тип `iam_access_binding` имеет только `project`-parent —
// account-scoped binding'и per-resource Get авторизуются через grant-tuples выше.
// ЗДЕСЬ СТОЯЛО «без `iam_user`-hierarchy-tuple per-resource UserService.Get/
// Update/Delete никогда не авторизуется» — И ЭТО НЕВЕРНО СО ДНЯ СНЯТИЯ ВНЕШНЕГО
// ДВИЖКА. Предка личности называет не этот кортеж, а цепь областей
// (`kaname.resource_scope_edge`), и берёт она его из таблицы членств (kacho#944;
// прежде — из колонки строки). Читателя у самого кортежа на пути решения нет:
// атом плана ищет `admin`/`owner` НА ОБЪЕКТЕ-ПРЕДКЕ, а не отношение `account` на
// личности. Кортеж пишется тремя местами и не читается ни одним — предмет
// заведён отдельно (kacho#946), здесь он назван, а не снят: уборка и отрыв — разные
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
//     в модели (kacho#715-follow-up); комментарий обязан называть то отношение, от
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
	out := []service.RelationTuple{
		// Grant-tuples. owner@account is the D-4 owner standing (зеркалит CreateAccount
		// ownerTuples); admin@account is DROPPED (owner-binding reconcile materializes
		// the tier). project admin@project kept as the explicit project-admin self-grant.
		{User: fmt.Sprintf("user:%s", userID), Relation: "owner", Object: fmt.Sprintf("account:%s", accID)},
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
	}
	// Самовыдача на проект и указатель объекта её выдачи на предка — ТЕ ЖЕ
	// кортежи, что пишутся в ведомость этой выдачи (projectBindingTuples):
	// эмитируемое и записанное выпущенным — одно значение, а не два списка.
	return append(out, projectBindingTuples(userID, prjID, projectAB.ID)...)
}

// projectBindingTuples — кортежи ЖИЗНЕННОГО ЦИКЛА проектной самовыдачи
// заведения: явное право администратора проекта и указатель объекта выдачи на
// предка (`iam_access_binding` имеет лишь project-parent).
//
//	user:<usr>#admin            @project:<prj>
//	project:<prj>#project       @iam_access_binding:<ab>
//
// Источник ОДИН для эмиссии (bootstrapTuples) и для ведомости выпущенных
// кортежей выдачи (`access_binding_emitted_tuples`, BootstrapPersonalResourcesTx).
// Ведомость обязательна: снятие выдачи — и штатное (`AccessBinding.Delete`), и
// дренажом области при удалении проекта (`shared.RevokeBindingsInScope`) — снимает
// РОВНО записанное в ней. Выдача без ведомости уходила строкой, а оба кортежа
// оставались фактами модели прав на объект, которого больше нет (kaname#665).
func projectBindingTuples(userID domain.UserID, prjID domain.ProjectID, abID domain.AccessBindingID) []service.RelationTuple {
	return []service.RelationTuple{
		{User: fmt.Sprintf("user:%s", userID), Relation: "admin", Object: fmt.Sprintf("project:%s", prjID)},
		{User: fmt.Sprintf("project:%s", prjID), Relation: "project", Object: fmt.Sprintf("iam_access_binding:%s", abID)},
	}
}
