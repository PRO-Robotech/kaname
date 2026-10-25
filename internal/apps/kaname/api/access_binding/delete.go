// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// delete.go — DeleteAccessBindingUseCase.
// 0 rows → NotFound (repo возвращает ErrNotFound).
//
// Atomic revoke notes:
//   - The FGA tuple deletion is queued via
//     `w.AccessBindingsW().EmitRelationDelete(ctx, stored)` inside the same
//     writer-tx as the binding delete. Tx rollback ⇒ no orphan fga_outbox
//     rows AND no orphan binding state.
//   - Снимаемый набор — СОХРАНЁННЫЙ реестр выдачи (access_binding_emitted_tuples —
//     F3/#178), прочитанный `w.AccessBindings().SelectEmittedTuples(id)`: снятие
//     верно тому, что выпущено при выдаче либо последней сверке, даже если
//     разрешения роли с тех пор менялись (набор, выведенный заново, осиротил бы
//     выданное прежде). Общий кортеж, который
//     держит другая действующая выдача, снимает не use-case: свёртка строки снятия
//     спрашивает о держателях под замком строки факта (миграция 20261019180000,
//     kaname#919).
//
// ОТЗЫВ ДЕЙСТВУЕТ С КОММИТА, и догоняющего пути для этого не нужно.
//   - Строка снятия, положенная в журнал намерений ТОЙ ЖЕ writer-tx, снимает
//     прямой факт триггером журнала — в том же коммите. Прежде здесь стоял
//     синхронный пост-коммитный вызов в чужое хранилище: он закрывал окно между
//     коммитом и дренажом, пока право продолжало действовать. Хранилища нет
//     (стадия S6, эпик kacho#747) — нет ни окна, ни того, кого догонять.
//   - Строки снятия — на весь emitted-set; факт, который ещё держит другая
//     ACTIVE-привязка, свёртка оставляет.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

type DeleteAccessBindingUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// relations — ДВЕРЬ РЕШЕНИЯ, и только на READ-стороне: `requireGrantAuthority`
	// спрашивает, вправе ли вызывающий снимать эту выдачу.
	//
	// Писать через неё больше нельзя и не нужно: синхронное удаление кортежей из
	// чужого хранилища снято вместе с хранилищем (стадия S6, эпик kacho#747), а строка
	// журнала, положенная writer-tx, снимает прямой факт триггером — в том же
	// коммите. nil-safe: непровязанная дверь означает отказ отвечать, а не «доступ
	// есть».
	relations clients.RelationStore
	logger    *slog.Logger
	// delegated — делегированный путь права выдавать (kaname#986, Р2); nil —
	// выключен.
	delegated *DelegatedGrantPath
}

// WithDelegatedGrantPath — делегат удаляет выдачи своего делегирования
// (kaname#986, Р2). Провязывает корень службы.
func (u *DeleteAccessBindingUseCase) WithDelegatedGrantPath(p *DelegatedGrantPath) *DeleteAccessBindingUseCase {
	u.delegated = p
	return u
}

func NewDeleteAccessBindingUseCase(r Repo, opsRepo operations.Repo) *DeleteAccessBindingUseCase {
	return &DeleteAccessBindingUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore подключает ДВЕРЬ РЕШЕНИЯ. Она нужна на READ-стороне:
// `requireGrantAuthority` спрашивает, вправе ли вызывающий снимать эту выдачу.
// Синхронного applier'а снятия за ней больше нет — см. разбор в шапке файла.
// Logger остаётся для диагностики самой проверки прав.
func (u *DeleteAccessBindingUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *DeleteAccessBindingUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *DeleteAccessBindingUseCase) Execute(ctx context.Context, id domain.AccessBindingID) (*operations.Operation, error) {
	// Anti-anon guard.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccessBinding, "access binding"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	binding, err := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			// Non-existent AB → PermissionDenied (not NotFound) to prevent
			// existence-leakage. The authz-deny garbage-per-resource scope expects 403
			// for all subjects including authenticated non-owners.
			return nil, authzguard.PermissionDenied()
		}
		// Any OTHER Get failure (transient DB fault) is NOT existence-hiding —
		// map it to its real, retriable/terminal gRPC code (shared.MapRepoErr),
		// not the non-retriable PermissionDenied a client would never retry.
		return nil, shared.MapRepoErr(err)
	}
	// AUTHZ FIRST (#4/#6 — security-ordering). requireGrantAuthority MUST run before
	// any state-dependent response (the deletion_protection pre-check below),
	// otherwise an authenticated caller WITHOUT grant authority who targets a
	// protected binding would receive the friendly FAILED_PRECONDITION
	// "deletion_protection enabled" instead of PermissionDenied — leaking that the
	// binding (a) exists and (b) is protected, contradicting the uniform-403
	// existence-leak protection the not-found branch above enforces. Only a caller
	// who is actually allowed to delete the binding may observe its protection state.
	//
	// requireGrantAuthority is the exact mirror of Create's authority rule. A
	// self-only IsSelf(subjectID) form would reject legitimate admin-revokes (an
	// account/project owner could grant a role to user X but could not revoke it).
	// With grant-authority: admin can grant AND revoke; subject self-revoke trivially
	// passes the owner path when the binding is on their own account, or the FGA admin
	// path when the binding is on a resource they admin.
	//
	// Право отозвать и удалить (kaname#986, Р1а, Р2): прежний вопрос двери
	// слушателя (`v_delete` на объекте выдачи) переехал сюда дословно, вместе с
	// правом выдавать на области; делегат проходит только по выдаче своего
	// действующего делегирования (`removalAuthority`).
	if err := removalAuthority(ctx, u.repo, u.relations, u.delegated, binding); err != nil {
		return nil, err
	}
	// RBAC explicit-model 2026 P6 (D-10 / C-02): sync deletion_protection
	// pre-check for a friendly FAILED_PRECONDITION on the request path (before any
	// Operation is created) — reached ONLY by an authorized deleter (authz ran
	// above). The async worker additionally runs an atomic CAS backstop
	// (DeleteGuarded) against the TOCTOU window (C-04).
	if binding.DeletionProtection {
		return nil, status.Errorf(codes.FailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before Delete", id)
	}
	// Capture the authenticated caller as the revoke actor NOW (sync path —
	// the principal is in ctx here, not necessarily in the async worker ctx).
	// Anti-spoofing: sourced from PrincipalFromContext, never a request field.
	actor := authzguard.PrincipalUserID(ctx)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete access binding %s", id),
		// account_id NARROW-SCOPE (D-9): only account-scoped bindings (the loaded
		// binding's ResourceType=="account") carry account_id; project/cluster
		// bindings leave it empty (SQL NULL). auditTenantAccountID is the single
		// decision point shared with the audit_outbox tenant scope.
		&iamv1.DeleteAccessBindingMetadata{AccessBindingId: string(id), AccountId: auditTenantAccountID(binding)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor)
	})
	return &op, nil
}

// deleteAttempts — сколько раз тело снятия исполняет СВОЮ транзакцию, если база
// откатила её как сторону взаимной блокировки либо конфликта сериализации.
//
// ПОЧЕМУ ПОВТОР ЗДЕСЬ, А НЕ ОТКАЗ ВЫЗЫВАЮЩЕМУ. Транзакцию снятия под параллельной
// нагрузкой делят строки с фоновой материализацией того же субъекта (строка
// выдачи, на которую дочерние вставки берут `FOR KEY SHARE`, и строки прямого
// факта). Цикл ожиданий база разрывает, откатывая одну сторону ЦЕЛИКОМ, и
// сторона арендатора не обязана быть той, кто за фоновую работу платит:
// наблюдалось (kaname#679) — операция снятия `done:true` с ABORTED, выдача жива,
// каждое следующее создание той же тройки получает ALREADY_EXISTS.
//
// ПОЧЕМУ ПОВТОР БЕЗОПАСЕН — СВОЙСТВО ЭТОГО ТЕЛА, А НЕ ИСПОЛНИТЕЛЯ. Тело — ровно
// одна транзакция записи, и после её коммита оно не делает ничего (см. хвост
// [DeleteAccessBindingUseCase.deleteOnce]); на отказе 40P01/40001 база откатила
// её целиком, поэтому «частично применилось» исключено, и повтор исполняет то же
// самое с чистого листа: заново берёт замок выдачи, заново читает её и её
// ведомость. Выдача, которую за это время снял другой, даёт NotFound — честный
// исход, а не второй отзыв. Признак повтора — `iamerr.ErrAborted`, и только он:
// его ставит переводчик отказов базы ровно на этот класс (pgmaperr), а не на
// «что-то пошло не так».
//
// Число — не запас «на всякий случай»: цикл разрывается снятием ОДНОЙ стороны,
// после чего выжившая доходит до коммита, и следующая попытка встаёт уже за ней,
// а не в цикл. На стенде за прогон набора наблюдалась одна такая жертва. Третья
// попытка покрывает второго контрагента, пришедшего в окно отступа; исчерпание
// отдаёт прежний терминальный отказ — изменение не применено, и вызывающий узнаёт
// это тем же текстом, что и раньше.
const deleteAttempts = 3

// deleteRetryBackoff — отступ перед следующей попыткой: выжившей стороне цикла
// нужно дойти до коммита, а не встретить повтор на той же строке.
const deleteRetryBackoff = 50 * time.Millisecond

func (u *DeleteAccessBindingUseCase) doDelete(ctx context.Context, id domain.AccessBindingID, actor string) (*anypb.Any, error) {
	for attempt := 1; ; attempt++ {
		err := u.deleteOnce(ctx, id, actor)
		if err == nil {
			return anypb.New(&emptypb.Empty{})
		}
		if !stderrors.Is(err, iamerr.ErrAborted) || attempt == deleteAttempts {
			return nil, shared.MapRepoErr(err)
		}
		if u.logger != nil {
			u.logger.Warn("access_binding delete: transaction lost a concurrent-change conflict, retrying",
				"binding_id", string(id), "attempt", attempt, "of", deleteAttempts)
		}
		timer := time.NewTimer(time.Duration(attempt) * deleteRetryBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, shared.MapRepoErr(ctx.Err())
		case <-timer.C:
		}
	}
}

// deleteOnce — ОДНА транзакция снятия. Отказы возвращаются НЕпереведёнными в
// статус: признак повтора (`iamerr.ErrAborted`) читает [doDelete], а перевод в
// gRPC-код делается там один раз — статус признака уже не несёт.
func (u *DeleteAccessBindingUseCase) deleteOnce(ctx context.Context, id domain.AccessBindingID, actor string) error {
	w, err := u.repo.Writer(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	// ПОРЯДОК ЗАМКОВ — тот же, что у отзыва (doRevoke) и истечения срока
	// (reconcile.ExpireBinding): advisory-замок выдачи (против полного прохода,
	// истечения, отзыва) → строка выдачи `FOR UPDATE` (GetForDeactivation, против
	// аддитивного форварда) → чтение перечня субъектов и реестра → DELETE (замок
	// строки уже взят) → строки журналов.
	//
	// Строчный замок стоит ДО чтения реестра (kaname#923). Форвард advisory не берёт
	// (reconcile/forward.go «LOCK CHOICE»), решает «выдача жива» под `FOR KEY SHARE` и
	// пишет члена, реестр и строку журнала позже, в своей транзакции; применение к
	// прямому факту у обеих сторон идёт в той же транзакции — триггером журнала
	// намерений. DELETE и так ждал форварда, но реестр был прочитан раньше, и прямой
	// факт форварда переживал удаление. Строк каталога (порядок 2р→2а→4 применителей,
	// kaname#913) транзакция не берёт, ребра ожидания с ними нет.
	//
	// Замка строки мало: исход снятия решает и ВЕРСИЯ строки журнала — свёртка в
	// прямой факт снимает факт, лишь если его версия не новее версии строки снятия.
	// Строка снятия несёт момент своей вставки, а не начало транзакции
	// (fga_outbox, deleteStamp): иначе снятие, открывшее транзакцию раньше форварда и
	// получившее строку после его коммита, писало бы строку старше факта, и факт её
	// переживал. Оба порядка начала транзакций держит
	// reconcile_deactivation_order_race_integration_test.go.
	if err := w.AdvisoryXactLock(ctx, string(id)); err != nil {
		return err
	}
	// Строка выдачи — под замком снятия; из неё же измерения событий, до удаления.
	deletedBinding, err := w.AccessBindingsW().GetForDeactivation(ctx, id)
	if err != nil {
		return err
	}
	// Перечень субъектов — ДО удаления: дочерние строки уходят каскадом той же
	// транзакцией, и после удаления перечень вырождается в первого субъекта.
	subjects, err := bindingSubjectsOf(ctx, w.AccessBindings().ListSubjects, deletedBinding)
	if err != nil {
		return err
	}
	// F3/#178 — SYMMETRIC revoke from the PERSISTED emitted-set, NOT a re-derive
	// from the binding's CURRENT role. The role's permissions may have changed
	// (Role.Update) between grant and revoke; re-deriving would emit
	// EmitRelationDelete on the NEW tuple set and orphan the originally-granted
	// ones (standing privilege). access_binding_emitted_tuples records exactly
	// what THIS binding emitted at grant / last reconcile. Реестр читается В ЭТОЙ
	// пишущей транзакции ДО удаления выдачи: каскад внешнего ключа снимает его
	// строки вместе с ней.
	stored, err := w.AccessBindings().SelectEmittedTuples(ctx, id)
	if err != nil {
		return err
	}
	// RBAC explicit-model 2026 P6 (C-04): atomic CAS backstop against TOCTOU —
	// `DELETE … WHERE deletion_protection=false`. If a concurrent Update re-armed
	// protection between the sync pre-check and here, DeleteGuarded returns
	// FAILED_PRECONDITION and the binding stays (the row-lock serializes them).
	if err := w.AccessBindingsW().DeleteGuarded(ctx, id); err != nil {
		return err
	}
	// Строки снятия — в той же транзакции: откат не оставляет ни удалённой выдачи,
	// ни строк журнала. Строки снятия — после DELETE: реестр выдачи ушёл
	// каскадом в этой же транзакции и её факт не держит; факт, который держит
	// другая действующая выдача, свёртка оставляет (kaname#919).
	if err := w.AccessBindingsW().EmitRelationDelete(ctx, stored); err != nil {
		return err
	}
	// Симметрия созданию (kacho#2055): создание со-коммитит событие реконсайла,
	// которым материализуется пообъектный кортеж владельца, — снятие обязано
	// со-коммитить ОТЗЫВ в ту же writer-tx. Каскад `ON DELETE` его не заменяет:
	// он ключуется по идентификатору ПРИВЯЗКИ, а не снятого объекта. Воркер на
	// событие зовёт `ReconcileObject`, а тот на отсутствующем объекте получает
	// пустой желаемый набор — что и есть отзыв.
	// Снятие ВЫПУЩЕННЫХ кортежей выше — не то же самое: оно снимает набор,
	// который эмитировала САМА привязка. Событие отзывает пообъектные
	// кортежи, которые материализовали ДРУГИЕ привязки НА этом объекте.
	if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.accessBinding", string(id)); rerr != nil {
		return rerr
	}
	// Emit subject_change_outbox row in the same TX as the deletion: a rollback
	// of this TX will not leave an orphan outbox row (atomicity guarantee).
	// НА КАЖДОГО субъекта привязки, а не на легаси-одиночку: см.
	// emitSubjectChangeForEverySubject; перечень прочитан до удаления.
	if err := emitSubjectChangeFor(ctx, w.AccessBindingsW().EmitSubjectChangeEvent, subjects,
		"binding_revoke", "binding_delete"); err != nil {
		return err
	}

	// Emit the durable audit_outbox compliance event in the SAME writer-tx
	// (запрет #10). Actor = the authenticated revoker (captured sync), falling
	// back to the original granter when the caller identity is unknown so the
	// trail is never empty. Atomic with the DELETE: a rolled-back revoke leaves
	// no audit row claiming the access was removed.
	revokeActor := actor
	if revokeActor == "" {
		revokeActor = string(deletedBinding.GrantedByUserID)
	}
	if err := revokedAuditFor(ctx, w, subjects, revokeActor, deletedBinding); err != nil {
		return err
	}
	if err := w.Commit(ctx); err != nil {
		return err
	}
	committed = true

	// ЗДЕСЬ СТОЯЛО СИНХРОННОЕ УДАЛЕНИЕ КОРТЕЖЕЙ ИЗ ВНЕШНЕГО ДВИЖКА — предмета нет.
	//
	// Оно существовало ради ЛАТЕНТНОСТИ: строка намерения, положенная в журнал той же
	// транзакцией, доезжала до движка дренажом, и до этого момента отозванный доступ
	// продолжал отвечать «есть». Быстрый путь закрывал окно, журнал оставался доставкой
	// «хотя бы один раз».
	//
	// Окна больше нет: прямой факт складывается из ТОЙ ЖЕ строки журнала триггером —
	// в ТОЙ ЖЕ транзакции, что и снятие выдачи. Отзыв действует С КОММИТА не «быстрее»,
	// а по построению, и догонять его вторым писателем нечего.

	return nil
}
