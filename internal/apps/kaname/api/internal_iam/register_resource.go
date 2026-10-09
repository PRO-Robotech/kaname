// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource.go — RegisterResourceUseCase (Internal FGA-proxy).
//
// RegisterResource / UnregisterResource let a resource-owning module register an
// EVENT of its object, or withdraw the object, *through IAM* — the module never
// writes relations directly. SetPublicReadPublication lets the owner of a type that
// admits it publish an object for anonymous read.
//
// THE UNIT OF A GENERATION IS THE EVENT, NOT THE TUPLE (приёмка NTF-3, Р30
// «Единица поколения — событие»). A registration carries the event's whole set of
// tuples under one generation and is applied atomically — the projection admission
// (mirror, parent chain, object head) and the journal rows of the set commit in ONE
// writer-tx, or the generation is REJECTED_STALE and nothing is written. Applying
// tuple by tuple would lose every tuple after the first: they would arrive with the
// same generation, not newer than the head. A withdrawal is addressed by the object
// and takes EVERY relationship this proxy could have written on it.
//
// The contract stays idempotent: a stale or repeated delivery is REJECTED_STALE and
// the call answers OK, so neither AlreadyExists nor NotFound ever surfaces.
package internal_iam

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	corevalidate "github.com/PRO-Robotech/corelib/validate"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// relationOutboxEmitter — narrow write port: emit FGA tuple
// write/delete rows inside a caller-owned tx. Implemented by
// *repo/kaname/pg.FGAOutboxEmitter.
type relationOutboxEmitter interface {
	EmitWriteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
	EmitDeleteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
}

// resourceMirrorEmitter — narrow write port: put a registration or withdrawal intent
// into the projection admission inside the caller-owned tx (atomic co-commit with the
// owner-tuple emit, ban #10). The projection — mirror, parent chain and object head — is
// written by ONE producer, the database trigger `resource_event`, which compares the
// generation with the object's head (Р30 «Приём поколения — CAS»). Implemented by
// *repo/kaname/pg.ResourceMirrorEmitter.
//
// Both methods report whether the generation APPLIED: false is REJECTED_STALE — a late or
// repeated delivery that changed nothing (mirror, tombstone, chain). UpsertTx also reports
// whether the applied write left the selector-relevant projection byte-identical: the
// register path needs both — the first tells it there is nothing to do, the second that
// what it must do cannot involve removing anything.
type resourceMirrorEmitter interface {
	UpsertTx(ctx context.Context, tx service.Tx, row service.ResourceMirrorRow) (applied, projectionUnchanged bool, err error)
	DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, generation int64) (applied bool, err error)
}

// reconcileEventEmitter — narrow write port: enqueue a reconcile
// event into kaname.resource_reconcile_outbox in the SAME writer-tx as the
// mirror UPSERT/DELETE (atomic co-commit, ban #10). The reconciler-worker
// drains these and re-evaluates every binding member referencing the changed
// object (selector + byName containment / PENDING→ACTIVE verify). Optional —
// nil-safe (a deployment without the reconciler still mirrors correctly; the
// periodic sweep then catches up).
type reconcileEventEmitter interface {
	EmitTx(ctx context.Context, tx service.Tx, eventType, objectType, objectID string) error
}

// accountResolver — narrow read port: resolve a project's account_id
// SAME-DB (IAM owns Project) so the mirror's parent_account_id is backfilled even
// when the owner (compute) only supplied parent_project_id. NO cross-service call
// (IAM reads its own projects table). Optional — nil-safe (the owner-supplied
// parent_account_id is used as-is when the resolver is unwired).
type accountResolver interface {
	AccountForProjectTx(ctx context.Context, tx service.Tx, projectID string) (accountID string, ok bool, err error)
}

// objectReconciler — narrow port (instant-visibility): drive a SYNCHRONOUS post-commit
// materialization so the freshly-registered object's owner v_get materializes BEFORE the
// consumer's create-Operation reports done (a create→immediate-GET resolves ALLOW without
// waiting for the async reconcile-outbox drain). Implemented by reconcile.Reconciler.
//
// The create-path uses the ADDITIVE forward fast-path (ReconcileObjectForward): it
// materializes ONLY the just-registered object's per-object tuples for each matching
// binding, WITHOUT the per-binding advisory lock / full O(scope) recompute — so N
// concurrent registrations in the same project/account (all sharing one editor/owner
// binding) do NOT serialize on that binding's lock (the throughput fix). The co-committed
// resource_reconcile_outbox event still drives the async worker's FULL ReconcileObject as
// the at-least-once backstop (delete-stale / audit / sweep), so a skipped or failed
// forward pass is re-converged.
//
// nil-safe + non-fatal: an unwired reconciler (or a reconcile error) never fails Register
// — the reconcile-outbox drain + periodic sweep are the backstop.
// ПРЯМОГО ПРИМЕНИТЕЛЯ УКАЗАТЕЛЯ ОБЛАСТИ ЗДЕСЬ БОЛЬШЕ НЕТ.
//
// Он существовал ради СРОКА: указатель «объект → проект» пишет только этот
// use-case, реконсайлер его не выводит, — а ярус администратора аккаунта достаёт
// объекты ЧЕРЕЗ него. Снятие, оставившее указатель в очереди, отвечало бы «доступ
// есть» целому ярусу на ресурсе, который продукт уже объявил снятым.
//
// Срок стал нулевым: строка журнала, положенная той же транзакцией, порождает
// прямой факт триггером — в момент коммита, в обе стороны. Ускорять нечего.

// residualTupleReader — narrow read port: name every relationship standing on an
// object, IN THE WITHDRAWAL'S OWN TX, after its generation was admitted.
//
// WHY THE WITHDRAWING SIDE CANNOT NAME THEM ITSELF. A registration writes the event's
// tuples — the object→scope pointer and the creator's own `owner` among them — and at
// teardown the consumer holds none of them: the withdrawal is addressed by the object
// alone. So the only side that can name what must go is the side that holds the store.
// Measured on the stand 2026-08-04, before the withdrawal read them: the creator's
// `owner` survived a delivered withdrawal in 180 of 180 registry registrations and in 60
// of 60 repository ones — an object answering ALLOW for the rest of its existence to
// someone the product had already told it was gone.
//
// WHY IN THE TX, AFTER THE ADMISSION. The admission compares the generation with the
// object's head and holds the head row's lock until commit. A set read after it is
// complete: a registration committed before the admission is in it, one arriving after
// waits on the head and goes REJECTED_STALE. A set read BEFORE the tx would miss a
// registration committed between the read and the admission, and its tuples would
// outlive the object.
type residualTupleReader interface {
	// ObjectTuplesTx returns the relationships currently standing on the object.
	ObjectTuplesTx(ctx context.Context, tx service.Tx, object string) ([]service.RelationTuple, error)
}

type objectReconciler interface {
	// ReconcileObjectForward — the GUARDED entry point: it first reads the object's
	// materialized members and, finding any, delegates to the FULL EXCLUSIVE
	// ReconcileObject whose delete-stale diff revokes a now-unmatched grant.
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
	// ReconcileObjectForwardNoStale — the same pass WITHOUT that guard, for an object the
	// caller has PROVED carries nothing stale. On this path the proof is the mirror's own
	// SQL verdict: the registration advanced only source_version and replaced no part of
	// the projection a selector reads.
	ReconcileObjectForwardNoStale(ctx context.Context, objectType, objectID string) error
}

// materializationRecorder — narrow observability port for the POST-COMMIT accelerators
// this use-case drives (the forward reconcile and the direct tuple apply). Optional,
// nil-safe.
//
// WHY IT IS PART OF THE CONTRACT AND NOT A NICETY. Both accelerators are best-effort by
// design: they are fronting a durable queue, so a failure costs latency, not the change.
// That is exactly what makes a permanently broken one invisible — it logs one WARN and
// the product keeps working, more slowly, forever. A counter that records BOTH runs and
// outcomes makes "never failed" distinguishable from "never ran", which a log line alone
// cannot do (§Hardening-инвариант 8: «ноль отказов за всю жизнь контроля»
// обязано быть заметно). The `step` label additionally exposes which materialization
// path was taken, so a regression that silently pushes every registration back onto the
// EXCLUSIVE recompute shows up as a shift between two counters rather than as latency
// somebody has to notice.
type materializationRecorder interface {
	ObserveRegisterPostCommit(step, outcome string)
}

// Post-commit steps + outcomes reported through materializationRecorder. Kept as
// constants so the metric's label set is closed and greppable from both sides.
const (
	stepForwardAdditive = "forward_additive" // proven no-stale → guard skipped
	stepForwardGuarded  = "forward_guarded"  // guard kept → may escalate to the full pass
	// Двух шагов прямого применения кортежей здесь больше нет: их предметом было
	// ускорение доставки в чужое хранилище, а доставка стала тождеством коммита.
	// stepResidualRead — the object-scoped listing a withdrawal performs to name what
	// it must take away. Counted for the same reason the two above are: this step
	// can only fail by refusing the withdrawal, so "never failed" and "never ran" would
	// otherwise look identical, and the second is how the residue survived unnoticed in
	// the first place.
	stepResidualRead = "residual_read"
	// stepResidualWithdraw — recorded ONCE PER TUPLE the withdrawal took away. A
	// permanent zero on this series says the teardown path has
	// stopped removing anything extra, which is precisely the defect state.
	stepResidualWithdraw = "residual_withdraw"

	outcomeOK    = "ok"
	outcomeError = "error"
)

// tupleIntent — one relationship on an object: the unit the journal carries.
type tupleIntent struct {
	subject  string
	relation string
	object   string
}

// objectRef — an object in the rights MODEL dictionary, `<type>:<id>`, already
// validated by validateObject.
type objectRef string

// split разбирает объект `<type>:<id>` на имя типа и непрозрачный идентификатор.
// `validateObject` уже потребовал грамматику `<type>:<id>`, поэтому разрез по первому
// двоеточию безопасен.
//
// ПЕРЕВОДА ЗДЕСЬ НЕТ, и это несущее место (kacho#1990). Имя каталога спрашивается у
// живой строки, в той же транзакции, что пишет зеркало (`catalog_type.go`).
func (o objectRef) split() (modelType, id string) {
	colon := strings.IndexByte(string(o), ':')
	return string(o)[:colon], string(o)[colon+1:]
}

// publicReadPublisher — narrow write port for the publication of an object for
// anonymous read (`user:* #v_get`). Implemented by *repo/kaname/pg.PublicReadPublisher.
//
// ApplyTx applies the owner's intent inside the caller-owned tx IN THE ORDER OF THE
// OWNER'S VERSIONS and only to the object's CURRENT incarnation, judged by its head: an
// intent not newer than the last one applied, or for a withdrawn incarnation, changes
// nothing and enqueues no journal row, so a late delivery cannot overturn a newer one
// in either direction nor land on a repository re-created under the same name.
// WithdrawTx takes the publication with the withdrawn object; DropStaleIncarnationTx
// drops a publication of an earlier incarnation once a registration began a new one.
//
// A PORT, NOT A TUPLE EMIT, AND THE DIFFERENCE IS THE WHOLE FIX (kaname#107). The
// journal alone cannot say "closed at v2": removal deletes the fact, and a late open at
// v1 would then find an empty slot. The publication row keeps that order.
type publicReadPublisher interface {
	ApplyTx(ctx context.Context, tx service.Tx, in service.PublicReadIntent) (applied bool, err error)
	WithdrawTx(ctx context.Context, tx service.Tx, objectType, objectID string) error
	DropStaleIncarnationTx(ctx context.Context, tx service.Tx, objectType, objectID, headType string) error
}

// admitsPublication reports whether an object of this MODEL type may carry a
// publication at all — asked of the same closed list the proxy's acceptance rule
// reads (corelib/authz/proxytuple), not re-spelled here.
func admitsPublication(modelType string) bool {
	for _, admitted := range proxytuple.PublicReadObjectTypes() {
		if admitted == modelType {
			return true
		}
	}
	return false
}

// RegisterResourceUseCase orchestrates the FGA-proxy tuple relay + the
// resource_mirror co-commit (labels + parent-scope of the owner object) + the
// reconcile-event enqueue and parent_account_id backfill.
type RegisterResourceUseCase struct {
	emitter      relationOutboxEmitter
	mirror       resourceMirrorEmitter
	txb          service.TxBeginner
	catalogTypes catalogTypeReader     // ОБЯЗАТЕЛЕН, см. конструктор
	publications publicReadPublisher   // ОБЯЗАТЕЛЕН, см. конструктор
	reconcile    reconcileEventEmitter // optional, nil-safe
	accounts     accountResolver       // optional, nil-safe
	residual     residualTupleReader   // ОБЯЗАТЕЛЕН, см. конструктор
	objRecon     objectReconciler      // sync post-commit — optional, nil-safe
	metrics      materializationRecorder
	logger       *slog.Logger
}

// NewRegisterResourceUseCase — constructor. `mirror` co-commits the
// resource_mirror row in the same writer-tx as the owner-tuple emit.
//
// `catalogTypes` — ПАРАМЕТР, А НЕ ОПЦИЯ, и различие несущее. Необъявленный
// читатель означал бы запасной путь «переводим словарём сборки», то есть ровно
// тот дефект, ради снятия которого он заведён (kacho#1990): запасной путь
// молчалив — он даёт верный ответ на посеянных типах и неверный на заведённых
// применением, и отличить одно от другого по исходу нельзя. Обязательность
// проверяет КОМПИЛЯТОР: каждое место сборки use-case названо им поимённо, и
// забыть провязку нельзя.
//
// `publications` — ТОЖЕ ПАРАМЕТР, и по той же причине. Без него у публикации нет
// порядка: запасным путём здесь был бы голый кортеж в журнал, то есть ровно то
// состояние, в котором запоздавшая доставка открытия после закрытия возвращала бы
// анонимное чтение (kaname#107). Опция с «нет — значит голый кортеж» делала бы
// этот дефект молчаливым умолчанием.
//
// `residual` — ТОЖЕ ПАРАМЕТР. Снятие адресуется объектом и не несёт ни одного
// кортежа: что снимать, называет только он. Без него снятие убирало бы зеркало и
// оставляло бы все отношения на объекте — объект, которого нет, отвечал бы «доступ
// есть».
func NewRegisterResourceUseCase(
	emitter relationOutboxEmitter,
	mirror resourceMirrorEmitter,
	txb service.TxBeginner,
	catalogTypes catalogTypeReader,
	publications publicReadPublisher,
	residual residualTupleReader,
) *RegisterResourceUseCase {
	return &RegisterResourceUseCase{
		emitter: emitter, mirror: mirror, txb: txb,
		catalogTypes: catalogTypes, publications: publications, residual: residual,
	}
}

// WithReconcile wires the reconcile-event emitter: a mirror change
// enqueues a resource_reconcile_outbox event in the same writer-tx.
func (uc *RegisterResourceUseCase) WithReconcile(r reconcileEventEmitter) *RegisterResourceUseCase {
	uc.reconcile = r
	return uc
}

// WithAccountResolver wires the same-DB parent_account_id backfill.
func (uc *RegisterResourceUseCase) WithAccountResolver(a accountResolver) *RegisterResourceUseCase {
	uc.accounts = a
	return uc
}

// WithObjectReconciler wires the sync post-commit ReconcileObject
// (instant visibility). nil-safe. An optional logger surfaces a non-fatal
// reconcile error (the outbox drain + sweep remain the backstop).
func (uc *RegisterResourceUseCase) WithObjectReconciler(r objectReconciler, logger *slog.Logger) *RegisterResourceUseCase {
	uc.objRecon = r
	uc.logger = logger
	return uc
}

// WithMetrics wires the OPTIONAL post-commit observability recorder. nil-safe: without
// it the accelerators still run and still log, they are just not counted.
func (uc *RegisterResourceUseCase) WithMetrics(m materializationRecorder) *RegisterResourceUseCase {
	uc.metrics = m
	return uc
}

// observe reports one post-commit step outcome when a recorder is wired.
func (uc *RegisterResourceUseCase) observe(step string, err error) {
	if uc.metrics == nil {
		return
	}
	outcome := outcomeOK
	if err != nil {
		outcome = outcomeError
	}
	uc.metrics.ObserveRegisterPostCommit(step, outcome)
}

// Register validates the event — object, set of tuples, labels and generation — then
// puts the registration into the projection admission AND, when its generation was
// newer than the object's head and so applied, enqueues the event's whole set of
// tuples, in ONE writer-tx (atomic co-commit, ban #10). A generation not newer than the
// head is REJECTED_STALE: nothing is written, and the call still answers OK (the proxy
// is idempotent).
func (uc *RegisterResourceUseCase) Register(ctx context.Context, in registerInput) error {
	object, tuples, err := validateRegistration(in)
	if err != nil {
		return err
	}
	labels := in.GetLabels()
	// Minimal sanity-validation of the owner-supplied labels (defense-in-depth):
	// mirror the Kachō label-pattern so an arbitrary/oversized map
	// never lands. Reuses the corelib validator (key/value pattern, size).
	if err := corevalidate.Labels("labels", labels); err != nil {
		return err
	}
	gen, err := requireGeneration(in)
	if err != nil {
		return err
	}
	modelType, objID := object.split()
	objType, changed, projectionUnchanged, err := uc.applyRegistration(ctx, object, tuples, service.ResourceMirrorRow{
		ObjectType:      modelType,
		ObjectID:        objID,
		ParentProjectID: in.GetParentProjectId(),
		ParentAccountID: in.GetParentAccountId(),
		ParentChain:     in.GetParentChain(),
		Labels:          labels,
		Generation:      gen,
	})
	if err != nil {
		return err
	}
	// REDELIVERY GATE. Every consumer delivers each registration TWICE — a synchronous
	// post-commit call plus the at-least-once register-drainer replaying the same durable
	// intent — and both carry the SAME generation. The object's head therefore recognises
	// the second delivery: it is not newer, REJECTED_STALE, nothing written. When nothing
	// changed there is, by construction, nothing to materialise — the delivery that DID
	// apply emitted the event's tuples and the reconcile event — so the expensive forward
	// reconcile fan-out is skipped. Before the gate, iam re-ran the whole materialisation
	// on every duplicate (measured: two byte-identical 27-row fga_outbox batches 6.7 ms
	// apart for one created network).
	//
	// This is keyed on APPLIED STATE via the object's generation, NOT on queue contents.
	// De-duplicating unsent outbox rows by (event type, payload) would silently drop a
	// re-grant, whereas a genuine re-registration always carries a newer generation, so it
	// can never be swallowed. There is no admission without a generation, so there is no
	// longer an unversioned producer the gate would have to let through blind.
	if !changed {
		return nil
	}
	// Instant-visibility: after the event's tuples + mirror + reconcile event COMMIT, drive
	// a SYNCHRONOUS ADDITIVE forward materialization so the creator's per-object v_get
	// materializes before the consumer's create-Operation reports done — a
	// create→immediate-GET resolves ALLOW without waiting for the async reconcile-outbox
	// drain. The forward path takes NO per-binding advisory lock, so N concurrent
	// registrations in the same scope do NOT serialize (throughput). nil-safe + NON-fatal:
	// the resource is already durably registered; the async worker's FULL ReconcileObject
	// (from the co-committed reconcile event) + the periodic sweep are the at-least-once
	// backstop, so a forward error here is logged, not propagated (Register stays
	// successful).
	//
	// WHICH ENTRY POINT, AND WHY THE GATE ABOVE IS NOT ENOUGH. The gate above recognises
	// a delivery whose generation is not newer than the head. A NEWER generation that
	// changed nothing a selector reads (a labels-only round trip back to the same value,
	// a re-registration of the same state) applies, so the gate lets it through, and the
	// GUARDED forward would then find the members an earlier delivery wrote and route the
	// object to the FULL EXCLUSIVE recompute, on the single binding every object of the
	// account shares — one avoidable EXCLUSIVE pass per such registration.
	//
	// WHAT THIS IS AND IS NOT MEASURED TO FIX. The escalation is real and this removes it,
	// but do NOT read it as the whole of the materialization window: on a kind stand
	// (2026-08-04) the race was reproduced only in unit form, because the SYNCHRONOUS
	// delivery won every time — across 367 registrations `forward_additive` fired ZERO
	// times, so this branch never ran and the before/after window was identical within
	// run-to-run noise. In the same measurement the window that DID blow past the client
	// budget came from a different place: under concurrency the synchronous forward is
	// cancelled on the caller's per-call deadline (`context canceled`), materialization
	// falls back to the async drain, and the objects left invisible were exactly the
	// cancelled ones. That term is NOT addressed here. The step counter below is what
	// makes which-path-ran observable instead of inferred — it is how the above was
	// established at all.
	//
	// `projectionUnchanged` is the admission trigger's own verdict that the write advanced
	// only the generation: parent-scope and labels — everything a selector reads — were
	// already byte-identical. Nothing an earlier pass materialized from those facts can
	// have gone stale, so the delete-stale-capable pass has no work to do and the
	// registration stays additive. It is NOT the caller's word: iam derives it from the
	// row it already holds, so a consumer cannot ask to skip the guard.
	//
	// A registration that DID replace the projection (label flipped off, moved to another
	// parent) keeps the guarded entry point — that is precisely the revoke-on-update the
	// guard exists for.
	uc.syncReconcile(ctx, objType, objID, projectionUnchanged)
	return nil
}

// syncReconcile drives the optional post-commit forward materialization. `noStale` picks
// the entry point WITHOUT the delete-stale guard, and may only be set when iam itself has
// established that nothing materialized on the object can have gone stale (see Register).
// nil-safe; a reconcile error is non-fatal (logged when a logger is wired, and counted
// when a recorder is wired) — the async full ReconcileObject backstop re-converges.
// Бюджет пост-коммитного прохода. Отвязка снимает ОТМЕНУ вызывающего, но не время:
// повисший на блокировке проход иначе держал бы горутину всю жизнь процесса
// (§«Per-call deadline на КАЖДОМ внешнем вызове»). Щедро относительно
// здорового прохода (миллисекунды — низкие секунды) и конечно; исчерпание бюджета —
// не потеря данных, дренаж и реконсайлер сходятся к тому же состоянию.
const postCommitForwardBudget = 30 * time.Second

func (uc *RegisterResourceUseCase) syncReconcile(ctx context.Context, objType, objID string, noStale bool) {
	if uc.objRecon == nil {
		return
	}

	// ПОЧЕМУ КОНТЕКСТ ОТВЯЗЫВАЕТСЯ ОТ ОТМЕНЫ ВЫЗЫВАЮЩЕГО.
	//
	// Этот проход исполняется ПОСЛЕ коммита writer-tx, и вызывающему он уже не нужен:
	// его ответ не зависит от исхода (отказ здесь нефатален by design — VBC-15).
	// Но контекст запроса несёт per-call deadline кросс-сервисного регистратора
	// (services/<svc>/internal/clients/iam_sync_registrar.go, 5 с), и его истечение
	// отменяло не ответ, а САМУ МАТЕРИАЛИЗАЦИЮ: под конкуренцией замер дал 121 отказ
	// с `context canceled`, и невидимыми оставались ровно отменённые объекты —
	// создатель не видел свой свежий ресурс до асинхронного дренажа (p95 окна 82.6 с
	// при клиентском бюджете чтения-своих-записей 12.5 с).
	//
	// Отвязка законна ровно потому же, почему законна отвязка в shared/postcommit.go:
	// проход — УСКОРИТЕЛЬ, а не источник истины. Всё, что он материализует, уже
	// закоммичено в writer-tx выше (owner-tuple, строка зеркала, событие реконсайла),
	// поэтому пропущенный, упавший или убитый проход сходится через дренаж и
	// реконсайлер. Отвязка меняет, КОГДА работа наблюдается, а не ВЫПОЛНЯЕТСЯ ли она.
	//
	// Это НЕ барьер на видимость (ban #9): `Operation.done` у вызывающего по-прежнему
	// не ждёт материализации, а Register остаётся нефатальным к отказу прохода.
	//
	// Значения контекста (trace / request-id / slog-handler) сохраняются — иначе проход
	// потерял бы наблюдаемость ровно там, где она и нужна для разбора.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postCommitForwardBudget)
	defer cancel()
	step := stepForwardGuarded
	var err error
	if noStale {
		step = stepForwardAdditive
		err = uc.objRecon.ReconcileObjectForwardNoStale(ctx, objType, objID)
	} else {
		err = uc.objRecon.ReconcileObjectForward(ctx, objType, objID)
	}
	uc.observe(step, err)
	if err != nil && uc.logger != nil {
		uc.logger.WarnContext(ctx, "register resource: post-commit forward reconcile failed (drain/sweep will retry)",
			slog.String("object_type", objType), slog.String("object_id", objID),
			slog.String("step", step), slog.Any("err", err))
	}
}

// requireGeneration takes the object's generation from the request. There is no
// admission without one (Р30 «Поколение и проекция», NTF3-174 (н)): the inherited path
// «an empty version is −∞ and always applies» is gone, so `0` is a refusal that names the
// field, not a degraded write.
func requireGeneration(in generationInput) (int64, error) {
	switch g := in.GetGeneration(); {
	case g == 0:
		return 0, shared.InvalidArg("generation", "required")
	case g < 0:
		return 0, shared.InvalidArg("generation", "must be positive")
	default:
		return g, nil
	}
}

// Unregister validates the object and the withdrawal's generation, then puts the
// withdrawal into the projection admission AND — when applied — takes EVERY
// relationship this proxy could have written on the object and the object's
// publication, in ONE writer-tx. The applied withdrawal leaves the object's tombstone.
// A withdrawal not newer than the head is REJECTED_STALE: the object was already
// re-registered past it (or withdrawn by a newer one), and removing its tuples now would
// revoke what the newer state still grants; nothing is enqueued and nothing is
// materialized.
func (uc *RegisterResourceUseCase) Unregister(ctx context.Context, in unregisterInput) error {
	object, err := validateObject("object", in.GetObject())
	if err != nil {
		return err
	}
	gen, err := requireGeneration(in)
	if err != nil {
		return err
	}
	objType, applied, err := uc.applyWithdrawal(ctx, object, gen)
	if err != nil {
		return err
	}
	if !applied {
		return nil
	}
	// SYMMETRY WITH Register. Registration drives its materialization in-process right
	// after the commit; withdrawal used to hand its materialization entirely to the
	// reconcile queue. The result was a product fast at granting and slow at revoking:
	// the object's per-object verbs appeared inside the create request and were still
	// answered ALLOW long after the resource itself had begun answering 404 (measured on
	// the stand: twelve seconds, bounded only by queue depth, not by anything the caller
	// could observe or wait for).
	//
	// The forward entry point is correct here even though it is named for the additive
	// fast path: its delete-stale guard routes an object that ALREADY has materialized
	// members to the FULL pass, and the mirror row was removed in the tx above, so that
	// pass derives an empty desired set and strips the object's tuples — which is exactly
	// the withdrawal. The co-committed reconcile event stays the at-least-once backstop,
	// so a failure here degrades to the previous latency rather than losing the revoke.
	//
	// The guard is NEVER lifted here (noStale = false), and that is not caution but
	// mechanism: the removal IS the delete-stale diff, so an additive pass would strip
	// nothing at all.
	_, id := object.split()
	uc.syncReconcile(ctx, objType, id, false)
	return nil
}

// withdrawnTuples names what the withdrawal takes away: every relationship standing
// on the object that this proxy is permitted to write. The set is not re-spelled here
// — it is asked of the declaration (corelib/authz/proxytuple.IsProxyWritable), so a set
// that changes cannot leave a residue behind a comment that still names the old one.
//
// WHY THE SET IS EXACTLY THE PROXY-WRITABLE ONE, AND NOT "EVERYTHING ON THE OBJECT".
// The per-object verbs are NOT ours to remove: they are derived from grants and the
// reconciler's delete-stale pass — already driven from here — is what takes them away.
// Removing them here would race that pass and, worse, would make this the second place
// deciding the same question. The proxy-writable set is precisely the complement: the
// relationships nothing else can account for once the object is gone. The publication
// (`user:* #v_get`) is proxy-writable but goes by its own path, with its row and under
// its version (publicReadPublisher.WithdrawTx): a bare delete of the verb row carries no
// owner version, and the projection does not fold such a row at all.
//
// WHY A READ FAILURE IS AN ERROR AND NOT A SHRUG. Passing silently would leave the
// relationships standing on an object the product has withdrawn — a standing
// over-grant. The withdrawal intent is durable in the consumer's own outbox and a
// repeat is a no-op once applied, so refusing here costs a redelivery and nothing else
// (§Hardening-инвариант 8).
func (uc *RegisterResourceUseCase) withdrawnTuples(ctx context.Context, tx service.Tx, object objectRef) ([]service.RelationTuple, error) {
	standing, err := uc.residual.ObjectTuplesTx(ctx, tx, string(object))
	uc.observe(stepResidualRead, err)
	if err != nil {
		// Retriable, opaque: the consumer's drainer redelivers the identical intent.
		// Never echo the store's text.
		return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	out := make([]service.RelationTuple, 0, len(standing))
	for _, have := range standing {
		if !proxytuple.IsProxyWritable(have.User, have.Relation) {
			continue // not ours to remove — see the doc above
		}
		if proxytuple.IsPublicReadGrant(have.User, have.Relation) {
			continue // the publication goes by its own path — see the doc above
		}
		out = append(out, have)
	}
	for range out {
		uc.observe(stepResidualWithdraw, nil)
	}
	return out, nil
}

// objectInput — the object both the withdrawal and the publication address.
type objectInput interface {
	GetObject() string
}

// generationInput — carries the object's generation (register: state; unregister:
// tombstone). Both proto request messages satisfy it.
type generationInput interface {
	GetGeneration() int64
}

// registerInput — Register consumes the event: the object, the set of its tuples,
// the mirror fields (labels + parent-scope) and the generation. Satisfied by
// *iamv1.RegisterResourceRequest — the set's element type is the contract's own, the
// same way LookupSubjectUseCase consumes its request.
type registerInput interface {
	objectInput
	generationInput
	GetTuples() []*iamv1.RegisteredTuple
	GetLabels() map[string]string
	GetParentProjectId() string
	GetParentAccountId() string
	// GetParentChain — цепь предков произвольной формы. Пусто — «предков нет»:
	// применённая регистрация заменяет набор рёбер объекта целиком.
	GetParentChain() []string
}

// unregisterInput — Unregister consumes the object and the tombstone generation.
// Satisfied by *iamv1.UnregisterResourceRequest.
type unregisterInput interface {
	objectInput
	generationInput
}

// publicationInput — Publish consumes the owner's intent about anonymous read.
// Satisfied by *iamv1.SetPublicReadPublicationRequest.
type publicationInput interface {
	objectInput
	GetPublished() bool
	GetPublicationVersion() *timestamppb.Timestamp
	GetObjectGeneration() int64
}

// wildcardSubjectRefusal — набор события подстановочного субъекта не несёт:
// публикация для анонимного чтения идёт своим методом (Р30, NTF3-185 (в)).
const wildcardSubjectRefusal = "wildcard subject is published by SetPublicReadPublication"

// validateObject requires the FGA `<type>:<id>` object and names `field` on refusal.
func validateObject(field, v string) (objectRef, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", shared.InvalidArg(field, "required")
	}
	if err := validateRelationString(field, v); err != nil {
		return "", err
	}
	return objectRef(v), nil
}

// validateRegistration validates the event: the object and its set of tuples. The set
// is non-empty, carries every pair once and no wildcard subject (Р30 «Единица поколения
// — событие»); each refusal names the field `tuples`.
func validateRegistration(in registerInput) (objectRef, []tupleIntent, error) {
	object, err := validateObject("object", in.GetObject())
	if err != nil {
		return "", nil, err
	}
	set := in.GetTuples()
	if len(set) == 0 {
		return "", nil, shared.InvalidArg("tuples", "required")
	}
	seen := make(map[string]struct{}, len(set))
	out := make([]tupleIntent, 0, len(set))
	for _, el := range set {
		subject := strings.TrimSpace(el.GetSubjectId())
		relation := strings.TrimSpace(el.GetRelation())
		switch {
		case subject == "":
			return "", nil, shared.InvalidArg("tuples", "subject_id required")
		case relation == "":
			return "", nil, shared.InvalidArg("tuples", "relation required")
		case strings.HasSuffix(subject, ":*"):
			return "", nil, shared.InvalidArg("tuples", wildcardSubjectRefusal)
		}
		if validateRelationString("tuples", subject) != nil {
			return "", nil, shared.InvalidArg("tuples", "invalid subject_id")
		}
		if strings.ContainsAny(relation, " \t\n#:") {
			return "", nil, shared.InvalidArg("tuples", "invalid relation")
		}
		key := subject + "#" + relation
		if _, dup := seen[key]; dup {
			return "", nil, shared.InvalidArg("tuples", "duplicate "+key)
		}
		seen[key] = struct{}{}
		out = append(out, tupleIntent{subject: subject, relation: relation, object: string(object)})
	}
	return object, out, nil
}

// validatePublication validates the owner's publication intent: the object of a type
// that admits public read, the publication's version and the incarnation's generation.
func validatePublication(in publicationInput) (objectRef, time.Time, int64, error) {
	object, err := validateObject("object", in.GetObject())
	if err != nil {
		return "", time.Time{}, 0, err
	}
	v := in.GetPublicationVersion()
	if v == nil {
		return "", time.Time{}, 0, shared.InvalidArg("publication_version", "required")
	}
	if err := v.CheckValid(); err != nil || v.AsTime().IsZero() {
		return "", time.Time{}, 0, shared.InvalidArg("publication_version", "invalid timestamp")
	}
	switch g := in.GetObjectGeneration(); {
	case g == 0:
		return "", time.Time{}, 0, shared.InvalidArg("object_generation", "required")
	case g < 0:
		return "", time.Time{}, 0, shared.InvalidArg("object_generation", "must be positive")
	}
	if modelType, _ := object.split(); !admitsPublication(modelType) {
		return "", time.Time{}, 0, shared.InvalidArg("object", "type "+modelType+" does not admit public read")
	}
	return object, v.AsTime(), in.GetObjectGeneration(), nil
}

// validateRelationString enforces the FGA `<type>:<id>` shape: exactly one ':',
// non-empty type and id, no whitespace, no '#'.
func validateRelationString(field, v string) error {
	if strings.ContainsAny(v, " \t\n#") {
		return shared.InvalidArg(field, "invalid "+field)
	}
	colon := strings.IndexByte(v, ':')
	if colon <= 0 || colon == len(v)-1 {
		return shared.InvalidArg(field, "invalid "+field)
	}
	// Exactly one ':' — a second colon is rejected. split() cuts on the FIRST colon,
	// so a two-colon value would make the resource_mirror / reconcile-outbox key ("a:b"
	// from "type:a:b") diverge from the verbatim tuple object string ("type:a:b") — the
	// mirror row and the tuple then reference different objects.
	if strings.IndexByte(v[colon+1:], ':') >= 0 {
		return shared.InvalidArg(field, "invalid "+field)
	}
	return nil
}

// Publish applies the owner's intent about anonymous read of ONE object — the pure
// grant `user:* #v_get` — in its own writer-tx, through the publication port
// (Р30 «Публикация для анонимного чтения»; NTF3-186).
//
// WHAT IT DOES. The publication store judges the object's incarnation by its head
// (a withdrawn incarnation is never published), compares the intent's version with the
// last one applied and applies it only when strictly newer; an applied intent enqueues
// the journal row out of which the projection folds (or removes) the direct fact in the
// same commit. A stale or repeated delivery, or one for another incarnation, changes
// nothing and enqueues nothing — and that is the success of the call, not a refusal: the
// proxy's contract is idempotent, and a consumer redelivering an intent already
// superseded must hear OK, never an error it would retry forever.
//
// WHY THE VERSION IS THE OWNER'S AND NOT A CLOCK HERE. The producer delivers every
// publication TWICE — synchronously after its commit and through its durable queue —
// both carrying the one version its writer-tx stamped. The service therefore sees the
// intents of one object in any order, with repeats. Only the owner's version can tell
// which one is newest; a clock read here would order deliveries, not intents, and a late
// synchronous open arriving after the close would reopen a private object.
//
// NO DIRECT FACT IS WRITTEN HERE, BY DESIGN. It is folded out of the journal row by the
// schema, identically for every producer; a second writer here would be a second place
// about one subject.
func (uc *RegisterResourceUseCase) Publish(ctx context.Context, in publicationInput) error {
	object, version, objectGeneration, err := validatePublication(in)
	if err != nil {
		return err
	}
	tx, err := uc.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	modelType, id := object.split()
	headType, err := uc.catalogObjectType(ctx, tx, modelType)
	if err != nil {
		return fmt.Errorf("resolve catalog object type: %w", err)
	}
	if _, err := uc.publications.ApplyTx(ctx, tx, service.PublicReadIntent{
		ObjectType:       modelType,
		ObjectID:         id,
		HeadType:         headType,
		Published:        in.GetPublished(),
		Version:          version,
		ObjectGeneration: objectGeneration,
	}); err != nil {
		return fmt.Errorf("apply public-read publication: %w", err)
	}
	return commit(ctx, tx)
}

// begin opens the writer-tx of one admission. Backend-down at connection acquisition →
// retriable Unavailable (the handler maps ErrUnavailable → codes.Unavailable; the
// caller's transactional-outbox drainer then re-delivers). Fixed opaque message — never
// surface the raw pgx driver text (host/port/user/db).
func (uc *RegisterResourceUseCase) begin(ctx context.Context) (service.Tx, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	return tx, nil
}

// commit fixes the admission. Backend-down at commit → retriable Unavailable (same
// opaque, no-leak contract as begin): nothing durably landed, the caller's drainer
// re-delivers.
func commit(ctx context.Context, tx service.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	return nil
}

// applyRegistration puts the registration into the projection admission AND, when it
// applied, enqueues the event's set of tuples, drops a publication of a previous
// incarnation and enqueues the reconcile event — all in ONE writer-tx: they commit
// together or roll back together (atomic co-commit, ban #10).
//
// It returns whether the generation APPLIED (`changed`). False is REJECTED_STALE: the
// generation was not newer than the object's head — a late or repeated delivery — and
// the trigger wrote nothing; then nothing else is enqueued either (Р30 «Приём поколения
// — CAS»).
//
// `row.ObjectType` приходит сюда именем словаря МОДЕЛИ — тем, что стояло в объекте, — и
// переводится в имя словаря КАТАЛОГА ВНУТРИ транзакции, до первого обращения к
// зеркалу. Переведённое имя возвращается вызывающему: пост-коммитный проход
// материализации адресует ТОТ ЖЕ объект, что легло в зеркало, и второй перевод у него
// разошёлся бы с первым молча.
func (uc *RegisterResourceUseCase) applyRegistration(ctx context.Context, object objectRef, set []tupleIntent, row service.ResourceMirrorRow) (objectType string, changed, projectionUnchanged bool, err error) {
	tx, err := uc.begin(ctx)
	if err != nil {
		return "", false, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	modelType := row.ObjectType
	// Имя типа КАТАЛОГА — у живой строки, в этом же снимке (kacho#1990).
	if row.ObjectType, err = uc.catalogObjectType(ctx, tx, row.ObjectType); err != nil {
		return "", false, false, fmt.Errorf("resolve catalog object type: %w", err)
	}
	objectType = row.ObjectType

	// Backfill parent_account_id SAME-DB from projects.account_id when the owner
	// supplied only parent_project_id (IAM owns Project — no peer-call, no cycle). The
	// owner-supplied value (if any) wins only when the project is not resolvable
	// (graceful: a not-yet-mirrored project keeps the owner's value).
	if uc.accounts != nil && row.ParentAccountID == "" && row.ParentProjectID != "" {
		accID, ok, rerr := uc.accounts.AccountForProjectTx(ctx, tx, row.ParentProjectID)
		if rerr != nil {
			return "", false, false, fmt.Errorf("resolve account for project: %w", rerr)
		}
		if ok {
			row.ParentAccountID = accID
		}
	}
	// The admission runs FIRST so its verdict gates the enqueues below.
	if changed, projectionUnchanged, err = uc.mirror.UpsertTx(ctx, tx, row); err != nil {
		// Тип без живой строки каталога — это ОТКАЗ ВХОДУ, а не сбой записи. Он
		// выносится сюда до обёртки: обёртка «upsert resource mirror» — внутреннее имя
		// шага, и, доехав до провода, она сказала бы вызывающему про наше устройство
		// вместо того, что чинить. Полоса называет ПОЛЕ (`object`) отдельным
		// элементом отказа, а не прозой.
		if stderrors.Is(err, iamerr.ErrUnknownResourceType) {
			return "", false, false, shared.InvalidArg("object", iamerr.StripSentinel(err))
		}
		return "", false, false, fmt.Errorf("upsert resource mirror: %w", err)
	}
	if !changed {
		return objectType, false, false, nil
	}
	tuples := make([]service.RelationTuple, 0, len(set))
	for _, t := range set {
		tuples = append(tuples, service.RelationTuple{User: t.subject, Relation: t.relation, Object: t.object})
	}
	if err = uc.emitter.EmitWriteTx(ctx, tx, tuples); err != nil {
		return "", false, false, fmt.Errorf("emit fga outbox: %w", err)
	}
	// A NEW INCARNATION DOES NOT INHERIT AN OLDER ONE'S PUBLICATION. A registration that
	// began the incarnation (no head, or over the tombstone) moved the head's
	// incarnation boundary; a publication that landed for an earlier incarnation while
	// the head was absent is dropped here, in the same tx (Р30 «Публикация для
	// анонимного чтения»). On a live incarnation there is no such row and this is a
	// no-op.
	if admitsPublication(modelType) {
		_, id := object.split()
		if err = uc.publications.DropStaleIncarnationTx(ctx, tx, modelType, id, objectType); err != nil {
			return "", false, false, fmt.Errorf("drop stale public-read publication: %w", err)
		}
	}
	if err = uc.emitReconcile(ctx, tx, "mirror.upsert", row); err != nil {
		return "", false, false, err
	}
	if err = commit(ctx, tx); err != nil {
		return "", false, false, err
	}
	return objectType, true, projectionUnchanged, nil
}

// applyWithdrawal puts the withdrawal into the projection admission AND, when it
// applied, takes every proxy-writable relationship standing on the object — read in
// this tx, after the admission (see residualTupleReader) — and the object's publication,
// and enqueues the reconcile event, all in ONE writer-tx.
//
// THE OBJECT'S PUBLICATION GOES WITH THE OBJECT. Withdrawing means "this object no
// longer exists", and a publication cannot outlive its object: a repository's id is its
// NAME inside the registry, so a surviving publication would hand anonymous read to the
// next repository created under that name. After the withdrawal a late publication of
// the withdrawn incarnation is refused by the head (the tombstone), not by a row.
func (uc *RegisterResourceUseCase) applyWithdrawal(ctx context.Context, object objectRef, gen int64) (objectType string, applied bool, err error) {
	tx, err := uc.begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	modelType, id := object.split()
	if objectType, err = uc.catalogObjectType(ctx, tx, modelType); err != nil {
		return "", false, fmt.Errorf("resolve catalog object type: %w", err)
	}
	if applied, err = uc.mirror.DeleteTx(ctx, tx, objectType, id, gen); err != nil {
		return "", false, fmt.Errorf("delete resource mirror: %w", err)
	}
	if !applied {
		return objectType, false, nil
	}
	tuples, err := uc.withdrawnTuples(ctx, tx, object)
	if err != nil {
		return "", false, err
	}
	if len(tuples) > 0 {
		if err = uc.emitter.EmitDeleteTx(ctx, tx, tuples); err != nil {
			return "", false, fmt.Errorf("emit fga outbox: %w", err)
		}
	}
	if admitsPublication(modelType) {
		if err = uc.publications.WithdrawTx(ctx, tx, modelType, id); err != nil {
			return "", false, fmt.Errorf("withdraw public-read publication: %w", err)
		}
	}
	if err = uc.emitReconcile(ctx, tx, "mirror.delete", service.ResourceMirrorRow{ObjectType: objectType, ObjectID: id}); err != nil {
		return "", false, err
	}
	if err = commit(ctx, tx); err != nil {
		return "", false, err
	}
	return objectType, true, nil
}

// emitReconcile enqueues a reconcile event in the SAME writer-tx as the projection
// change (atomic co-commit, ban #10). The reconciler re-evaluates every binding member
// referencing this object (selector membership / byName containment / PENDING→ACTIVE
// verify). nil-safe when the reconciler is unwired (the periodic sweep then catches up).
// Only an APPLIED intent reaches here — a stale one returned before with nothing
// enqueued.
//
// NOTE: keep the event literals in sync with reconcile_outbox.EventUpsert /
// reconcile_outbox.EventDelete (the drainer reads them). They are inlined at the callers
// rather than imported because this use-case must not depend on the repo (pg) package
// — clean-arch dependency rule.
func (uc *RegisterResourceUseCase) emitReconcile(ctx context.Context, tx service.Tx, eventType string, row service.ResourceMirrorRow) error {
	if uc.reconcile == nil {
		return nil
	}
	if err := uc.reconcile.EmitTx(ctx, tx, eventType, row.ObjectType, row.ObjectID); err != nil {
		return fmt.Errorf("emit reconcile event: %w", err)
	}
	return nil
}
