// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource.go — RegisterResourceUseCase (Internal FGA-proxy).
//
// RegisterResource / UnregisterResource let a resource-owning module
// (vpc/compute/nlb) register or remove an owner-hierarchy FGA tuple *through
// IAM* — the module never writes FGA directly. The tuple intent is
// enqueued into kaname.fga_outbox in ONE writer-tx (atomic emit-in-tx,
// ban #10) and applied asynchronously by the existing drainer
// (clients/fga_applier.go), whose idempotent classification makes the contract:
//
//	repeat register of the same tuple → OK  (already_exists → ErrAlreadyApplied)
//	unregister of an absent tuple     → OK  (cannot_delete  → ErrAlreadyApplied)
//
// so neither AlreadyExists nor NotFound ever surfaces (proto contract).
//
// Sync unary per the proto (RegisterResourceResponse is empty); the
// at-least-once retry guarantee is provided by the caller-side drainer,
// not by an LRO. The tuple is taken verbatim from the request: the
// payload already carries the pre-composed FGA strings ({subject_id, relation,
// object}), so this use-case is the generic owner-tuple relay, not a
// resource-type-aware composer.
package internal_iam

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho/pkg/authz/proxytuple"
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

// resourceMirrorEmitter — narrow write port for the
// output-only mirror: UPSERT/DELETE a kaname.resource_mirror row inside the
// caller-owned tx (atomic co-commit with the owner-tuple emit, ban #10).
// Implemented by *repo/kaname/pg.ResourceMirrorEmitter.
//
// UpsertTx reports TWO verdicts the statements already compute: whether a row was
// written at all (the monotonic guard — a redelivery carrying an OLDER version updates
// zero rows), and whether the write left the selector-relevant projection byte-identical
// (a redelivery carrying the NEWER version — it applies, but nothing about the object
// changed). The register path needs both: the first tells it there is nothing to do, the
// second tells it that what it must do cannot involve removing anything.
type resourceMirrorEmitter interface {
	UpsertTx(ctx context.Context, tx service.Tx, row service.ResourceMirrorRow) (applied, projectionUnchanged bool, err error)
	DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, tombstone time.Time) error
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

// residualTupleReader — narrow read port: name every relationship STILL standing on an
// object, so a withdrawal can finish the job instead of removing only the one tuple it
// happened to be handed.
//
// WHY THE WITHDRAWING SIDE CANNOT NAME THEM ITSELF. A registration writes three kinds of
// relationship, and the consumer can name only one of them at teardown. The object→scope
// pointer it holds. The per-object verbs are derived from grants and belong to the
// reconciler. The third — the creator's own `owner` — is written through this proxy at
// create time from the caller's identity, and NOTHING stores that identity afterwards:
// neither the consumer's own row nor this mirror carries the subject. So the only side
// that can still name that tuple when the resource is being destroyed is the side that
// holds the store.
//
// Leaving it to the consumer is what produced the defect this port exists to close. The
// withdrawal was emitted, delivered and marked sent with no error, and the creator kept a
// relationship from which the model derives ALL FIVE verbs — an object answering ALLOW
// for the rest of its existence to someone the product had already told it was gone. The
// class is invisible to every assertion of the form "we called it": measured on the stand
// 2026-08-04, the residue survived a delivered withdrawal in 180 of 180 registry
// registrations and in 60 of 60 repository ones.
type residualTupleReader interface {
	// ObjectTuples returns the relationships currently standing on the object.
	ObjectTuples(ctx context.Context, object string) ([]service.RelationTuple, error)
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
// cannot do (security.md §Hardening-инвариант 8: «ноль отказов за всю жизнь контроля»
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
	// it must still take away. Counted for the same reason the two above are: this step
	// can only fail by refusing the withdrawal, so "never failed" and "never ran" would
	// otherwise look identical, and the second is how the residue survived unnoticed in
	// the first place.
	stepResidualRead = "residual_read"
	// stepResidualWithdraw — recorded ONCE PER TUPLE the withdrawal took away beyond the
	// one it was handed. A permanent zero on this series says the teardown path has
	// stopped removing anything extra, which is precisely the defect state.
	stepResidualWithdraw = "residual_withdraw"

	outcomeOK    = "ok"
	outcomeError = "error"
)

// RegisterResourceRequest / UnregisterResourceRequest fields the use-case
// consumes. We accept the proto messages directly at the handler boundary and
// pass a small value struct here to keep the use-case transport-agnostic.
type tupleIntent struct {
	subject  string
	relation string
	object   string
}

// splitObject разбирает объект FGA `<type>:<id>` на имя типа и непрозрачный
// идентификатор. `validateTuple` уже потребовал грамматику `<type>:<id>`,
// поэтому разрез по первому двоеточию безопасен.
//
// ПЕРЕВОДА ЗДЕСЬ БОЛЬШЕ НЕТ, и это несущее место (kacho#1990). Стоявший тут
// обратный перевод спрашивал словарь, ПОРОЖДЁННЫЙ СБОРКОЙ, и на промахе
// оставлял имя МОДЕЛИ там, где колонка названа словарём КАТАЛОГА, — то есть
// объект типа, заведённого применением манифеста в работающем процессе, в
// зеркало не попадал вовсе. Имя каталога теперь спрашивается у живой строки, в
// той же транзакции, что пишет зеркало (`catalog_type.go`).
func (t tupleIntent) splitObject() (fgaType, id string) {
	colon := strings.IndexByte(t.object, ':')
	return t.object[:colon], t.object[colon+1:]
}

// isPureGrant reports whether the intent only opens the object for anonymous
// read (`user:* #v_get`) instead of describing the object's own state.
//
// Such an intent carries no parent scope and no labels — nothing about the
// resource changed — yet it addresses the SAME object key as the resource's own
// registration. Feeding it through the projection path would overwrite the
// resource's parent scope with the empty one it carries and, on withdrawal,
// delete the projection of a resource that still exists. So a pure grant is
// applied as a tuple and nothing else.
func (t tupleIntent) isPureGrant() bool {
	return proxytuple.IsPublicReadGrant(t.subject, t.relation)
}

// RegisterResourceUseCase orchestrates the FGA-proxy tuple relay + the
// resource_mirror co-commit (labels + parent-scope of the owner object) + the
// reconcile-event enqueue and parent_account_id backfill.
type RegisterResourceUseCase struct {
	emitter      relationOutboxEmitter
	mirror       resourceMirrorEmitter
	txb          service.TxBeginner
	catalogTypes catalogTypeReader     // ОБЯЗАТЕЛЕН, см. конструктор
	reconcile    reconcileEventEmitter // optional, nil-safe
	accounts     accountResolver       // optional, nil-safe
	objRecon     objectReconciler      // sync post-commit — optional, nil-safe
	residual     residualTupleReader   // names what the withdrawal must still take away — optional, nil-safe
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
func NewRegisterResourceUseCase(
	emitter relationOutboxEmitter,
	mirror resourceMirrorEmitter,
	txb service.TxBeginner,
	catalogTypes catalogTypeReader,
) *RegisterResourceUseCase {
	return &RegisterResourceUseCase{emitter: emitter, mirror: mirror, txb: txb, catalogTypes: catalogTypes}
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

// WithResidualTupleReader wires the reader that names what is STILL standing on an object
// whose registration is being withdrawn. nil-safe: without it the withdrawal removes only
// the tuple it was handed, which is the pre-existing behaviour.
func (uc *RegisterResourceUseCase) WithResidualTupleReader(r residualTupleReader) *RegisterResourceUseCase {
	uc.residual = r
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

// Register validates the tuple + labels, then UPSERTs the mirror row AND enqueues
// an fga.tuple.write row in ONE writer-tx (atomic co-commit, ban #10).
func (uc *RegisterResourceUseCase) Register(ctx context.Context, in registerInput) error {
	t, err := validateTuple(in)
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
	fgaType, objID := t.splitObject()
	if t.isPureGrant() {
		// Tuple only: no projection write, so no redelivery gate to consult and
		// no binding fan-out to drive (no binding's desired set depends on the
		// wildcard tuple).
		_, err = uc.emitGrant(ctx, t, true, sourceVersion(in))
		return err
	}
	objType, changed, projectionUnchanged, err := uc.emit(ctx, t, service.ResourceMirrorRow{
		ObjectType:      fgaType,
		ObjectID:        objID,
		ParentProjectID: in.GetParentProjectId(),
		ParentAccountID: in.GetParentAccountId(),
		ParentChain:     in.GetParentChain(),
		Labels:          labels,
		SourceVersion:   sourceVersion(in),
	}, true)
	if err != nil {
		return err
	}
	// REDELIVERY GATE. Every consumer delivers each registration TWICE — a synchronous
	// post-commit call plus the at-least-once register-drainer replaying the same durable
	// intent — and the two carry the SAME monotonic source_version lineage (the sync path
	// stamps wall-clock AFTER the commit, the drainer replays the version the DB stamped
	// INSIDE the writer-tx, i.e. strictly earlier). The mirror's monotonic guard therefore
	// already recognises the second delivery: it changes zero rows. When nothing changed
	// there is, by construction, nothing to materialise — the delivery that DID write the
	// row emitted the owner tuple and the reconcile event — so the expensive forward
	// reconcile fan-out is skipped. Before this, iam re-ran the whole materialisation on
	// every duplicate (measured: two byte-identical 27-row fga_outbox batches 6.7 ms apart
	// for one created network).
	//
	// This is keyed on APPLIED STATE via a MONOTONIC version, NOT on queue contents.
	// De-duplicating unsent outbox rows by (event type, payload) would silently drop a
	// re-grant — grant → revoke → grant folds into grant → revoke — whereas a genuine
	// re-registration always carries a newer version (and an unregister removes the mirror
	// row outright), so it can never be swallowed. The revoke path is deliberately NOT
	// gated at all: a swallowed revoke is an over-grant, so Unregister always materialises.
	//
	// UNVERSIONED PRODUCERS ARE NEVER GATED. A caller that sends no source_version maps to
	// '-infinity', which loses every monotonic comparison — so its writes report `changed
	// = false` for reasons that have NOTHING to do with redelivery, and gating them would
	// suppress REAL materialisation. (Measured: registry's synchronous registrar sends no
	// version, so every re-registration after the first would have lost its fast path and
	// fallen back to the async drain — a widened read-your-writes window, not a saving.)
	// The gate therefore requires positive proof of redelivery — a version to compare —
	// and fails OPEN into doing the work when it has none.
	if !changed && !sourceVersion(in).IsZero() {
		return nil
	}
	// Instant-visibility: after the owner-tuple + mirror + reconcile event COMMIT, drive
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
	// only the duplicate that arrives with an OLDER version. Which of the two deliveries
	// arrives first is not fixed, and when the drainer wins, the synchronous registrar's
	// call carries the NEWER version — it applies, so the gate lets it through, and the
	// GUARDED forward then finds the members the first delivery just wrote and routes the
	// object to the FULL EXCLUSIVE recompute, on the single binding every object of the
	// account shares — one avoidable EXCLUSIVE pass per registered object, on the single
	// binding every object of the account contends for.
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
	// `projectionUnchanged` is the mirror's own SQL verdict that the write advanced only
	// source_version: parent-scope and labels — everything a selector reads — were
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
// (architecture.md — per-call deadline на каждом внешнем вызове). Щедро относительно
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

// sourceVersion extracts the owner-stamped monotonic version from the request.
// Nil/zero proto Timestamp → zero time.Time, which the mirror
// emitter normalizes to '-infinity' (legacy producer, applies unconditionally).
func sourceVersion(in versionedInput) time.Time {
	ts := in.GetSourceVersion()
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// Unregister validates the tuple, then DELETEs the mirror row AND enqueues an
// fga.tuple.delete row in ONE writer-tx (symmetry). Labels/parent on the
// Unregister payload are ignored (the row is removed by its (type,id) PK).
func (uc *RegisterResourceUseCase) Unregister(ctx context.Context, in unregisterInput) error {
	t, err := validateTuple(in)
	if err != nil {
		return err
	}
	if t.isPureGrant() {
		// Withdrawing the public grant removes the wildcard tuple. The resource
		// itself is untouched and its projection must survive.
		_, err = uc.emitGrant(ctx, t, false, sourceVersion(in))
		return err
	}
	fgaType, objID := t.splitObject()
	// EVERY relationship THIS PROXY COULD HAVE WRITTEN ON THE OBJECT GOES WITH IT.
	//
	// Withdrawing a hierarchy tuple is not "remove one edge", it is "this object no
	// longer exists". The request names one edge because that is all the consumer can
	// name; the rest — the creator's `owner` above all — was written from an identity
	// nobody stored, so only the side holding the store can still name it. Reading it
	// here is what turns a withdrawal that was merely DELIVERED into one that took
	// effect. Read BEFORE the tx: it is an external call and must not hold a DB
	// connection open across it.
	residual, err := uc.residualTuples(ctx, t)
	if err != nil {
		return err
	}
	// SourceVersion carries the unregister tombstone-version: the mirror DELETE
	// fires only if it is >= the stored register (Delete-after-Update reorder
	// cannot wipe a fresher row).
	//
	// The revoke path is NEVER gated on "did the mirror change": a swallowed revoke is a
	// standing over-grant, so the tuple-delete and the reconcile event are enqueued
	// unconditionally (fail-closed). The producer-cost saving is taken only on the grant
	// path, where a no-op is provably a redelivery of work already done.
	objType, _, _, err := uc.emit(ctx, t, service.ResourceMirrorRow{
		ObjectType:    fgaType,
		ObjectID:      objID,
		SourceVersion: sourceVersion(in),
	}, false, residual...)
	if err != nil {
		return err
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
	uc.syncReconcile(ctx, objType, objID, false)
	return nil
}

// residualTuples names what a teardown must take away IN ADDITION to the tuple the
// request carries: every relationship still standing on the object that this proxy is
// permitted to write. The set is not re-spelled here — it is asked of the declaration
// (pkg/authz/proxytuple.IsProxyWritable), so a set that changes cannot leave a residue
// behind a comment that still names the old one. Returns nil for a pure-grant
// withdrawal and when no reader is wired.
//
// WHY THE SET IS EXACTLY THE PROXY-WRITABLE ONE, AND NOT "EVERYTHING ON THE OBJECT".
// The per-object verbs are NOT ours to remove: they are derived from grants and the
// reconciler's delete-stale pass — already driven from here — is what takes them away.
// Removing them here would race that pass and, worse, would make this the second place
// deciding the same question. The proxy-writable set is precisely the complement: the
// relationships nothing else can account for once the object is gone.
//
// WHY A READ FAILURE IS AN ERROR AND NOT A SHRUG. Passing silently would restore the
// original defect and make it permanent AND quiet: the caller would be told the
// withdrawal succeeded while the access stood. The withdrawal intent is durable in the
// consumer's own outbox and a repeat is a no-op at the drainer, so refusing here costs a
// redelivery and nothing else (security.md §Hardening-инвариант 8: a control that
// degrades on failure must distinguish a blip from a standing misconfiguration — here we
// refuse to take the risk at all, because the failure mode is a standing over-grant).
func (uc *RegisterResourceUseCase) residualTuples(ctx context.Context, t tupleIntent) ([]service.RelationTuple, error) {
	if uc.residual == nil {
		return nil, nil
	}
	standing, err := uc.residual.ObjectTuples(ctx, t.object)
	uc.observe(stepResidualRead, err)
	if err != nil {
		// Retriable, opaque: the consumer's drainer redelivers the identical intent.
		// Never echo the store's transport text (endpoint + store id leak).
		return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "authz backend unavailable")
	}
	out := make([]service.RelationTuple, 0, len(standing))
	for _, have := range standing {
		if have.Relation == t.relation && have.User == t.subject {
			continue // the request already carries this one
		}
		if !proxytuple.IsProxyWritable(have.User, have.Relation) {
			continue // not ours to remove — see the doc above
		}
		out = append(out, have)
	}
	for range out {
		uc.observe(stepResidualWithdraw, nil)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// tupleInput — the minimal transport-agnostic shape both RPCs share. Satisfied
// by the proto Register/Unregister request messages (handler adapts them).
type tupleInput interface {
	GetSubjectId() string
	GetRelation() string
	GetObject() string
}

// versionedInput — carries the owner-stamped monotonic source_version
// (register: state-version; unregister: tombstone-version). Both proto request
// messages satisfy it.
type versionedInput interface {
	GetSourceVersion() *timestamppb.Timestamp
}

// registerInput — Register additionally consumes the mirror fields (labels +
// parent-scope) + the source_version. Satisfied by
// *iamv1.RegisterResourceRequest.
type registerInput interface {
	tupleInput
	versionedInput
	GetLabels() map[string]string
	GetParentProjectId() string
	GetParentAccountId() string
	// GetParentChain — цепь предков произвольной формы. Пусто у вызывающего,
	// который её не шлёт; тогда предки читаются из двух полей выше, как раньше.
	GetParentChain() []string
}

// unregisterInput — Unregister consumes the tuple + the tombstone source_version.
// Satisfied by *iamv1.UnregisterResourceRequest.
type unregisterInput interface {
	tupleInput
	versionedInput
}

func validateTuple(in tupleInput) (tupleIntent, error) {
	subject := strings.TrimSpace(in.GetSubjectId())
	relation := strings.TrimSpace(in.GetRelation())
	object := strings.TrimSpace(in.GetObject())

	if subject == "" {
		return tupleIntent{}, shared.InvalidArg("subject_id", "required")
	}
	if relation == "" {
		return tupleIntent{}, shared.InvalidArg("relation", "required")
	}
	if object == "" {
		return tupleIntent{}, shared.InvalidArg("object", "required")
	}
	// FGA object/subject grammar: `<type>:<id>`, no whitespace and no `#`
	// (the latter is the userset separator and would corrupt the tuple).
	if err := validateRelationString("subject_id", subject); err != nil {
		return tupleIntent{}, err
	}
	if err := validateRelationString("object", object); err != nil {
		return tupleIntent{}, err
	}
	if strings.ContainsAny(relation, " \t\n#:") {
		return tupleIntent{}, shared.InvalidArg("relation", "invalid relation")
	}
	return tupleIntent{subject: subject, relation: relation, object: object}, nil
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
	// Exactly one ':' — a second colon is rejected. objectType() splits on the
	// FIRST colon, so a two-colon value would make the resource_mirror /
	// reconcile-outbox key ("a:b" from "type:a:b") diverge from the verbatim FGA
	// tuple object string ("type:a:b") — the mirror row and the tuple then
	// reference different objects.
	if strings.IndexByte(v[colon+1:], ':') >= 0 {
		return shared.InvalidArg(field, "invalid "+field)
	}
	return nil
}

// emitGrant enqueues ONLY the tuple write/delete, in its own writer-tx. Used for
// a pure grant (see tupleIntent.isPureGrant): there is no projection row to
// co-commit with, because the intent says nothing about the object's own state.
// The at-least-once contract is unchanged — the tuple enqueue is durable, and the
// drainer's idempotent classification makes a repeat a no-op.
// `version` приходит от вызывающего, а не берётся часами здесь: обе доставки
// одного намерения обязаны нести ОДНО значение, иначе гашение редоставки у
// принимающей стороны зависит от того, кто выиграл гонку.
//
// ПРЯМОЙ ФАКТ ОТНОШЕНИЯ ЗДЕСЬ НЕ ПИШЕТСЯ, И ЭТО НЕ УПУЩЕНИЕ. Он складывается из
// строки журнала, которую кладёт `EmitWriteTx`, — схемой, одинаково для всех
// производителей кортежа (use-case, реконсайлер, посев старта, сырой SQL
// миграции). Писатель, добавленный сюда, стал бы вторым местом об одном
// предмете: SQL-производителей он не покрывает вовсе, а с первым разошёлся бы
// версией. Отсюда же следует, что состояние формы E есть свёртка ТОГО ЖЕ
// журнала, из которого складывается состояние движка, — а значит расхождение
// между ними больше не может завестись от того, что кто-то забыл написать
// вторую строку.
func (uc *RegisterResourceUseCase) emitGrant(ctx context.Context, t tupleIntent, write bool, version time.Time) (bool, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		// Same opaque, no-leak contract as emit: retriable Unavailable.
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	tuples := []service.RelationTuple{{User: t.subject, Relation: t.relation, Object: t.object}}
	if write {
		err = uc.emitter.EmitWriteTx(ctx, tx, tuples)
	} else {
		err = uc.emitter.EmitDeleteTx(ctx, tx, tuples)
	}
	if err != nil {
		return false, fmt.Errorf("emit fga outbox: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	return true, nil
}

// emit runs the owner-tuple fga_outbox emit AND the resource_mirror UPSERT/DELETE
// in ONE writer-tx — both commit together or roll back together (atomic
// co-commit, ban #10). write=true → register (UPSERT + tuple.write);
// write=false → unregister (DELETE + tuple.delete).
// It returns whether the mirror statement actually CHANGED a row. On the register path a
// false means the monotonic guard rejected the write as not-newer — a redelivery of a
// registration already applied — and the owner-tuple + reconcile-event enqueues are
// SKIPPED with it (they were performed by the delivery that did write the row). The
// unregister path always enqueues (a swallowed revoke would be an over-grant), so its
// flag is informational only.
// `row.ObjectType` приходит сюда именем словаря МОДЕЛИ — тем, что стояло в
// кортеже, — и переводится в имя словаря КАТАЛОГА ВНУТРИ транзакции, до первого
// обращения к зеркалу. Переведённое имя возвращается вызывающему: пост-коммитный
// проход материализации адресует ТОТ ЖЕ объект, что легло в зеркало, и второй
// перевод у него разошёлся бы с первым молча.
func (uc *RegisterResourceUseCase) emit(ctx context.Context, t tupleIntent, row service.ResourceMirrorRow, write bool, extra ...service.RelationTuple) (objectType string, changed bool, projectionUnchanged bool, err error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		// Backend-down at connection acquisition → retriable Unavailable (the
		// handler maps ErrUnavailable → codes.Unavailable; the caller's
		// transactional-outbox drainer then re-delivers). Fixed opaque message —
		// never surface the raw pgx driver text (host/port/user/db).
		return "", false, false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	// Имя типа КАТАЛОГА — у живой строки, в этом же снимке (kacho#1990).
	if row.ObjectType, err = uc.catalogObjectType(ctx, tx, row.ObjectType); err != nil {
		return "", false, false, fmt.Errorf("resolve catalog object type: %w", err)
	}
	objectType = row.ObjectType

	// The tuple named by the request, plus whatever the caller established must go with
	// it (see residualTuples): one atomic enqueue, so a withdrawal cannot commit half of
	// its own removal.
	tuples := append([]service.RelationTuple{{User: t.subject, Relation: t.relation, Object: t.object}}, extra...)
	changed = true
	if write {
		// Backfill parent_account_id SAME-DB from projects.account_id when the
		// owner supplied only parent_project_id (IAM owns Project — no peer-call, no
		// cycle). The owner-supplied value (if any) wins only when the project is not
		// resolvable (graceful: a not-yet-mirrored project keeps the owner's value).
		if uc.accounts != nil && row.ParentAccountID == "" && row.ParentProjectID != "" {
			accID, ok, rerr := uc.accounts.AccountForProjectTx(ctx, tx, row.ParentProjectID)
			if rerr != nil {
				return "", false, false, fmt.Errorf("resolve account for project: %w", rerr)
			}
			if ok {
				row.ParentAccountID = accID
			}
		}
		// The mirror UPSERT runs FIRST so its monotonic verdict can gate the two
		// enqueues below. Ordering within the tx is otherwise irrelevant — all three
		// statements still commit together or roll back together (ban #10).
		if changed, projectionUnchanged, err = uc.mirror.UpsertTx(ctx, tx, row); err != nil {
			// Тип без живой строки каталога — это ОТКАЗ ВХОДУ, а не сбой записи.
			// Он выносится сюда до обёртки: обёртка «upsert resource mirror» —
			// внутреннее имя шага, и, доехав до провода, она сказала бы
			// вызывающему про наше устройство вместо того, что чинить.
			//
			// Полоса называет ПОЛЕ (`object`) отдельным элементом отказа, а не
			// прозой: вызывающий машинно узнаёт, какой из трёх элементов кортежа
			// негоден. Чей это тип — вопрос другой полосы, и на неё отвечает
			// правило приёма отказом по правам, без причины.
			if stderrors.Is(err, iamerr.ErrUnknownResourceType) {
				return "", false, false, shared.InvalidArg("object", iamerr.StripSentinel(err))
			}
			return "", false, false, fmt.Errorf("upsert resource mirror: %w", err)
		}
		// An UNVERSIONED producer ('-infinity') loses every monotonic comparison, so its
		// `changed = false` proves nothing about redelivery — treat it as changed so a
		// real registration is never suppressed (see the gate note in Register). For the
		// same reason it can prove nothing about staleness either: the version-only bump
		// it never satisfies is what would have established that, so it keeps the guard.
		if row.SourceVersion.IsZero() {
			changed = true
			projectionUnchanged = false
		}
		if changed {
			if err = uc.emitter.EmitWriteTx(ctx, tx, tuples); err != nil {
				return "", false, false, fmt.Errorf("emit fga outbox: %w", err)
			}
		}
	} else {
		if err = uc.emitter.EmitDeleteTx(ctx, tx, tuples); err != nil {
			return "", false, false, fmt.Errorf("emit fga outbox: %w", err)
		}
		if err = uc.mirror.DeleteTx(ctx, tx, row.ObjectType, row.ObjectID, row.SourceVersion); err != nil {
			return "", false, false, fmt.Errorf("delete resource mirror: %w", err)
		}
	}
	// Enqueue a reconcile event in the SAME writer-tx as the mirror
	// change (atomic co-commit, ban #10). The reconciler re-evaluates every
	// binding member referencing this object (selector membership / byName
	// containment / PENDING→ACTIVE verify). nil-safe when the reconciler is
	// unwired (the periodic sweep then catches up).
	//
	// Skipped on a no-op register (see the redelivery gate in Register): the mirror is
	// byte-for-byte what it already was, so re-running the reconciler over it would
	// re-derive an identical desired set and change nothing.
	if uc.reconcile != nil && changed {
		// NOTE: keep these literals in sync with reconcile_outbox.EventUpsert /
		// reconcile_outbox.EventDelete (the drainer reads them). They are inlined
		// here rather than imported because this use-case must not depend on the
		// repo (pg) package — clean-arch dependency rule.
		eventType := "mirror.upsert"
		if !write {
			eventType = "mirror.delete"
		}
		if err = uc.reconcile.EmitTx(ctx, tx, eventType, row.ObjectType, row.ObjectID); err != nil {
			return "", false, false, fmt.Errorf("emit reconcile event: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		// Backend-down at commit → retriable Unavailable (same opaque, no-leak
		// contract as Begin). The row/tuple did not durably land; the caller's
		// drainer re-delivers.
		return "", false, false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	return objectType, changed, projectionUnchanged, nil
}
