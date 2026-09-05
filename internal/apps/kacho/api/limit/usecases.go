// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/status"

	kerrors "github.com/PRO-Robotech/kacho/pkg/errors"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// resourceKind — the noun used in the malformed-id message. One constant, so the
// sync format check and the not-found tone cannot drift apart.
const resourceKind = "limit"

// iamServiceDomain — the `domain` half of ErrorInfo (`iam.kacho.cloud`).
const iamServiceDomain = "iam"

// quotaReaderRelation — the NARROW relation an owner service must hold on the
// cluster object to read resolved ceilings and their delta.
//
// It is not `system_viewer`: that tier is the whole cluster-scoped read surface,
// and handing it over so a service can learn two numbers is a grant far wider than
// the capability. It is not `viewer` either — `viewer` on the cluster object is
// satisfied by a wildcard tuple by DESIGN (the global placement catalogue must be
// readable by every authenticated tenant), so a check against it would answer
// "yes" to everyone and look exactly like a gate (security.md §«Отношение,
// выполнимое подстановочным знаком»).
const quotaReaderRelation = "quota_reader"

// validateID — malformed own-id → sync INVALID_ARGUMENT, always the first
// statement of an RPC that takes one. Without it a malformed id reaches the store
// and returns NOT_FOUND, which asserts the absence of a resource the caller never
// named.
//
// corevalidate.ResourceID lets the EMPTY string through by contract, so the
// required-check is made here rather than assumed.
//
// The refusal carries the lane token as well as the code: a client keys on the
// token, and prose — stable as it is — is not parsable.
func validateID(id string) error {
	if id == "" {
		return shared.InvalidArg("limit_id", "limit_id: required")
	}
	if err := corevalidate.ResourceID(resourceKind, ids.PrefixLimitHyphen, id); err != nil {
		return kerrors.ReasonInvalidResourceID.Errf(
			kerrors.PeerRef{Service: iamServiceDomain, ResourceType: "iam.limit", ResourceID: id},
			"invalid %s id '%s'", resourceKind, id)
	}
	return nil
}

// ── Get ──────────────────────────────────────────────────────────────────────

// GetUseCase — sync read of one limit.
type GetUseCase struct{ repo limitRepo }

// NewGetUseCase — constructor.
func NewGetUseCase(r limitRepo) *GetUseCase { return &GetUseCase{repo: r} }

// Execute — direct-read lane: a well-formed id with no row is NOT_FOUND.
func (uc *GetUseCase) Execute(ctx context.Context, id string) (domain.Limit, error) {
	if err := validateID(id); err != nil {
		return domain.Limit{}, err
	}
	l, err := uc.repo.Get(ctx, domain.LimitID(id))
	if err != nil {
		return domain.Limit{}, shared.MapRepoErr(err)
	}
	return l, nil
}

// ── List ─────────────────────────────────────────────────────────────────────

// ListUseCase — sync cursor-paginated read.
type ListUseCase struct{ repo limitRepo }

// NewListUseCase — constructor.
func NewListUseCase(r limitRepo) *ListUseCase { return &ListUseCase{repo: r} }

// ListResult — one page plus the cursor for the next.
type ListResult struct {
	Limits        []domain.Limit
	NextPageToken string
}

// Execute — pagination format is validated FIRST, so a garbage token or an
// out-of-range page size is INVALID_ARGUMENT independently of what the caller
// holds and of what the store contains. `page_size` out of range is REJECTED,
// never clamped.
func (uc *ListUseCase) Execute(
	ctx context.Context, pageSize int64, pageToken string, f domain.LimitFilter,
) (ListResult, error) {
	if err := shared.ValidateRawPagination(pageToken, pageSize); err != nil {
		return ListResult{}, err
	}
	size, err := corevalidate.PageSize("page_size", pageSize)
	if err != nil {
		return ListResult{}, err
	}
	if verr := f.Validate(); verr != nil {
		return ListResult{}, shared.MapValidationErr(verr)
	}

	rows, next, err := uc.repo.List(ctx, int(size), pageToken, f)
	if err != nil {
		return ListResult{}, shared.MapRepoErr(err)
	}
	return ListResult{Limits: rows, NextPageToken: next}, nil
}

// ── Create ───────────────────────────────────────────────────────────────────

// CreateUseCase — states a ceiling for one triple.
type CreateUseCase struct {
	repo    limitRepo
	opsRepo operations.Repo
	logger  *slog.Logger
}

// NewCreateUseCase — constructor.
func NewCreateUseCase(r limitRepo, ops operations.Repo, logger *slog.Logger) *CreateUseCase {
	return &CreateUseCase{repo: r, opsRepo: ops, logger: logger}
}

// Execute — validate → persist Operation → insert.
//
// The Operation row is persisted BEFORE the write, so the id the caller receives is
// always pollable; a failure is recorded on it as a terminal error rather than
// leaving the caller polling a row that does not exist.
func (uc *CreateUseCase) Execute(ctx context.Context, req *iamv1.CreateLimitRequest) (*operationpb.Operation, error) {
	l := domain.Limit{
		ID:      domain.LimitID(ids.NewHyphenID(ids.PrefixLimitHyphen)),
		Scope:   scopeFromProto(req.GetScope()),
		ScopeID: strings.TrimSpace(req.GetScopeId()),
		Kind:    domain.LimitKind(strings.TrimSpace(req.GetKind())),
		Value:   req.GetValue(),
	}
	// Validation runs against the same entity that will be stored, so the rule the
	// caller is judged by and the rule the row satisfies are one rule.
	if err := l.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create limit %s for %s", l.Kind, scopeSubjectText(l)),
		&iamv1.CreateLimitMetadata{LimitId: string(l.ID)},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	created, err := uc.repo.Insert(ctx, l)
	if err != nil {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}
	return uc.finish(ctx, op, created)
}

// ── Update ───────────────────────────────────────────────────────────────────

// UpdateUseCase — changes the ceiling.
type UpdateUseCase struct {
	repo    limitRepo
	opsRepo operations.Repo
	logger  *slog.Logger
}

// NewUpdateUseCase — constructor.
func NewUpdateUseCase(r limitRepo, ops operations.Repo, logger *slog.Logger) *UpdateUseCase {
	return &UpdateUseCase{repo: r, opsRepo: ops, logger: logger}
}

// mutableFields — the known-set the update mask is checked against. `value` is the
// whole of it: the triple a limit governs IS its identity among those in force.
var mutableFields = []string{"value"}

// immutableFields — named separately so a mask naming one of them is refused BY
// NAME. They must be checked BEFORE the known-set check: the known-set does not
// contain them, so the generic "unknown field" answer would fire first and the
// caller would never learn that the field exists and simply cannot be changed.
var immutableFields = []string{"id", "created_at", "scope", "scope_id", "kind", "revision"}

// Execute — mask discipline, then the write.
func (uc *UpdateUseCase) Execute(ctx context.Context, req *iamv1.UpdateLimitRequest) (*operationpb.Operation, error) {
	id := req.GetLimitId()
	if err := validateID(id); err != nil {
		return nil, err
	}

	paths := req.GetUpdateMask().GetPaths()
	// Immutable first — see the comment on immutableFields.
	for _, p := range paths {
		for _, im := range immutableFields {
			if normalizeFieldPath(p) == im {
				return nil, shared.InvalidArg("update_mask",
					fmt.Sprintf("%s is immutable after Limit.Create", im))
			}
		}
	}
	known := make(map[string]struct{}, len(mutableFields))
	for _, f := range mutableFields {
		known[f] = struct{}{}
	}
	normalized := make([]string, 0, len(paths))
	for _, p := range paths {
		normalized = append(normalized, normalizeFieldPath(p))
	}
	if err := corevalidate.UpdateMask("update_mask", normalized, known); err != nil {
		return nil, err
	}
	if req.GetValue() < 0 {
		return nil, shared.InvalidArg("value", "Illegal argument value: must not be negative")
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update limit %s", id),
		&iamv1.UpdateLimitMetadata{LimitId: id},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	updated, err := uc.repo.Update(ctx, domain.LimitID(id), req.GetValue())
	if err != nil {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}
	return finishOp(ctx, uc.opsRepo, uc.logger, op, updated)
}

// ── Delete ───────────────────────────────────────────────────────────────────

// DeleteUseCase — withdraws a ceiling.
type DeleteUseCase struct {
	repo    limitRepo
	opsRepo operations.Repo
	logger  *slog.Logger
}

// NewDeleteUseCase — constructor.
func NewDeleteUseCase(r limitRepo, ops operations.Repo, logger *slog.Logger) *DeleteUseCase {
	return &DeleteUseCase{repo: r, opsRepo: ops, logger: logger}
}

// Execute — idempotent by construction: withdrawing an already-withdrawn ceiling
// succeeds and reports the same code as the first withdrawal, because the caller
// asked for the ceiling to be gone and it is.
func (uc *DeleteUseCase) Execute(ctx context.Context, id string) (*operationpb.Operation, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete limit %s", id),
		&iamv1.DeleteLimitMetadata{LimitId: id},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	withdrawn, existed, err := uc.repo.Withdraw(ctx, domain.LimitID(id))
	if err != nil {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}
	// On the idempotent repeat the response echoes the id alone: there is nothing
	// left to describe, and inventing a body would be describing a row that is not
	// in force.
	if !existed {
		withdrawn = domain.Limit{ID: domain.LimitID(id)}
	}
	return finishOp(ctx, uc.opsRepo, uc.logger, op, withdrawn)
}

// ── Resolve ──────────────────────────────────────────────────────────────────

// ResolveUseCase — the ceilings in force for one scope object, per kind of one
// service. Read by owner services; gated by the narrow relation.
type ResolveUseCase struct {
	repo    limitRepo
	checker authzguard.RelationChecker
	// logger — ЧИТАТЕЛЬ причины отказа. Заполняется умолчанием в конструкторе, а
	// не оставляется пустым: несобранный журнал вернул бы ровно то состояние,
	// ради которого он заводится, — отказ без единой строки о причине (#666).
	logger *slog.Logger
}

// NewResolveUseCase — constructor.
func NewResolveUseCase(r limitRepo) *ResolveUseCase {
	return &ResolveUseCase{repo: r, logger: slog.Default()}
}

// WithLogger заменяет журнал по умолчанию. Пустой не принимается: молчание — не
// настройка, а потеря причины.
func (uc *ResolveUseCase) WithLogger(l *slog.Logger) *ResolveUseCase {
	if l != nil {
		uc.logger = l
	}
	return uc
}

// WithQuotaReaderChecker wires the narrow ReBAC gate (defense-in-depth behind the
// edge's catalog entry). nil-safe: an unwired checker fails CLOSED — an
// unauthorised read of the platform's ceilings is not a lesser failure than an
// unauthorised write.
func (uc *ResolveUseCase) WithQuotaReaderChecker(c authzguard.RelationChecker) *ResolveUseCase {
	uc.checker = c
	return uc
}

// Execute — narrow gate, then one read of the whole stated set, then precedence.
func (uc *ResolveUseCase) Execute(ctx context.Context, scopeID, service string) ([]domain.EffectiveLimit, error) {
	if err := requireQuotaReader(ctx, uc.checker); err != nil {
		return nil, err
	}
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return nil, shared.InvalidArg("scope_id", "scope_id: required")
	}
	service = strings.TrimSpace(service)
	if service == "" {
		return nil, shared.InvalidArg("service", "service: required")
	}
	// A service nobody counts for is refused BY NAME rather than answered with an
	// empty list: an empty answer reads as "this tenant has no ceilings", and the
	// owner would then have to decide what that means — which is exactly the guess
	// this contract exists to remove.
	if len(domain.CountableKindsOfService(service)) == 0 {
		return nil, shared.InvalidArg("service",
			fmt.Sprintf("Illegal argument service: %s owns no countable resource kinds", service))
	}

	stated, ok, err := uc.repo.StatedFor(ctx, scopeID)
	if err != nil {
		// Перевод СТИРАЕТ причину (текст INTERNAL фиксирован, текст недоступности
		// опаковый), поэтому она называется журналу здесь — в том единственном
		// месте, где ещё цела.
		return nil, shared.LogRepoErr(ctx, uc.logger, "Resolve", err)
	}
	if !ok {
		// Direct-read lane: accounts and projects are iam's OWN rows.
		return nil, kerrors.ReasonResourceNotFound.Errf(
			kerrors.PeerRef{Service: iamServiceDomain, ResourceType: "iam.project", ResourceID: scopeID},
			"Project %s not found", scopeID)
	}
	return domain.ResolveEffective(service, stated), nil
}

// ── ListChangedSince ─────────────────────────────────────────────────────────

// ListChangedUseCase — the delta an owner pulls to keep its projection fresh.
type ListChangedUseCase struct {
	repo    limitRepo
	cursors deltaCursorCodec
	checker authzguard.RelationChecker
	// logger — ЧИТАТЕЛЬ причины отказа; см. одноимённое поле резолва.
	logger *slog.Logger
}

// NewListChangedUseCase — constructor.
func NewListChangedUseCase(r limitRepo, c deltaCursorCodec) *ListChangedUseCase {
	return &ListChangedUseCase{repo: r, cursors: c, logger: slog.Default()}
}

// WithLogger заменяет журнал по умолчанию. Пустой не принимается.
func (uc *ListChangedUseCase) WithLogger(l *slog.Logger) *ListChangedUseCase {
	if l != nil {
		uc.logger = l
	}
	return uc
}

// WithQuotaReaderChecker wires the narrow ReBAC gate. nil-safe, fail-closed.
func (uc *ListChangedUseCase) WithQuotaReaderChecker(c authzguard.RelationChecker) *ListChangedUseCase {
	uc.checker = c
	return uc
}

// ChangedResult — the delta page plus the cursor to pass next time.
type ChangedResult struct {
	Changes    []domain.Limit
	NextCursor string
}

// Execute — narrow gate, cursor format, then the page.
//
// The next cursor is returned even when the page is empty: a puller that only
// advanced on non-empty pages would re-scan the same tail forever once it caught up.
func (uc *ListChangedUseCase) Execute(ctx context.Context, cursor string, pageSize int64) (ChangedResult, error) {
	if err := requireQuotaReader(ctx, uc.checker); err != nil {
		return ChangedResult{}, err
	}
	if pageSize < 0 || pageSize > int64(shared.MaxListPageSize) {
		return ChangedResult{}, shared.InvalidArg("page_size", "Illegal argument page_size")
	}
	size, err := corevalidate.PageSize("page_size", pageSize)
	if err != nil {
		return ChangedResult{}, err
	}
	after, cerr := uc.cursors.Decode(cursor)
	if cerr != nil {
		return ChangedResult{}, shared.MapRepoErr(cerr)
	}

	rows, next, err := uc.repo.ChangedSince(ctx, after, int(size))
	if err != nil {
		// Единственная полоса, на которой тянущий узнаёт об отказе. Без строки
		// здесь причину назвать нечем: клиенту достаётся фиксированный текст, а
		// журнала доступа у сервиса нет.
		return ChangedResult{}, shared.LogRepoErr(ctx, uc.logger, "ListChangedSince", err)
	}
	return ChangedResult{Changes: rows, NextCursor: uc.cursors.Encode(next)}, nil
}

// moduleSubject — личность МОДУЛЯ: учётная запись, выведенная из проверенного
// сертификата пира. Пусто, когда сертификата нет (процессная фикстура) либо он
// не принадлежит модулю платформы.
func moduleSubject(ctx context.Context) string {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		return ""
	}
	sva, ok := authzguard.SANToServiceAccountID(san)
	if !ok {
		return ""
	}
	return "service_account:" + sva
}

// requireQuotaReader — the narrow gate, shared by both service-facing reads.
//
// ИСХОДОВ ТРИ, И ОНИ РАЗНЫЕ (#665).
//
//   - право есть → nil;
//   - модель ответила «нет» → PermissionDenied. Отказ говорит вызывающему
//     «повтор бессмыслен»: решение зависит от тройки (субъект, отношение,
//     объект), и одинаковый повтор не меняет ни одного из трёх;
//   - вопрос остался БЕЗ ОТВЕТА (хранилище отношений не отвечает, срок вызова
//     истёк, движок не сконфигурирован) → AuthzBackendUnavailable. О правах это
//     не говорит ничего, и тот же вопрос мгновением позже получает ответ.
//
// Fail-closed не меняется ни в одном из двух отказов: запрос отвергнут, доступа
// никто не получил. Различается КОД — и код здесь весь сигнал. Схлопнув их, гейт
// выдаёт терминальный вердикт на мигание: тянущий пределы перестаёт повторять
// (`retry.OnUnavailable` повторяет ТОЛЬКО недоступность), а на полосе мутации
// арендатор получает терминальный 403 на создании ресурса вместо повторяемого
// отказа.
//
// Прежняя редакция объявляла ровно обратное — «PermissionDenied на каждом
// исходе» — при том что сосед по пакету
// (`authzguard.AuthzBackendUnavailable`) объявляет различие смыслом своего
// существования, и три соседних стража его соблюдают. Два места об одном
// предмете, из которых верно было одно.
//
// Незаряженный проверяющий (`checker == nil`) остаётся ОТКАЗОМ, а не
// недоступностью, и это не непоследовательность: несобранный гейт повтором не
// чинится, поэтому «повтори позже» было бы обещанием, которого никто не
// исполнит.
func requireQuotaReader(ctx context.Context, checker authzguard.RelationChecker) error {
	if checker == nil {
		return authzguard.PermissionDenied()
	}
	// ЛИЧНОСТЕЙ РОВНО ДВЕ, и обе законны — поэтому они спрашиваются по одной, а
	// не циклом по списку.
	//
	// Величины читают два разных вызывающих: МОДУЛЬ на пути мутации (доказывает
	// себя сертификатом; членство в группе читателей заведено его служебной
	// учётной записи) и ЧЕЛОВЕК через край (его личность приезжает переданным
	// принципалом, а сертификат в этом случае принадлежит КРАЮ, который
	// читателем не является и быть не должен).
	//
	// ПОЧЕМУ НЕ ЦИКЛ. Их две по построению, и это свойство, а не коллекция: цикл
	// объявил бы стоимость вопроса растущей и был бы прав только если бы список
	// зависел от входа. Гейт стоимости страницы (`internal/authzfilter`) это и
	// заметил — справедливо.
	//
	// ЧТО СТОИЛА ОДНА ЛИЧНОСТЬ. Сперва гейт смотрел ТОЛЬКО принципала: модуль
	// работает от имени арендатора, тот читателем не является, и резолв отказывал
	// каждой мутации домена. Потом — ТОЛЬКО сертификат: администратор через край
	// потерял доступ, которым пользуется. Обе проверки нужны вместе.
	object := "cluster:" + domain.ClusterSingletonID

	// unanswered — неполадка на ЛЮБОМ из заданных вопросов. Хранится, а не
	// возвращается сразу: разрешению второе мнение не нужно, поэтому «да» второй
	// личности сильнее неполадки на первой.
	var unanswered error

	if subject := moduleSubject(ctx); subject != "" {
		allowed, err := checker.Check(ctx, subject, quotaReaderRelation, object)
		switch {
		case err != nil:
			unanswered = err
		case allowed:
			return nil
		}
	}
	if subject, ok := authzguard.PrincipalSubject(ctx); ok {
		allowed, err := checker.Check(ctx, subject, quotaReaderRelation, object)
		switch {
		case err != nil:
			unanswered = err
		case allowed:
			return nil
		}
	}

	// Отказ — решение ТОЛЬКО когда каждый заданный вопрос получил ответ. Иначе
	// «нет» одной личности и молчание другой были бы неотличимы от полного
	// отказа, а неотличимость и есть предмет. Та же форма — у соседнего гейта
	// пакета (`authzguard.AllowsVerb`).
	//
	// Сырая ошибка наружу не идёт (`security.md` §Hardening #1): текст
	// хранилища отношений может нести адрес и диагностику движка.
	if unanswered != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	return authzguard.PermissionDenied()
}

// finish — terminal Operation of a Create. Method form kept so the Create path
// reads like the others while sharing finishOp's body.
func (uc *CreateUseCase) finish(ctx context.Context, op operations.Operation, l domain.Limit) (*operationpb.Operation, error) {
	return finishOp(ctx, uc.opsRepo, uc.logger, op, l)
}

// finishOp — records the terminal Operation and returns it. One implementation for
// all three mutations: three copies would each need the same "response marshalling
// failed" arm, and the third would eventually not have it.
func finishOp(
	ctx context.Context, opsRepo operations.Repo, logger *slog.Logger,
	op operations.Operation, l domain.Limit,
) (*operationpb.Operation, error) {
	resp, merr := operationResponse(l)
	if merr != nil {
		return nil, merr
	}
	if err := opsRepo.MarkDone(ctx, op.ID, resp); err != nil && logger != nil {
		logger.ErrorContext(ctx, "limit: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done, op.Response = true, resp
	return shared.OperationToProto(&op), nil
}

// scopeSubjectText — the human half of an operation description.
func scopeSubjectText(l domain.Limit) string {
	if l.Scope == domain.LimitScopeDefault {
		return "the platform default"
	}
	return strings.ToLower(string(l.Scope)) + " " + l.ScopeID
}

// normalizeFieldPath — masks arrive in either snake_case (proto) or camelCase
// (REST через grpc-gateway). Both name the same field, so both are accepted;
// refusing one of them would make the answer depend on which door was used.
func normalizeFieldPath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		ch := p[i]
		if ch >= 'A' && ch <= 'Z' {
			b.WriteByte('_')
			b.WriteByte(ch - 'A' + 'a')
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}
