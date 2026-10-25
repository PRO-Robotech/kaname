// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// create.go — CreateGrantDelegationUseCase (GD-01…GD-07, GD-50).
//
// Порядок проверок (GD-05): форма — синхронно, первой; затем право выдавать на
// аккаунте; затем состав (роли объявлены манифестом одного модуля, не `iam`,
// типы цели того же модуля, делегат существует). Отказ в праве поэтому не
// раскрывает, есть ли роль и чья она. Уникальность действующего делегирования
// пары держит база (частичный уникальный индекс), отказ — в `Operation.error`.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// delegateTypeName — единственный тип делегата (Р1): имя значения контракта.
const delegateTypeName = "SUBJECT_TYPE_SERVICE_ACCOUNT"

// CreateInput — вход заведения делегирования. Типы — именами значений контракта
// (`SUBJECT_TYPE_*`): проверку формы делает use-case, обработчик только переносит.
type CreateInput struct {
	AccountID    string
	DelegateType string
	DelegateID   string
	RoleIDs      []string
	TargetTypes  []string
	SubjectTypes []string
}

// CreateGrantDelegationUseCase — заведение делегирования.
type CreateGrantDelegationUseCase struct {
	repo      Repo
	opsRepo   operations.Repo
	cat       catalog.Source
	relations clients.RelationStore
	logger    *slog.Logger
}

// NewCreateGrantDelegationUseCase — над хранилищем, операциями и каталожным
// фактом (живость типов цели — тот же снимок, что у цели выдачи).
func NewCreateGrantDelegationUseCase(r Repo, opsRepo operations.Repo, cat catalog.Source) *CreateGrantDelegationUseCase {
	return &CreateGrantDelegationUseCase{repo: r, opsRepo: opsRepo, cat: cat}
}

// WithRelationStore — дверь решения: право выдавать на аккаунте (Путь 0, Путь 2).
func (u *CreateGrantDelegationUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateGrantDelegationUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// Execute — синхронные проверки и операция заведения.
func (u *CreateGrantDelegationUseCase) Execute(ctx context.Context, in CreateInput) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	d, err := u.validateForm(in)
	if err != nil {
		return nil, err
	}
	if err := requireAccountGrantAuthority(ctx, u.repo, u.relations, d.AccountID); err != nil {
		return nil, err
	}
	module, err := u.validateComposition(ctx, d)
	if err != nil {
		return nil, err
	}
	d.Module = module
	caller := operations.PrincipalFromContext(ctx)
	d.DelegatedBy = domain.GrantDelegationActor{Type: caller.Type, ID: caller.ID}
	d.ID = domain.GrantDelegationID(ids.NewID(domain.PrefixGrantDelegation))
	actor := authzguard.PrincipalUserID(ctx)

	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM,
		fmt.Sprintf("Create grant delegation (%s → %s on account %s)", d.Module, d.DelegateID, d.AccountID),
		&iamv1.CreateGrantDelegationMetadata{GrantDelegationId: string(d.ID), AccountId: string(d.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		res, derr := u.doCreate(ctx, d, actor)
		if derr != nil && u.logger != nil {
			u.logger.Error("grant_delegation create operation failed", "op", op.ID, "err", derr,
				"account", string(d.AccountID), "delegate", string(d.DelegateID))
		}
		return res, derr
	})
	return &op, nil
}

// validateForm — форма запроса, синхронно и до права (GD-04). Отказ с полем —
// `shared.InvalidArg` (`field_violations[0]` = {поле, текст}); форма
// идентификатора — `shared.ValidateResourceID`, без деталей (Р6).
func (u *CreateGrantDelegationUseCase) validateForm(in CreateInput) (domain.GrantDelegation, error) {
	var d domain.GrantDelegation
	if in.AccountID == "" {
		return d, shared.InvalidArg("account_id", "account_id: required")
	}
	if err := shared.ValidateResourceID(in.AccountID, domain.PrefixAccount, "account"); err != nil {
		return d, err
	}
	if in.DelegateType != delegateTypeName {
		return d, shared.InvalidArg("delegate.type",
			"delegate.type: only SUBJECT_TYPE_SERVICE_ACCOUNT can hold a grant delegation")
	}
	if err := shared.ValidateResourceID(in.DelegateID, domain.PrefixServiceAccount, "service account"); err != nil {
		return d, err
	}
	if err := validateSet("role_ids", "role", "roles", in.RoleIDs, domain.MaxGrantDelegationRoles); err != nil {
		return d, err
	}
	if err := validateSet("target_types", "type", "types", in.TargetTypes, domain.MaxGrantDelegationTargetTypes); err != nil {
		return d, err
	}
	facts := u.facts()
	for _, t := range in.TargetTypes {
		if !domain.ValidTargetType(facts, t) {
			return d, shared.InvalidArg("target_types", fmt.Sprintf(
				"Illegal argument target_types[] %q (not a live entry of the platform resource catalog; grantable types are published by %s)",
				t, domain.CatalogEndpoint))
		}
	}
	subjects, err := subjectTypesOf(in.SubjectTypes)
	if err != nil {
		return d, err
	}
	d.AccountID = domain.AccountID(in.AccountID)
	d.DelegateID = domain.ServiceAccountID(in.DelegateID)
	for _, r := range in.RoleIDs {
		d.RoleIDs = append(d.RoleIDs, domain.RoleID(r))
	}
	d.TargetTypes = append([]string(nil), in.TargetTypes...)
	d.SubjectTypes = subjects
	return d, nil
}

// facts — каталожный факт; незаданный источник — ни одного годного типа (отказ,
// а не всеразрешение).
func (u *CreateGrantDelegationUseCase) facts() domain.TargetTypeCatalog {
	if u.cat == nil {
		return nil
	}
	if f := u.cat.Facts(); f != nil {
		return f
	}
	return nil
}

// validateSet — ось-набор: обязательна, не больше предела, без повторов.
func validateSet(field, noun, plural string, xs []string, limit int) error {
	if len(xs) == 0 {
		return shared.InvalidArg(field, field+": required")
	}
	if len(xs) > limit {
		return shared.InvalidArg(field, fmt.Sprintf("%s: at most %d %s", field, limit, plural))
	}
	seen := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if _, dup := seen[x]; dup {
			return shared.InvalidArg(field, fmt.Sprintf("%s: %s %s is listed twice", field, noun, x))
		}
		seen[x] = struct{}{}
	}
	return nil
}

// subjectTypesOf — ось типов субъекта: 1…4, без повторов, без
// `SUBJECT_TYPE_UNSPECIFIED`.
func subjectTypesOf(names []string) ([]domain.SubjectType, error) {
	const field = "subject_types"
	if len(names) == 0 {
		return nil, shared.InvalidArg(field, field+": required")
	}
	seen := make(map[domain.SubjectType]struct{}, len(names))
	out := make([]domain.SubjectType, 0, len(names))
	for _, n := range names {
		t, ok := domain.SubjectTypeOfPrincipal(n)
		if !ok || !strings.HasPrefix(n, "SUBJECT_TYPE_") {
			return nil, shared.InvalidArg(field, fmt.Sprintf("%s: %s is not a subject type", field, n))
		}
		if _, dup := seen[t]; dup {
			return nil, shared.InvalidArg(field, fmt.Sprintf("%s: type %s is listed twice", field, n))
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) > domain.MaxGrantDelegationSubjectTypes {
		return nil, shared.InvalidArg(field, fmt.Sprintf("%s: at most %d types", field, domain.MaxGrantDelegationSubjectTypes))
	}
	return out, nil
}

// validateComposition — состав делегирования, после права (GD-06): аккаунт
// существует; каждая роль существует и объявлена манифестом модуля; роли, их
// правила и типы цели — одного модуля M; M ≠ `iam`; делегат существует.
// Отдаёт M.
func (u *CreateGrantDelegationUseCase) validateComposition(ctx context.Context, d domain.GrantDelegation) (string, error) {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	// Аккаунт области существует. Владельцу и администратору аккаунта это
	// доказало право выдавать; администратор облака проходит право, не читая
	// аккаунта (Путь 0), и без этой проверки завёл бы делегирование на
	// несуществующий аккаунт: ссылка `account_id` внешнего ключа не несёт.
	if _, gerr := rd.Accounts().Get(ctx, d.AccountID); gerr != nil {
		if stderrors.Is(gerr, iamerr.ErrNotFound) {
			return "", status.Errorf(codes.FailedPrecondition, "Account %s not found", d.AccountID)
		}
		return "", shared.MapRepoErr(gerr)
	}

	modules := map[string]struct{}{}
	for _, id := range d.RoleIDs {
		role, gerr := rd.Roles().Get(ctx, id)
		if gerr != nil {
			if stderrors.Is(gerr, iamerr.ErrNotFound) {
				return "", status.Errorf(codes.FailedPrecondition, "Role %s not found", id)
			}
			return "", shared.MapRepoErr(gerr)
		}
		m := domain.RoleDeclaringModule(role)
		if m == "" {
			return "", status.Errorf(codes.FailedPrecondition, "role %s is not declared by a module manifest", id)
		}
		modules[m] = struct{}{}
		for _, rule := range role.Rules {
			if rule.Module != "" {
				modules[rule.Module] = struct{}{}
			}
		}
	}
	for _, t := range d.TargetTypes {
		modules[domain.ModuleOfCatalogType(t)] = struct{}{}
	}
	if len(modules) != 1 {
		found := make([]string, 0, len(modules))
		for m := range modules {
			found = append(found, m)
		}
		sort.Strings(found)
		return "", status.Errorf(codes.FailedPrecondition,
			"role_ids and target_types must belong to one module; found %s", strings.Join(found, ", "))
	}
	var module string
	for m := range modules {
		module = m
	}
	if module == "iam" {
		return "", status.Error(codes.FailedPrecondition, "module iam cannot be delegated")
	}
	if _, gerr := rd.ServiceAccounts().Get(ctx, d.DelegateID); gerr != nil {
		if stderrors.Is(gerr, iamerr.ErrNotFound) {
			return "", status.Errorf(codes.FailedPrecondition, "ServiceAccount %s not found", d.DelegateID)
		}
		return "", shared.MapRepoErr(gerr)
	}
	return module, nil
}

// doCreate — строка делегирования и строка аудита в одной транзакции писателя
// (Р5). Второе действующее делегирование пары — 23505, `ALREADY_EXISTS` (Д1).
func (u *CreateGrantDelegationUseCase) doCreate(ctx context.Context, d domain.GrantDelegation, actor string) (*anypb.Any, error) {
	d.CreatedAt = time.Now().UTC()
	created, err := shared.DoWithWriteTx(ctx, u.repo, func(ctx context.Context, w Writer) (domain.GrantDelegation, error) {
		out, ierr := w.AccessBindingsW().GrantDelegationsW().Insert(ctx, d)
		if ierr != nil {
			return domain.GrantDelegation{}, ierr
		}
		sorted := domain.SortedGrantDelegationAxes(out)
		if aerr := w.EmitAuditEvent(ctx, outboxtypes.AuditEvent{
			EventType:       auditEventCreated,
			TenantAccountID: string(out.AccountID),
			Payload: map[string]any{
				"actor":         actor,
				"delegation_id": string(out.ID),
				"account_id":    string(out.AccountID),
				"delegate":      string(out.DelegateID),
				"module":        out.Module,
				"role_ids":      sorted.RoleIDs,
				"target_types":  sorted.TargetTypes,
				"subject_types": sorted.SubjectTypes,
			},
		}); aerr != nil {
			return domain.GrantDelegation{}, aerr
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	return marshalGD(created)
}
