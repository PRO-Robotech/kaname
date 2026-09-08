// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// resourceKind — the noun used in the malformed-id message. One constant, so the
// sync format check and the not-found tone cannot drift apart.
const resourceKind = "interactive client"

// grantTypesInteractive — the ONLY shape this resource registers. A constant and
// not a request field: the resource exists precisely to produce this shape, and
// offering a choice would offer something no caller can evaluate and no code
// downstream reads.
var grantTypesInteractive = []string{"authorization_code", "refresh_token"}

// validateID — malformed own-id → sync INVALID_ARGUMENT, always the first
// statement of an RPC that takes one. Without it a malformed id reaches the
// store and returns NOT_FOUND, which asserts the absence of a resource the
// caller never named.
//
// corevalidate.ResourceID lets the EMPTY string through by contract, so the
// required-check is made here rather than assumed: an empty id would otherwise
// travel on and come back as `InteractiveClient  not found`.
func validateID(id string) error {
	if id == "" {
		return shared.InvalidArg("interactive_client_id", "interactive_client_id: required")
	}
	return corevalidate.ResourceID(resourceKind, ids.PrefixInteractiveClientHyphen, id)
}

// parseNameFilter — the whitelist is one field (`name=`), matching the platform
// filter phase. Anything else is refused BY NAME rather than ignored: a filter
// silently dropped returns a page the caller did not ask for.
func parseNameFilter(filter string) (string, error) {
	if strings.TrimSpace(filter) == "" {
		return "", nil
	}
	const p = "name="
	f := strings.TrimSpace(filter)
	if !strings.HasPrefix(f, p) {
		return "", shared.InvalidArg("filter", "Illegal argument filter")
	}
	v := strings.Trim(strings.TrimPrefix(f, p), `"'`)
	if v == "" {
		return "", shared.InvalidArg("filter", "Illegal argument filter")
	}
	return v, nil
}

// ── Get ──────────────────────────────────────────────────────────────────────

// GetUseCase — sync read of one client.
type GetUseCase struct{ repo clientRepo }

// NewGetUseCase — constructor.
func NewGetUseCase(r clientRepo) *GetUseCase { return &GetUseCase{repo: r} }

// Execute — direct-read lane: a well-formed id with no row is NOT_FOUND.
func (uc *GetUseCase) Execute(ctx context.Context, id string) (domain.InteractiveClient, error) {
	if err := validateID(id); err != nil {
		return domain.InteractiveClient{}, err
	}
	c, err := uc.repo.Get(ctx, domain.InteractiveClientID(id))
	if err != nil {
		return domain.InteractiveClient{}, shared.MapRepoErr(err)
	}
	return c, nil
}

// ── List ─────────────────────────────────────────────────────────────────────

// ListUseCase — sync cursor-paginated read.
type ListUseCase struct{ repo clientRepo }

// NewListUseCase — constructor.
func NewListUseCase(r clientRepo) *ListUseCase { return &ListUseCase{repo: r} }

// ListResult — one page plus the cursor for the next.
type ListResult struct {
	Clients       []domain.InteractiveClient
	NextPageToken string
}

// Execute — pagination format is validated FIRST, so a garbage token or an
// out-of-range page size is INVALID_ARGUMENT independently of what the caller
// holds and of what the store contains. `page_size` out of range is REJECTED,
// never clamped: silent clamping returns a different page than the one asked
// for and the caller never learns of it.
func (uc *ListUseCase) Execute(ctx context.Context, pageSize int64, pageToken, filter string) (ListResult, error) {
	if pageSize < 0 || pageSize > int64(shared.MaxListPageSize) {
		return ListResult{}, shared.InvalidArg("page_size", "Illegal argument page_size")
	}
	if err := shared.ValidatePageToken("page_token", pageToken); err != nil {
		return ListResult{}, err
	}
	size, err := corevalidate.PageSize("page_size", pageSize)
	if err != nil {
		return ListResult{}, err
	}
	name, err := parseNameFilter(filter)
	if err != nil {
		return ListResult{}, err
	}

	rows, next, err := uc.repo.List(ctx, int(size), pageToken, name)
	if err != nil {
		return ListResult{}, shared.MapRepoErr(err)
	}
	return ListResult{Clients: rows, NextPageToken: next}, nil
}

// ── Create ───────────────────────────────────────────────────────────────────

// providerCompensationEmitter — durable-приёмник компенсирующего намерения для
// клиента, уже созданного у провайдера, когда своя строка не закоммичена.
// Порт объявлен здесь, у потребителя (dependency rule); реализация и разбор,
// почему намерение обязано быть durable, — clients.ProviderCompensationOutbox.
type providerCompensationEmitter interface {
	EmitHydraClientDelete(ctx context.Context, clientID, origin, reason string) error
}

// CreateUseCase — registers the client at the identity provider, then records it.
type CreateUseCase struct {
	repo      clientRepo
	provider  providerClients
	opsRepo   operations.Repo
	audiences []string
	logger    *slog.Logger
	// compensation — durable sink for the compensating intent when the row is
	// not committed after the provider registration. nil → direct best-effort
	// deregistration only (see clients.ProviderCompensationOutbox).
	compensation providerCompensationEmitter
}

// WithCompensationEmitter wires the durable sink for compensating intents.
// Composition-root only.
func (uc *CreateUseCase) WithCompensationEmitter(c providerCompensationEmitter) *CreateUseCase {
	uc.compensation = c
	return uc
}

// compensationOriginInteractiveClient — saga attribution in the intent.
const compensationOriginInteractiveClient = "interactive_client"

// providerReleaseTimeout — upper bound on the release (recording the intent OR
// the direct call). Detached from the caller's cancellation: the release must
// run even when the request is already gone.
const providerReleaseTimeout = 5 * time.Second

// releaseProviderClient removes a registration made before the row was
// committed. The DURABLE intent is the primary path — it survives both a dead
// process and a failing release call; the direct deregistration stays as the
// FALLBACK for when the intent cannot be recorded. Both are idempotent.
func (uc *CreateUseCase) releaseProviderClient(ctx context.Context, clientID, reason string) {
	if clientID == "" {
		return
	}
	relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerReleaseTimeout)
	defer cancel()

	if uc.compensation != nil {
		if err := uc.compensation.EmitHydraClientDelete(
			relCtx, clientID, compensationOriginInteractiveClient, reason,
		); err == nil {
			return
		} else if uc.logger != nil {
			uc.logger.ErrorContext(relCtx,
				"interactive client: durable compensation intent could not be recorded, falling back to a direct release",
				"provider_client_id", clientID, "reason", reason, "err", err.Error())
		}
	}
	if err := uc.provider.Deregister(relCtx, clientID); err != nil && uc.logger != nil {
		// Neither an intent nor a release: the registration stays at the
		// provider, and this line is the only handle left to remove it by hand.
		uc.logger.ErrorContext(relCtx,
			"interactive client: provider registration left behind after a failed insert",
			"provider_client_id", clientID, "reason", reason, "err", err.Error())
	}
}

// NewCreateUseCase — constructor. `audiences` comes from iam's own configuration
// (Р2): the caller never supplies it and it is echoed output-only.
func NewCreateUseCase(r clientRepo, p providerClients, ops operations.Repo, audiences []string, logger *slog.Logger) *CreateUseCase {
	return &CreateUseCase{repo: r, provider: p, opsRepo: ops, audiences: audiences, logger: logger}
}

// Execute — validate → persist Operation → register at provider → insert row.
//
// WHY THE PROVIDER IS CONTACTED BEFORE THE ROW IS WRITTEN, AND WHAT PAYS FOR IT.
// The row must carry the provider's client id, so registration comes first. If
// the insert then fails — most often because the name is taken — the client that
// was just registered is deregistered again. Without that compensation an orphan
// would remain at the provider that the platform has no record of and no way to
// name: nothing would ever remove it, and it would keep accepting ceremonies.
//
// The Operation row is persisted BEFORE either side effect, so the id the caller
// receives is always pollable; a failure is recorded on it as a terminal error
// rather than leaving the caller polling a row that does not exist.
func (uc *CreateUseCase) Execute(ctx context.Context, req *iamv1.CreateInteractiveClientRequest) (*operationpb.Operation, error) {
	id := ids.NewHyphenID(ids.PrefixInteractiveClientHyphen)
	c := domain.InteractiveClient{
		ID: domain.InteractiveClientID(id),
		// Пустое имя — законный вход создания и означает «назови сам»: до
		// записи его заменяет имя, производное от идентификатора (#1279). Имя
		// клиента уникально на ВЕСЬ кластер, поэтому умолчание обязано быть
		// производным именно от идентификатора — он глобально уникален by
		// construction, и два безымянных создания не столкнутся БЕЗ
		// проверки-перед-вставкой (запрет #10).
		Name:                   domain.InteractiveClientName(corevalidate.NameOrDefault(req.GetName(), id)),
		Description:            domain.Description(req.GetDescription()),
		Labels:                 labelsFromProto(req.GetLabels()),
		RedirectURIs:           req.GetRedirectUris(),
		PostLogoutRedirectURIs: req.GetPostLogoutRedirectUris(),
		Status:                 domain.InteractiveClientActive,
	}
	// Validation runs against the same entity that will be stored, so the rule
	// the caller is judged by and the rule the row satisfies are one rule.
	if err := c.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create interactive client %s", c.Name),
		&iamv1.CreateInteractiveClientMetadata{InteractiveClientId: string(c.ID)},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	fail := func(err error) (*operationpb.Operation, error) {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}

	pc, err := uc.provider.Register(ctx, ProviderClientSpec{
		Name:                   string(c.Name),
		RedirectURIs:           c.RedirectURIs,
		PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		Audiences:              uc.audiences,
		GrantTypes:             grantTypesInteractive,
	})
	if err != nil {
		return fail(err)
	}
	c.ClientID = pc.ClientID
	c.GrantTypes = pc.GrantTypes
	c.TokenEndpointAuthMethod = pc.TokenEndpointAuthMethod
	c.Audiences = pc.Audiences

	created, err := uc.repo.Insert(ctx, c)
	if err != nil {
		// Compensate the half-done registration. The compensating intent cannot
		// ride the insert's transaction — that transaction is precisely the one
		// that failed — so it is committed on its own and delivered
		// at-least-once, which is what makes it survive both a dead process and
		// a provider that is itself the thing failing.
		uc.releaseProviderClient(ctx, pc.ClientID, "client row was not inserted")
		return fail(err)
	}

	resp, merr := operationResponse(created)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDone(ctx, op.ID, resp); err != nil && uc.logger != nil {
		uc.logger.ErrorContext(ctx, "interactive client Create: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done, op.Response = true, resp
	return shared.OperationToProto(&op), nil
}

// ── Update ───────────────────────────────────────────────────────────────────

// UpdateUseCase — applies the mutable fields.
type UpdateUseCase struct {
	repo    clientRepo
	opsRepo operations.Repo
	logger  *slog.Logger
}

// NewUpdateUseCase — constructor.
func NewUpdateUseCase(r clientRepo, ops operations.Repo, logger *slog.Logger) *UpdateUseCase {
	return &UpdateUseCase{repo: r, opsRepo: ops, logger: logger}
}

// mutableFields — the known-set the update mask is checked against.
var mutableFields = []string{"name", "description", "labels", "redirect_uris", "post_logout_redirect_uris"}

// immutableFields — named separately so a mask naming one of them is refused BY
// NAME. They must be checked BEFORE the known-set check: the known-set does not
// contain them, so the generic "unknown field" answer would fire first and the
// caller would never learn that the field exists and simply cannot be changed.
var immutableFields = []string{"id", "created_at", "client_id", "audiences", "grant_types", "token_endpoint_auth_method", "status"}

// Execute — mask discipline, then the write.
func (uc *UpdateUseCase) Execute(ctx context.Context, req *iamv1.UpdateInteractiveClientRequest) (*operationpb.Operation, error) {
	id := req.GetInteractiveClientId()
	if err := validateID(id); err != nil {
		return nil, err
	}

	paths := req.GetUpdateMask().GetPaths()
	// Immutable first — see the comment on immutableFields.
	for _, p := range paths {
		for _, im := range immutableFields {
			if normalizeFieldPath(p) == im {
				return nil, shared.InvalidArg("update_mask",
					fmt.Sprintf("%s is immutable after InteractiveClient.Create", im))
			}
		}
	}
	known := make(map[string]struct{}, len(mutableFields)*2)
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

	cur, err := uc.repo.Get(ctx, domain.InteractiveClientID(id))
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// Empty mask → full-object PATCH over the mutable fields; immutable values
	// present in the body are silently ignored (api-conventions).
	set := make(map[string]bool, len(paths))
	for _, p := range paths {
		set[normalizeFieldPath(p)] = true
	}
	all := len(paths) == 0
	if all || set["name"] {
		cur.Name = domain.InteractiveClientName(req.GetName())
	}
	if all || set["description"] {
		cur.Description = domain.Description(req.GetDescription())
	}
	if all || set["labels"] {
		cur.Labels = labelsFromProto(req.GetLabels())
	}
	if all || set["redirect_uris"] {
		cur.RedirectURIs = req.GetRedirectUris()
	}
	if all || set["post_logout_redirect_uris"] {
		cur.PostLogoutRedirectURIs = req.GetPostLogoutRedirectUris()
	}
	// The updated entity is validated by the SAME rules as on Create — a mutable
	// field must not be reachable through Update in a shape Create would refuse.
	if err := cur.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update interactive client %s", id),
		&iamv1.UpdateInteractiveClientMetadata{InteractiveClientId: id},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	updated, err := uc.repo.Update(ctx, cur)
	if err != nil {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}

	resp, merr := operationResponse(updated)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDone(ctx, op.ID, resp); err != nil && uc.logger != nil {
		uc.logger.ErrorContext(ctx, "interactive client Update: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done, op.Response = true, resp
	return shared.OperationToProto(&op), nil
}

// ── Delete ───────────────────────────────────────────────────────────────────

// DeleteUseCase — removes the client at the provider and its row.
type DeleteUseCase struct {
	repo     clientRepo
	provider providerClients
	opsRepo  operations.Repo
	logger   *slog.Logger
}

// NewDeleteUseCase — constructor.
func NewDeleteUseCase(r clientRepo, p providerClients, ops operations.Repo, logger *slog.Logger) *DeleteUseCase {
	return &DeleteUseCase{repo: r, provider: p, opsRepo: ops, logger: logger}
}

// Execute — idempotent by construction.
//
// Deleting an already-absent client succeeds and reports the same code as the
// first delete: the caller asked for the client to be gone, and it is. The row
// is removed first and the provider-side deregistration follows only when a row
// was actually taken — otherwise a repeated Delete would keep asking the
// provider to remove something already removed.
func (uc *DeleteUseCase) Execute(ctx context.Context, id string) (*operationpb.Operation, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete interactive client %s", id),
		&iamv1.DeleteInteractiveClientMetadata{InteractiveClientId: id},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	removed, existed, err := uc.repo.Delete(ctx, domain.InteractiveClientID(id))
	if err != nil {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}
	if existed && removed.ClientID != "" {
		if derr := uc.provider.Deregister(ctx, removed.ClientID); derr != nil {
			// The row is already gone, so the platform can no longer name this
			// provider client. Loud, never swallowed — this is the one line that
			// makes a leftover registration findable.
			if uc.logger != nil {
				uc.logger.ErrorContext(ctx,
					"interactive client: row removed but provider deregistration failed",
					"provider_client_id", removed.ClientID, "err", derr.Error())
			}
			gerr := shared.MapRepoErr(derr)
			_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
			return nil, gerr
		}
	}
	// The response echoes the removed resource when there was one; on the
	// idempotent repeat it echoes the id alone, because there is nothing left to
	// describe and inventing a body would be describing a row that does not exist.
	removed.ID = domain.InteractiveClientID(id)
	resp, merr := operationResponse(removed)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDone(ctx, op.ID, resp); err != nil && uc.logger != nil {
		uc.logger.ErrorContext(ctx, "interactive client Delete: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done, op.Response = true, resp
	return shared.OperationToProto(&op), nil
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

func labelsFromProto(in map[string]string) domain.Labels {
	if len(in) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(in))
	for k, v := range in {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}
