// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package sa_keys — SAKeyService use-cases (Class A static SA-keys via
// Hydra OAuth2 client_credentials + private_key_jwt).
//
// On Issue (private_key_jwt mode):
//
//  1. Generate an ECDSA P-256 keypair locally; the private half NEVER
//     leaves kacho-iam's response and is NEVER stored in DB.
//  2. Register an OAuth2 client with Hydra Admin with
//     `token_endpoint_auth_method=private_key_jwt`,
//     `grant_types=[client_credentials]`, `jwks={keys:[<public JWK>]}`,
//     `owner=<sva_id>`. Hydra returns NO `client_secret` — none exists.
//  3. Persist `service_account_oauth_clients` row (hydra_client_id mapping
//     + public PEM + algorithm).
//  4. Return IssueSAKeyResponse with the plaintext PRIVATE PEM + kid
//     in `Operation.response` (one-shot delivery; redacted post-completion
//     by OpsResponseRedactor so re-polling Operation.Get yields no secret).
//
// On Revoke:
//
//  1. Fetch row by id, scoped by sva_id (Authorization Cross-Tenant check).
//  2. Delete row + DELETE Hydra OAuth2 client (idempotent — Hydra 404 is OK).
//
// On List: paged read of own SA's clients (no Hydra round-trip).
package sa_keys

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ───────────────── Port interfaces ─────────────────

// SAClientRepo abstracts the SA-OAuth-clients repo. Tx-scoped writes take the
// opaque service.Tx handle (the concrete pgx.Tx is recovered inside the pg
// adapter via txAsPgx) so this use-case package stays free of the pgx driver.
type SAClientRepo interface {
	Get(ctx context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error)
	Insert(ctx context.Context, tx service.Tx, c domain.ServiceAccountOAuthClient) (domain.ServiceAccountOAuthClient, error)
	DeleteByID(ctx context.Context, tx service.Tx, id domain.SAOAuthClientID) error
	List(ctx context.Context, svaID domain.ServiceAccountID, pageToken string, pageSize int32) ([]domain.ServiceAccountOAuthClient, string, error)
	// AccountForServiceAccount resolves the owning account of a ServiceAccount so
	// Issue/Revoke can stamp `account_id` on the Operation metadata (account-scoped
	// /iam/operations feed). Missing SA → ErrNotFound.
	AccountForServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.AccountID, error)
}

// OAuthClientAdmin abstracts hydra-admin operations needed by Issue/Revoke.
type OAuthClientAdmin interface {
	CreateOAuthClient(ctx context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error
}

// TrustGrantAdmin abstracts the Hydra jwt-bearer trust-grant registration used by
// the federated Issue path. Each trusted subject is registered as an EXACT-subject
// grant (allow_any_subject=false) so Hydra accepts an external assertion only when
// its `sub` matches the granted subject verbatim.
type TrustGrantAdmin interface {
	CreateJWTBearerTrustGrant(ctx context.Context, g clients.JWTBearerTrustGrant) error
}

// OpsResponseRedactor clears a named field in the proto-marshalled success
// response of an `operations` row. Idempotent: re-running on an
// already-cleared field is a no-op. The concrete pg adapter reads the
// Any-wrapped response from the BYTEA `response_data` column, clears the field
// reflectively, and writes the re-marshalled bytes back (single-statement
// UPDATE) — there is no JSONB `response` column to jsonb_set.
type OpsResponseRedactor interface {
	RedactResponseField(ctx context.Context, opID string, fieldPath []string) error
}

// ───────────────── Issue use-case ─────────────────

// IssueSAKeyUseCase mints a new Hydra OAuth2 client + persists the mapping.
type IssueSAKeyUseCase struct {
	repo    SAClientRepo
	tx      service.TxBeginner
	hydra   OAuthClientAdmin
	opsRepo operations.Repo
	// trustGrants registers exact-subject jwt-bearer trust-grants for the
	// federated path. Nil → skipped (test / private_key_jwt-only wiring); the
	// composition root wires it so a federated key's `(issuer, subject)` binding
	// actually lands in Hydra.
	trustGrants TrustGrantAdmin
	// Redactor for post-MarkDone client_secret redaction. Nil → redaction
	// skipped (test / legacy wiring). Production main.go wires the pg
	// adapter so the secret is replaced with `"<redacted>"` after the
	// caller's first poll of Operation.Get.
	redactor OpsResponseRedactor
	// audit — durable audit_outbox emitter. nil → no audit row
	// (purely-additive; mutation contract unchanged). See WithAuditEmitter.
	audit auditEmitter
	now   func() time.Time
	// graceTimer — injectable grace-window timer (defaults to time.After).
	// Tests substitute a channel they control so the grace expiry is driven
	// deterministically instead of racing wall-clock; production leaves it nil.
	graceTimer func(time.Duration) <-chan time.Time
	// logger — surfaces failures of the detached secret-redaction goroutine
	// (redaction error / give-up / recovered panic), so a key that stays
	// un-redacted in the operation response is detectable. nil → no logging.
	logger *slog.Logger
	// redactGrace — задержка между тем как Operation стал Done, и затиранием
	// одноразового private_key_pem. Даёт поллящему клиенту (docker/CI/UI) окно,
	// чтобы прочитать и сохранить ключ до его вычистки. 0 → без окна (тест/legacy).
	redactGrace time.Duration

	// HydraClientNamePrefix — used to compose the Hydra `client_name`
	// (default "kacho-sak-<svaID>"). Configurable via env at wire-time.
	HydraClientNamePrefix string
	// DefaultScope — scope granted to issued keys (default empty).
	DefaultScope string
	// AudiencePrefix — appended with `/<svaID>` as Hydra audience.
	AudiencePrefix string
	// RegistryAudience — the configured registry service audience (the same
	// value the `/iam/token` Docker-Registry shim requests from Hydra during the
	// client_credentials exchange, sourced from
	// `api-server.registry-token.service`). ALWAYS whitelisted on every issued
	// SA-key's Hydra client so a docker/registry key works out of the box —
	// without it Hydra rejects the exchange with "Requested audience … has not
	// been whitelisted by the OAuth 2.0 Client" (#320). Empty → not added
	// (test / registry-disabled wiring). Set in the composition root.
	RegistryAudience string
}

// WithResponseRedactor wires the post-Issue secret redactor.
func (u *IssueSAKeyUseCase) WithResponseRedactor(r OpsResponseRedactor) *IssueSAKeyUseCase {
	u.redactor = r
	return u
}

// WithAuditEmitter wires the durable audit_outbox emitter.
// Composition-root only. nil emitter → audit emit is skipped.
func (u *IssueSAKeyUseCase) WithAuditEmitter(a auditEmitter) *IssueSAKeyUseCase {
	u.audit = a
	return u
}

// WithTrustGrantAdmin wires the Hydra jwt-bearer trust-grant registrar used by the
// federated Issue path. Composition-root only. nil → federated Issue skips
// trust-grant registration.
func (u *IssueSAKeyUseCase) WithTrustGrantAdmin(t TrustGrantAdmin) *IssueSAKeyUseCase {
	u.trustGrants = t
	return u
}

// WithLogger wires the logger used by the detached secret-redaction goroutine to
// surface redaction failures (the only place a key can stay un-redacted).
func (u *IssueSAKeyUseCase) WithLogger(l *slog.Logger) *IssueSAKeyUseCase {
	u.logger = l
	return u
}

// WithRedactGrace задаёт grace-окно между Done-ом Operation и затиранием
// одноразового private_key_pem. Composition-root передаёт значение из конфига
// (KACHO_IAM_SAKEY_REDACT_GRACE, дефолт 120s); нулевое или отрицательное значение
// трактуется как «без окна» (немедленное затирание — тест/legacy).
func (u *IssueSAKeyUseCase) WithRedactGrace(d time.Duration) *IssueSAKeyUseCase {
	u.redactGrace = d
	return u
}

// NewIssueSAKeyUseCase constructs.
func NewIssueSAKeyUseCase(r SAClientRepo, tx service.TxBeginner, h OAuthClientAdmin, ops operations.Repo) *IssueSAKeyUseCase {
	return &IssueSAKeyUseCase{
		repo:                  r,
		tx:                    tx,
		hydra:                 h,
		opsRepo:               ops,
		now:                   time.Now,
		HydraClientNamePrefix: "kacho-sak-",
	}
}

// IssueInput — sanitized.
type IssueInput struct {
	ServiceAccountID domain.ServiceAccountID
	Description      string
	TTLSeconds       int64
	CreatedByUserID  string

	// Name — человекочитаемое имя ключа (create-only, immutable). Пусто → "".
	Name string
	// Labels — произвольные метки ключа (create-only, immutable). Пусто → {}.
	Labels domain.Labels

	// TrustedSubjects — Federation IN. When non-empty, the use-case
	// switches to FEDERATED mode: no keypair is generated, the Hydra OAuth2
	// client is registered with `grant_types=[urn:ietf:params:oauth:grant-
	// type:jwt-bearer]` + `token_endpoint_auth_method=none` (no JWKS), and
	// the response omits `private_key_pem` / `public_key_pem`. External
	// workloads sign their own assertions through the IdP that emitted one
	// of the listed `(issuer, subject_pattern)` tuples; Hydra accepts the
	// assertion if and only if the issuer is in the global trusted-issuers
	// list (helm umbrella `hydra.config.oauth2.grant.jwt` + admin
	// trust-grants) and the (iss, sub) matches an entry below. Empty slice
	// = private_key_jwt mode.
	TrustedSubjects []domain.TrustedSubject

	// Audience — Federation OUT. When non-empty, the Hydra OAuth2
	// client is registered with this exact `audience` list (replacing the
	// default kacho-internal `AudiencePrefix`-built audience), so every
	// access_token minted for this client lands the values in its `aud`
	// claim. Required for OIDC-trust-federation with external IdPs — the
	// `audience` value must match exactly what the remote IdP expects (its
	// token-exchange endpoint or resource URI).
	// Order preserved; empty entries dropped; duplicates collapsed.
	// Empty slice = legacy kacho-internal-only audience.
	Audience []string
}

// Execute returns a started Operation.
func (u *IssueSAKeyUseCase) Execute(ctx context.Context, in IssueInput) (*operations.Operation, error) {
	if in.ServiceAccountID == "" {
		return nil, status.Error(codes.InvalidArgument, "service_account_id required")
	}
	if !strings.HasPrefix(string(in.ServiceAccountID), domain.PrefixServiceAccount) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service account id '%s'", in.ServiceAccountID)
	}
	if in.CreatedByUserID == "" {
		return nil, status.Error(codes.InvalidArgument, "created_by_user_id required")
	}
	if in.TTLSeconds < 0 {
		return nil, status.Error(codes.InvalidArgument, "ttl_seconds must be >= 0")
	}
	if len(in.Description) > 256 {
		return nil, status.Error(codes.InvalidArgument, "description too long (max 256)")
	}
	for i, ts := range in.TrustedSubjects {
		if err := ts.Validate(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "trusted_subjects[%d]: %v", i, err)
		}
	}
	if err := domain.OAuthClientName(in.Name).Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := in.Labels.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Resolve the owning account so the Operation metadata carries account_id —
	// the account-scoped /iam/operations feed otherwise excludes token operations.
	accountID, err := u.repo.AccountForServiceAccount(ctx, in.ServiceAccountID)
	if err != nil {
		return nil, mapPGErr(err)
	}

	keyID := domain.SAOAuthClientID(ids.NewID(domain.PrefixSAOAuthClient))
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Issue SA key for %s", in.ServiceAccountID),
		&iamv1.IssueSAKeyMetadata{
			ServiceAccountId: string(in.ServiceAccountID),
			KeyId:            string(keyID),
			AccountId:        string(accountID),
		},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	// Capture the verified caller principal SYNCHRONOUSLY (before the worker
	// goroutine is spawned) — the audit actor must be the authenticated
	// principal (anti-spoofing, acceptance 5.2-40), never a request-body field.
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		resp, derr := u.doIssue(ctx, keyID, in, actor)
		// Schedule post-completion redact. The worker is about to invoke
		// MarkDone(opID, resp) with plaintext `client_secret` baked in;
		// after that completes, we replace the secret field in-place via a
		// single-statement UPDATE on the operations row (idempotent).
		//
		// The redact runs in a separate goroutine because the MarkDone call
		// happens INSIDE the same goroutine that runs `fn`, AFTER `fn`
		// returns — so we cannot inline the redact here. The goroutine waits
		// for done=true, holds the grace window (so the polling client can
		// retrieve the one-shot key), then performs the single UPDATE.
		// Concurrency safety: the UPDATE is single-statement atomic; idempotent
		// — re-running with the same `<redacted>` value is a no-op.
		if derr == nil && u.redactor != nil && len(in.TrustedSubjects) == 0 {
			// G118 (gosec) is suppressed intentionally: the goroutine must outlive
			// the request-scoped ctx because the gRPC client has already received
			// the Operation envelope by the time MarkDone runs; binding it to ctx
			// would race-cancel the redact UPDATE on request return. The goroutine
			// builds its own bounded context (grace + margin) inside
			// scheduleSecretRedact, derived from the worker ctx via WithoutCancel
			// so trace/request-id baggage survives the detach.
			//
			// Federated rows (TrustedSubjects non-empty) carry no key
			// material in the response — nothing to redact, skip the goroutine.
			go u.scheduleSecretRedact(ctx, op.ID) // #nosec G118 -- deliberate lifetime detach (baggage preserved via WithoutCancel; see comment above).
		}
		return resp, derr
	})
	return &op, nil
}

// redactCtxMargin — запас поверх grace-окна для ctx-таймаута redact-goroutine:
// сначала ~2s поллинга done, затем grace, затем сам UPDATE. Таймаут обязан
// пережить grace-окно, иначе ctx отменится до затирания.
const redactCtxMargin = 10 * time.Second

// scheduleSecretRedact дожидается, пока операция станет Done (worker вызывает
// MarkDone сразу после `fn`), выдерживает grace-окно, затем одним UPDATE заменяет
// `response.private_key_pem` на `"<redacted>"`. Legacy-поле `response.client_secret`
// затирается тем же образом для wire-compat, хотя новые ключи оставляют его пустым.
//
// Grace-окно (redactGrace) даёт поллящему клиенту время прочитать и сохранить
// одноразовый ключ ДО затирания — без него клиент гарантированно проигрывает гонку
// и получает "<redacted>". По истечении окна секрет всё равно вычищается из LRO.
func (u *IssueSAKeyUseCase) scheduleSecretRedact(callerCtx context.Context, opID string) {
	// recover-guard: эта goroutine детачена от запроса и переживает его, поэтому
	// неперехваченная паника (в opsRepo.Get / RedactResponseField) убила бы весь
	// IAM-процесс — а он на critical path каждого InternalIAMService.Check. Паника
	// ловится и логируется: ключ мог остаться нередактированным, но процесс жив.
	defer func() {
		if r := recover(); r != nil && u.logger != nil {
			u.logger.Error("sa-key secret redaction panicked — key material may remain in the operation response",
				slog.String("operation_id", opID), slog.Any("panic", r))
		}
	}()
	if u.redactor == nil {
		return
	}
	grace := u.redactGrace
	if grace < 0 {
		grace = 0
	}
	// Detach from the caller's cancellation (the redact must outlive the
	// request-scoped ctx — the gRPC client already holds the Operation envelope)
	// but PRESERVE its trace/request-id/slog baggage via WithoutCancel. Таймаут =
	// grace + margin, чтобы ctx не отменился до затирания (grace может быть 120s).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), grace+redactCtxMargin)
	defer cancel()

	if !u.awaitOpDone(ctx, opID) {
		return // причина уже залогирована внутри awaitOpDone
	}

	// Grace-окно перед затиранием. op.response access-controlled на владельца
	// операции, поэтому такая экспозиция приемлема — это осознанный компромисс
	// между окном poll-retrieval у клиента и временем жизни секрета в LRO.
	if grace > 0 {
		select {
		case <-u.graceAfter(grace):
		case <-ctx.Done():
			if u.logger != nil {
				u.logger.WarnContext(ctx, "sa-key secret redaction ctx expired during the grace window — key material may remain",
					slog.String("operation_id", opID))
			}
			return
		}
	}

	u.redactSecretFields(ctx, opID)
}

// graceAfter returns the grace-window timer channel — the injected graceTimer
// when set (deterministic tests), otherwise the wall-clock time.After.
func (u *IssueSAKeyUseCase) graceAfter(d time.Duration) <-chan time.Time {
	if u.graceTimer != nil {
		return u.graceTimer(d)
	}
	return time.After(d)
}

// awaitOpDone поллит операцию, пока она не станет Done. Bounded: 100 попыток по
// 20ms (~2s). Возвращает false, если операция не завершилась в бюджете (worker-
// panic / DB-down) или ctx истёк — тогда затирать нечего (ответа с секретом нет).
func (u *IssueSAKeyUseCase) awaitOpDone(ctx context.Context, opID string) bool {
	for attempt := 0; attempt < 100; attempt++ {
		op, err := u.opsRepo.Get(ctx, opID)
		if err == nil && op != nil && op.Done {
			return true
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			if u.logger != nil {
				u.logger.WarnContext(ctx, "sa-key secret redaction gave up before the operation completed — key material may remain",
					slog.String("operation_id", opID))
			}
			return false
		}
	}
	if u.logger != nil {
		u.logger.WarnContext(ctx, "sa-key secret redaction exhausted retries before the operation completed — key material may remain",
			slog.String("operation_id", opID))
	}
	return false
}

// redactSecretFields затирает одноразовый private_key_pem (и legacy client_secret
// для wire-compat) в proto-marshalled response операции одним UPDATE на строку;
// idempotent — повтор с тем же `<redacted>` no-op. Провал затирания оставляет
// plaintext ключ в operations.response_data, re-fetchable через Operation.Get —
// логируем на Error, чтобы застрявший секрет был обнаружим, никогда не глушим.
func (u *IssueSAKeyUseCase) redactSecretFields(ctx context.Context, opID string) {
	if rerr := u.redactor.RedactResponseField(ctx, opID,
		[]string{"private_key_pem"}); rerr != nil && u.logger != nil {
		u.logger.ErrorContext(ctx, "sa-key private_key_pem redaction failed — plaintext key may remain in the operation response",
			slog.String("operation_id", opID), slog.Any("err", rerr))
	}
	if rerr := u.redactor.RedactResponseField(ctx, opID,
		[]string{"client_secret"}); rerr != nil && u.logger != nil {
		u.logger.ErrorContext(ctx, "sa-key client_secret redaction failed",
			slog.String("operation_id", opID), slog.Any("err", rerr))
	}
}

// doIssue dispatches to the private_key_jwt path or the federated path
// depending on whether the caller supplied TrustedSubjects.
func (u *IssueSAKeyUseCase) doIssue(ctx context.Context, keyID domain.SAOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	if len(in.TrustedSubjects) > 0 {
		return u.doIssueFederated(ctx, keyID, in, actor)
	}
	return u.doIssuePrivateKeyJWT(ctx, keyID, in, actor)
}

// hydraUnavailable maps a failed Hydra-admin call to a fixed, opaque
// codes.Unavailable status and logs the raw cause.
//
// This runs on the async operations worker (operations.Run). That worker maps any
// UNRECOGNIZED error — anything status.FromError can't read as a gRPC status,
// including a plain fmt.Errorf even when it wraps iamerr.ErrUnavailable — to a
// generic codes.Internal "internal worker error" and logs NOTHING. So the previous
// `fmt.Errorf("%w: hydra create-client: %w", iamerr.ErrUnavailable, err)` degraded a
// peer-UNREACHABLE hydra-admin (e.g. KACHO_IAM_HYDRA_ADMIN_URL absent → issuer-derived
// public host unresolvable in-cluster) into an opaque INTERNAL with zero diagnostics.
//
// Returning an explicit UNAVAILABLE keeps the mutation fail-closed per the
// peer-unavailable convention; the raw driver/URL text is LOGGED, never returned, so
// it never leaks infra topology on the wire (hardening: INTERNAL/UNAVAILABLE opaque).
func (u *IssueSAKeyUseCase) hydraUnavailable(ctx context.Context, action string, err error) error {
	if u.logger != nil {
		u.logger.ErrorContext(ctx, "hydra admin call failed",
			slog.String("action", action), slog.Any("error", err))
	}
	return status.Error(codes.Unavailable, "hydra admin unavailable")
}

// doIssuePrivateKeyJWT — mint ECDSA P-256 keypair, register
// Hydra client with private_key_jwt + embedded JWK, persist mapping with
// PublicKeyPEM + KeyAlgorithm, return PrivateKeyPEM exactly once.
func (u *IssueSAKeyUseCase) doIssuePrivateKeyJWT(ctx context.Context, keyID domain.SAOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	// 1. Mint ECDSA P-256 keypair locally. The JWK `kid` is the kacho-iam
	//    SA-OAuth-client id (`soc_*`) so caller→Hydra assertions are
	//    self-describing.
	key, err := generateES256Key(string(keyID))
	if err != nil {
		return nil, fmt.Errorf("generate sa keypair: %w", err)
	}

	// 2. Register OAuth2 client with Hydra using private_key_jwt + the
	//    public JWK. Hydra returns NO client_secret.
	clientName := u.HydraClientNamePrefix + string(in.ServiceAccountID)
	// #nosec G101 -- "client_credentials" is the OAuth2 grant-type identifier (RFC 6749 section 4.4),
	// not a credential. Same applies to "private_key_jwt" (RFC 7521 client_assertion_type).
	hydraReq := clients.CreateOAuthClientRequest{
		ClientName:              clientName,
		Owner:                   string(in.ServiceAccountID),
		Scope:                   u.DefaultScope,
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "private_key_jwt",
		// Hydra обязан проверять client_assertion тем же alg, что несёт ключ (ES256);
		// без этого Hydra дефолтит на RS256 → invalid_client на ES256-assertion.
		TokenEndpointAuthSigningAlg: key.JWK.Alg,
		JWKS:                        &clients.JWKS{Keys: []clients.JWK{key.JWK}},
	}
	hydraReq.Audience = u.resolveAudience(in)
	hydraClient, err := u.hydra.CreateOAuthClient(ctx, hydraReq)
	if err != nil {
		return nil, u.hydraUnavailable(ctx, "create-client", err)
	}

	// 3. Persist mapping row in TX.
	row := domain.ServiceAccountOAuthClient{
		ID:              keyID,
		SvaID:           in.ServiceAccountID,
		OAuthClientID:   domain.OAuthClientID(hydraClient.ClientID),
		Description:     domain.Description(in.Description),
		CreatedByUserID: domain.UserID(in.CreatedByUserID),
		PublicKeyPEM:    key.PublicPEM,
		KeyAlgorithm:    key.Algorithm,
		Name:            domain.OAuthClientName(in.Name),
		Labels:          in.Labels,
	}
	if in.TTLSeconds > 0 {
		t := u.now().Add(time.Duration(in.TTLSeconds) * time.Second)
		row.ExpiresAt = &t
	}
	persisted, err := u.commitMapping(ctx, row, hydraClient.ClientID, actor, key.Algorithm)
	if err != nil {
		return nil, err
	}

	// 4. Build response — return PRIVATE PEM + kid ONCE. `client_secret`
	//    is kept empty (deprecated field, retained for wire-compat).
	pbKey, err := saClientToProto(persisted)
	if err != nil {
		return nil, err
	}
	resp := &iamv1.IssueSAKeyResponse{
		Key:           pbKey,
		ClientId:      hydraClient.ClientID,
		ClientSecret:  "", // private_key_jwt: no shared secret exists.
		PrivateKeyPem: key.PrivatePEM,
		PublicKeyPem:  key.PublicPEM,
		Algorithm:     key.Algorithm,
		KeyId:         string(keyID),
		// Echo resolved audience list (informational; what Hydra
		// will land in `aud` of minted tokens for this client).
		Audiences: hydraReq.Audience,
	}
	return anypb.New(resp)
}

// resolveAudience derives the Hydra `audience` whitelist for a new SA client.
//
// Audience semantics (each layer is unioned, order-preserving, deduplicated):
//   - in.Audience non-empty → its entries lead the list (empties dropped).
//     External-federation rollout requires the audience to match what the
//     external IdP expects — those caller values are preserved verbatim.
//   - in.Audience empty AND AudiencePrefix set → append the legacy
//     kacho-internal audience `<prefix>/sa/<svaID>`. Backwards-compat for
//     callers that do not specify audience. (Skipped when the caller supplied
//     an explicit audience, keeping the external-federation contract: the
//     internal default is not force-mixed into a deliberate external list.)
//   - RegistryAudience set → ALWAYS appended so a docker/registry SA-key works
//     out of the box. The `/iam/token` shim requests `audience=<registry
//     service>` during the client_credentials exchange; Hydra rejects that
//     exchange unless this client whitelists that audience (#320). Whitelisting
//     it is additive — it never changes the `aud` a token actually carries
//     (that is chosen per-exchange by the requested `audience` param).
//   - everything empty → nil (Hydra mints tokens with no `aud` claim; valid for
//     the kacho-internal API gateway which doesn't require aud).
func (u *IssueSAKeyUseCase) resolveAudience(in IssueInput) []string {
	seen := make(map[string]struct{}, len(in.Audience)+2)
	out := make([]string, 0, len(in.Audience)+2)
	add := func(a string) {
		if a == "" {
			return
		}
		if _, dup := seen[a]; dup {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}

	for _, a := range in.Audience {
		add(a)
	}
	// Fall back to the kacho-internal default only when the caller supplied no
	// (non-empty) audience — a deliberate external-federation list is not mixed
	// with the internal default.
	if len(out) == 0 && u.AudiencePrefix != "" {
		add(strings.TrimRight(u.AudiencePrefix, "/") + "/sa/" + string(in.ServiceAccountID))
	}
	// Always whitelist the configured registry service audience (#320).
	add(u.RegistryAudience)

	if len(out) == 0 {
		return nil
	}
	return out
}

// doIssueFederated — register Hydra client for RFC 7523
// jwt-bearer grant (no JWKS, no client auth), persist mapping with
// TrustedSubjects, return response WITHOUT any key material. External
// workloads will sign their own assertions through the listed external IdPs
// and present them to Hydra `/oauth2/token`.
func (u *IssueSAKeyUseCase) doIssueFederated(ctx context.Context, keyID domain.SAOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	clientName := u.HydraClientNamePrefix + string(in.ServiceAccountID)
	hydraReq := clients.CreateOAuthClientRequest{
		ClientName: clientName,
		Owner:      string(in.ServiceAccountID),
		Scope:      u.DefaultScope,
		// RFC 7521/7523 jwt-bearer grant. Hydra accepts incoming OIDC
		// assertions whose `iss` matches a globally-configured trusted
		// issuer (helm umbrella `hydra.config.oauth2.grant.jwt` + admin
		// trust-grants), then mints kacho-issued access_tokens against
		// this client_id.
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		// No client authentication — the assertion IS the credential
		// (signed by the external IdP). Hydra v26 spelling.
		TokenEndpointAuthMethod: "none",
		// Federated mode: NO JWKS — Hydra validates the assertion against
		// the external IdP's JWKS (resolved via the trusted-issuer config).
		JWKS: nil,
	}
	hydraReq.Audience = u.resolveAudience(in)
	hydraClient, err := u.hydra.CreateOAuthClient(ctx, hydraReq)
	if err != nil {
		return nil, u.hydraUnavailable(ctx, "create-client", err)
	}

	// Register an EXACT-subject jwt-bearer trust-grant per trusted subject: Hydra
	// accepts an external assertion only when its `sub` equals the granted subject
	// verbatim (allow_any_subject=false). The subject_pattern is already validated
	// literal-anchored, so LiteralSubject always resolves here. On failure roll
	// back the just-created Hydra client (external side-effect) and fail closed.
	if u.trustGrants != nil {
		if err := u.registerTrustGrants(ctx, in); err != nil {
			_ = u.hydra.DeleteOAuthClient(ctx, hydraClient.ClientID)
			return nil, err
		}
	}

	row := domain.ServiceAccountOAuthClient{
		ID:              keyID,
		SvaID:           in.ServiceAccountID,
		OAuthClientID:   domain.OAuthClientID(hydraClient.ClientID),
		Description:     domain.Description(in.Description),
		CreatedByUserID: domain.UserID(in.CreatedByUserID),
		// PublicKeyPEM + KeyAlgorithm intentionally empty — no key
		// material in kacho-iam for federated rows.
		TrustedSubjects: append([]domain.TrustedSubject(nil), in.TrustedSubjects...),
		Name:            domain.OAuthClientName(in.Name),
		Labels:          in.Labels,
	}
	if in.TTLSeconds > 0 {
		t := u.now().Add(time.Duration(in.TTLSeconds) * time.Second)
		row.ExpiresAt = &t
	}
	// Federated rows carry no kacho-held key material — key_algorithm is "".
	persisted, err := u.commitMapping(ctx, row, hydraClient.ClientID, actor, "")
	if err != nil {
		return nil, err
	}

	pbKey, err := saClientToProto(persisted)
	if err != nil {
		return nil, err
	}
	resp := &iamv1.IssueSAKeyResponse{
		Key:      pbKey,
		ClientId: hydraClient.ClientID,
		// Federated: no key material. Algorithm + KeyId are likewise empty
		// because the asserting party owns its own kid scheme.
		ClientSecret:  "",
		PrivateKeyPem: "",
		PublicKeyPem:  "",
		Algorithm:     "",
		KeyId:         string(keyID),
		// Echo resolved audience list (informational; what Hydra
		// will land in `aud` of tokens minted from federated assertions).
		Audiences: hydraReq.Audience,
	}
	return anypb.New(resp)
}

// registerTrustGrants registers one EXACT-subject jwt-bearer trust-grant per
// trusted subject. allow_any_subject is always false — trusting an issuer must not
// mean trusting an arbitrary subject from it. On the first failure the caller
// rolls back the Hydra client and fails closed.
func (u *IssueSAKeyUseCase) registerTrustGrants(ctx context.Context, in IssueInput) error {
	expiresAt := u.trustGrantExpiry(in)
	scope := strings.Fields(u.DefaultScope)
	for i, ts := range in.TrustedSubjects {
		subject, ok := ts.LiteralSubject()
		if !ok {
			// Defensive: Validate() already rejects non-literal patterns.
			return status.Errorf(codes.InvalidArgument,
				"trusted_subjects[%d].subject_pattern must be a literal anchored subject", i)
		}
		grant := clients.JWTBearerTrustGrant{
			Issuer:          ts.Issuer,
			Subject:         subject,
			AllowAnySubject: false,
			Scope:           scope,
			ExpiresAt:       expiresAt,
		}
		if err := u.trustGrants.CreateJWTBearerTrustGrant(ctx, grant); err != nil {
			return u.hydraUnavailable(ctx, "create-trust-grant", err)
		}
	}
	return nil
}

// trustGrantExpiry — the trust-grant lifetime: the SA-key's expiry when set,
// otherwise a long-lived default (the federation binding lives as long as the key).
func (u *IssueSAKeyUseCase) trustGrantExpiry(in IssueInput) time.Time {
	if in.TTLSeconds > 0 {
		return u.now().Add(time.Duration(in.TTLSeconds) * time.Second)
	}
	return u.now().Add(10 * 365 * 24 * time.Hour)
}

// commitMapping persists the SA-OAuth-client mapping row in a fresh tx and
// rolls back + deletes the Hydra client on failure. Shared by both the
// private_key_jwt and federated paths.
//
// The durable iam.sa_key.issued audit_outbox row is emitted in the SAME tx as
// the Insert (atomic, запрет #10): the audit row commits iff the mapping
// commits, so a rolled-back Insert (e.g. sva_unique 23505) leaves no orphan
// compliance row. The Hydra client is created BEFORE this tx (external side-
// effect) and rolled back on failure via DeleteOAuthClient; the audit row
// records only the DB-committed fact.
func (u *IssueSAKeyUseCase) commitMapping(ctx context.Context, row domain.ServiceAccountOAuthClient, hydraClientID, actor, keyAlgorithm string) (domain.ServiceAccountOAuthClient, error) {
	// cleanupCtx — detached from the caller's cancellation (the Hydra-client
	// rollback must run even if the request ctx is cancelled) but PRESERVES the
	// caller's trace/request-id/slog baggage. Bounded so a slow Hydra
	// admin can't hang the rollback.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cleanupCancel()

	tx, err := u.tx.Begin(ctx)
	if err != nil {
		_ = u.hydra.DeleteOAuthClient(cleanupCtx, hydraClientID)
		return domain.ServiceAccountOAuthClient{}, mapPGErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
			_ = u.hydra.DeleteOAuthClient(cleanupCtx, hydraClientID)
		}
	}()
	persisted, err := u.repo.Insert(ctx, tx, row)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapPGErr(err)
	}
	// Emit the durable audit row in the SAME tx (atomic with the Insert).
	// Payload carries only non-secret identifiers (no key material — 5.2-36).
	if u.audit != nil {
		if aerr := u.audit.EmitTx(ctx, tx, service.AuditEvent{
			EventType:       auditEventSAKeyIssued,
			TenantAccountID: "",
			Payload: saKeyAuditPayload(
				actor, string(row.SvaID), string(persisted.ID), keyAlgorithm),
		}); aerr != nil {
			return domain.ServiceAccountOAuthClient{}, mapPGErr(aerr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ServiceAccountOAuthClient{}, mapPGErr(err)
	}
	committed = true
	return persisted, nil
}

// ───────────────── Revoke use-case ─────────────────

// RevokeSAKeyUseCase deletes both the kacho-iam mapping row and the Hydra
// OAuth2 client.
type RevokeSAKeyUseCase struct {
	repo    SAClientRepo
	tx      service.TxBeginner
	hydra   OAuthClientAdmin
	opsRepo operations.Repo
	// audit — durable audit_outbox emitter. nil → no audit row.
	audit auditEmitter
	// logger — surfaces the eventual-consistency Hydra orphan-cleanup warning
	// after the DB delete commits. nil → warning is skipped (degraded wiring).
	logger *slog.Logger
}

// NewRevokeSAKeyUseCase constructs.
func NewRevokeSAKeyUseCase(r SAClientRepo, tx service.TxBeginner, h OAuthClientAdmin, ops operations.Repo) *RevokeSAKeyUseCase {
	return &RevokeSAKeyUseCase{repo: r, tx: tx, hydra: h, opsRepo: ops}
}

// WithAuditEmitter wires the durable audit_outbox emitter.
// Composition-root only. nil emitter → audit emit is skipped.
func (u *RevokeSAKeyUseCase) WithAuditEmitter(a auditEmitter) *RevokeSAKeyUseCase {
	u.audit = a
	return u
}

// WithLogger wires the logger used to surface the post-commit Hydra
// orphan-cleanup warning. Composition-root only; returns the receiver.
func (u *RevokeSAKeyUseCase) WithLogger(l *slog.Logger) *RevokeSAKeyUseCase {
	u.logger = l
	return u
}

// RevokeInput — sanitized.
type RevokeInput struct {
	ServiceAccountID domain.ServiceAccountID
	KeyID            domain.SAOAuthClientID
}

// Execute returns a started Operation.
func (u *RevokeSAKeyUseCase) Execute(ctx context.Context, in RevokeInput) (*operations.Operation, error) {
	if in.ServiceAccountID == "" {
		return nil, status.Error(codes.InvalidArgument, "service_account_id required")
	}
	if in.KeyID == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id required")
	}
	// Resolve the owning account so the Operation metadata carries account_id —
	// the account-scoped /iam/operations feed otherwise excludes token operations.
	accountID, err := u.repo.AccountForServiceAccount(ctx, in.ServiceAccountID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke SA key %s", in.KeyID),
		&iamv1.RevokeSAKeyMetadata{
			ServiceAccountId: string(in.ServiceAccountID),
			KeyId:            string(in.KeyID),
			AccountId:        string(accountID),
		},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	// Capture the verified caller principal SYNCHRONOUSLY (anti-spoofing,
	// acceptance 5.2-40) — the audit actor is never a request-body field.
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doRevoke(ctx, in, actor)
	})
	return &op, nil
}

func (u *RevokeSAKeyUseCase) doRevoke(ctx context.Context, in RevokeInput, actor string) (*anypb.Any, error) {
	cur, err := u.repo.Get(ctx, in.KeyID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	// Cross-SA isolation — verify ownership before delete.
	if cur.SvaID != in.ServiceAccountID {
		return nil, status.Errorf(codes.NotFound, "ServiceAccountKey %s not found for service account %s", in.KeyID, in.ServiceAccountID)
	}
	tx, err := u.tx.Begin(ctx)
	if err != nil {
		return nil, mapPGErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := u.repo.DeleteByID(ctx, tx, in.KeyID); err != nil {
		return nil, mapPGErr(err)
	}
	// Emit the durable iam.sa_key.revoked audit row in the SAME tx as the
	// mapping delete (atomic, запрет #10): no key material in payload (5.2-36).
	if u.audit != nil {
		if aerr := u.audit.EmitTx(ctx, tx, service.AuditEvent{
			EventType:       auditEventSAKeyRevoked,
			TenantAccountID: "",
			Payload: saKeyAuditPayload(
				actor, string(cur.SvaID), string(in.KeyID), cur.KeyAlgorithm),
		}); aerr != nil {
			return nil, mapPGErr(aerr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapPGErr(err)
	}
	committed = true
	// Delete from Hydra (idempotent — 404 OK).
	if err := u.hydra.DeleteOAuthClient(ctx, string(cur.OAuthClientID)); err != nil {
		if !errors.Is(err, clients.ErrHydraClientNotFound) {
			// The DB delete already committed; this is eventual-consistency — the
			// Hydra orphan-cleanup worker sweeps the leftover client later. Emit
			// the promised structured warning (was silently swallowed via `_ =
			// err`, CWE-390) so the orphan is observable to operators and the
			// sweep has a signal; keep the RPC successful (non-fatal).
			if u.logger != nil {
				u.logger.WarnContext(ctx, "sa-key hydra oauth-client delete failed after DB commit — orphaned client left for the cleanup worker",
					slog.String("oauth_client_id", string(cur.OAuthClientID)),
					slog.String("key_id", string(in.KeyID)),
					slog.String("err", err.Error()),
				)
			}
		}
	}
	resp := &iamv1.RevokeSAKeyResponse{
		KeyId:     string(in.KeyID),
		RevokedAt: timestamppb.Now(),
	}
	return anypb.New(resp)
}

// ───────────────── List use-case ─────────────────

// ListSAKeysUseCase — sync read.
type ListSAKeysUseCase struct {
	repo SAClientRepo
}

// NewListSAKeysUseCase constructs.
func NewListSAKeysUseCase(r SAClientRepo) *ListSAKeysUseCase { return &ListSAKeysUseCase{repo: r} }

// ListInput — sanitized.
type ListInput struct {
	ServiceAccountID domain.ServiceAccountID
	PageSize         int32
	PageToken        string
}

// Execute returns paged keys.
func (u *ListSAKeysUseCase) Execute(ctx context.Context, in ListInput) ([]domain.ServiceAccountOAuthClient, string, error) {
	if in.ServiceAccountID == "" {
		return nil, "", status.Error(codes.InvalidArgument, "service_account_id required")
	}
	return u.repo.List(ctx, in.ServiceAccountID, in.PageToken, in.PageSize)
}

// ───────────────── helpers ─────────────────

// labelsFromProto converts a protobuf label map into domain.Labels. nil/empty →
// empty (non-nil) map (parity with account/project/group handlers).
func labelsFromProto(m map[string]string) domain.Labels {
	if len(m) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}

// labelsToProto converts domain.Labels into the protobuf label map. nil/empty → nil.
func labelsToProto(l domain.Labels) map[string]string {
	if len(l) == 0 {
		return nil
	}
	out := make(map[string]string, len(l))
	for k, v := range l {
		out[string(k)] = string(v)
	}
	return out
}

func saClientToProto(c domain.ServiceAccountOAuthClient) (*iamv1.ServiceAccountOAuthClient, error) {
	pb := &iamv1.ServiceAccountOAuthClient{
		Id:              string(c.ID),
		SvaId:           string(c.SvaID),
		HydraClientId:   string(c.OAuthClientID),
		Description:     string(c.Description),
		CreatedByUserId: string(c.CreatedByUserID),
		CreatedAt:       shared.TimestampProto(c.CreatedAt),
		Name:            string(c.Name),
		Labels:          labelsToProto(c.Labels),
	}
	if c.ExpiresAt != nil {
		pb.ExpiresAt = shared.TimestampProto(*c.ExpiresAt)
	}
	if c.LastUsedAt != nil {
		pb.LastUsedAt = shared.TimestampProto(*c.LastUsedAt)
	}
	return pb, nil
}

func mapPGErr(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, iamerr.StripSentinel(err))
	}
	return status.Error(codes.Internal, "internal SA key error")
}
