// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sa_keys — SAKeyService use-cases (Class A static SA-keys via
// OAuth2 client_credentials + private_key_jwt).
//
// On Issue (private_key_jwt mode):
//
//  1. Generate an ECDSA P-256 keypair locally; the private half NEVER
//     leaves kaname's response and is NEVER stored in DB.
//  2. Name the client. НА ПЕРЕВЕДЁННОМ КОНТУРЕ имя назначаем МЫ и оно совпадает
//     с идентификатором нашей строки; к прежнему издателю обращения нет вовсе
//     (задача #1120, разбор — `nameClient` ниже и
//     `docs/engineering/architecture/sa-key-issuance-leaves-the-provider.md`).
//     Пока контур не переведён — регистрируется OAuth2-клиент у прежнего
//     издателя с `token_endpoint_auth_method=private_key_jwt`,
//     `grant_types=[client_credentials]`, `jwks={keys:[<public JWK>]}`,
//     `owner=<sva_id>`; `client_secret` не возвращается — его не существует.
//  3. Persist `service_account_oauth_clients` row (`hydra_client_id` carries the
//     name the client answers to — ours or the previous issuer's, see step 2 —
//     + public PEM + algorithm).
//  4. Return IssueSAKeyResponse with the plaintext PRIVATE PEM + kid
//     in `Operation.response` (one-shot delivery; redacted post-completion
//     by OpsResponseRedactor so re-polling Operation.Get yields no secret).
//
// On Revoke:
//
//  1. Fetch row by id, scoped by sva_id (Authorization Cross-Tenant check).
//  2. Delete row + DELETE the provider's OAuth2 client (idempotent — 404 is OK).
//     Обращение остаётся безусловным намеренно: строки, заведённые ДО перевода
//     контура, своё зеркало сохраняют и снимать его надо, а отказ этого вызова
//     и без того не мешает отзыву состояться.
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// ───────────────── Port interfaces ─────────────────

// SAClientRepo abstracts the SA-OAuth-clients repo. Tx-scoped writes take the
// opaque service.Tx handle (the concrete pgx.Tx is recovered inside the pg
// adapter via txAsPgx) so this use-case package stays free of the pgx driver.
type SAClientRepo interface {
	Insert(ctx context.Context, tx service.Tx, c domain.ServiceAccountOAuthClient) (domain.ServiceAccountOAuthClient, error)
	// DeleteOwnedByID removes the credential row with ONE statement narrowed by
	// its owning service account, and returns the row it removed. found=false is
	// a legal outcome: the row is absent OR it belongs to another owner, and the
	// two are indistinguishable from here by construction (see doRevoke).
	DeleteOwnedByID(ctx context.Context, tx service.Tx, ownerID domain.ServiceAccountID, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, bool, error)
	List(ctx context.Context, svaID domain.ServiceAccountID, pageToken string, pageSize int32) ([]domain.ServiceAccountOAuthClient, string, error)
	// AccountForServiceAccount resolves the owning account of a ServiceAccount so
	// Issue/Revoke can stamp `account_id` on the Operation metadata (account-scoped
	// /iam/operations feed). Missing SA → ErrNotFound.
	// The second return states whether that account may authenticate. It is
	// part of this signature rather than a separate lookup so no caller can
	// decide on a field the query was never asked to load.
	AccountForServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.AccountID, bool, error)
	// OwnerUserForServiceAccount resolves the account owner (a users(id)) of a
	// ServiceAccount. Used to stamp a VALID `created_by` when the caller is a
	// machine (service-account) principal that is not itself a users row — the
	// #60 analog for SA-keys (see Execute). Deterministic (never caller-chosen),
	// so it opens no created_by-spoofing surface. Missing SA → ErrNotFound.
	OwnerUserForServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.UserID, error)
}

// OAuthClientAdmin abstracts hydra-admin operations needed by Issue/Revoke.
type OAuthClientAdmin interface {
	CreateOAuthClient(ctx context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error
}

// TrustedIssuerWriter — запись НАШЕГО перечня доверенных издателей (#1124).
//
// # Почему запись идёт в транзакции вызывающего, а не своим обращением
//
// Прежде доверие выдавалось ВЕЕРОМ обращений к поставщику: понятия «группа» у
// него нет, отката веера — тоже, отказ на k-м оставлял k-1 выданными, и снять
// их можно было только по присвоенным им идентификаторам. Отсюда была вся
// оснастка компенсации: возвращаемые идентификаторы, обратный порядок снятия,
// durable-намерение на случай смерти процесса.
//
// Перечень стал нашей таблицей — и веер исчез вместе со своим предметом. Строка
// ключа и её перечень пишутся ОДНОЙ транзакцией: полусделанного состояния между
// ними не существует, компенсировать нечего.
type TrustedIssuerWriter interface {
	InsertTrustedIssuers(
		ctx context.Context,
		tx service.Tx,
		clientID domain.SAOAuthClientID,
		subjects []domain.TrustedSubject,
		expiresAt *time.Time,
	) error
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

// providerCompensationEmitter — durable-приёмник компенсирующего намерения для
// клиента, уже созданного у провайдера, когда своя строка не закоммичена.
// Порт объявлен здесь, у потребителя (dependency rule); реализация и разбор,
// почему намерение обязано быть durable, — clients.ProviderCompensationOutbox.
type providerCompensationEmitter interface {
	EmitHydraClientDelete(ctx context.Context, clientID, origin, reason string) error
}

// IssueSAKeyUseCase mints a new Hydra OAuth2 client + persists the mapping.
type IssueSAKeyUseCase struct {
	repo    SAClientRepo
	tx      service.TxBeginner
	hydra   OAuthClientAdmin
	opsRepo operations.Repo
	// trustedIssuers — писатель нашего перечня доверенных издателей. Nil на
	// федеративной выдаче — ОТКАЗ, а не «пропустить»: ключ, чей перечень не
	// записан, не примет никого, и выдача ответила бы успехом на невыполнимое.
	trustedIssuers TrustedIssuerWriter
	// ownIssuance — контур переведён на свою чеканку (задача #1120).
	ownIssuance bool
	// Redactor for post-MarkDone client_secret redaction. Nil → redaction
	// skipped (test / legacy wiring). Production main.go wires the pg
	// adapter so the secret is CLEARED (the field is reset to empty — there is no
	// placeholder) after the
	// caller's first poll of Operation.Get.
	redactor OpsResponseRedactor
	// audit — durable audit_outbox emitter. nil → no audit row
	// (purely-additive; mutation contract unchanged). See WithAuditEmitter.
	audit auditEmitter
	// compensation — durable-приёмник компенсирующих намерений для клиента,
	// зарегистрированного у провайдера до того, как своя строка закоммичена.
	// nil → компенсация деградирует в прямой (best-effort) вызов снятия.
	compensation providerCompensationEmitter
	now          func() time.Time
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
	// MaxTTL — inclusive ceiling on `ttl_seconds`. A request above it is
	// refused with InvalidArgument before any Hydra client is registered.
	// Zero → no ceiling (degraded/legacy wiring); the composition root sets it
	// from config so the machine credential cannot outlive policy.
	MaxTTL time.Duration
	// DefaultTTL — lifetime applied when the caller omits `ttl_seconds`.
	// Zero → the legacy non-expiring behaviour is kept (so an un-migrated
	// deployment is unchanged until the knob is wired). A non-zero value is
	// what turns "0 means never expires" into "0 means the policy default".
	DefaultTTL time.Duration
	// BindDPoP — register the key's OAuth2 client so the provider mints
	// SENDER-CONSTRAINED access tokens (RFC 9449 `cnf.jkt`) instead of plain
	// bearers. Binding is per-client registration metadata, so it must be
	// requested at issue time; a key registered before this was enabled keeps
	// minting unbound tokens until it is rotated.
	//
	// Default false. This is the issuance half of the control whose enforcement
	// half lives at the edge (api-gateway
	// KACHO_API_GATEWAY_AUTHN_REQUIRE_MACHINE_TOKEN_BINDING) — enforcement
	// without issuance can only reject, so issuance is enabled first.
	BindDPoP bool
	// AccessTokenLifespan — per-client `access_token_lifespan` stamped on the
	// Hydra OAuth2 client registered for this key, so tokens minted from a
	// machine credential do not silently inherit the provider-global default.
	// Zero → field omitted (provider default applies).
	AccessTokenLifespan time.Duration
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

// WithTrustedIssuerWriter провязывает писателя нашего перечня доверенных
// издателей. Composition-root only.
func (u *IssueSAKeyUseCase) WithTrustedIssuerWriter(w TrustedIssuerWriter) *IssueSAKeyUseCase {
	u.trustedIssuers = w
	return u
}

// WithOwnIssuance объявляет контур выдачи ПЕРЕВЕДЁННЫМ на свою чеканку
// (задача #1120).
//
// Composition-root only: «переведён ли контур» — свойство ПОСАДКИ, а не запроса,
// и вызывающий его не выбирает.
func (u *IssueSAKeyUseCase) WithOwnIssuance() *IssueSAKeyUseCase {
	u.ownIssuance = true
	return u
}

// WithCompensationEmitter wires the durable sink for compensating intents.
// Composition-root only. nil → the half-done registration is compensated by a
// direct best-effort release only (см. clients.ProviderCompensationOutbox).
func (u *IssueSAKeyUseCase) WithCompensationEmitter(c providerCompensationEmitter) *IssueSAKeyUseCase {
	u.compensation = c
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
// (KANAME_SAKEY_REDACT_GRACE, дефолт 120s); нулевое или отрицательное значение
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

	// CallerIsServiceAccount marks that the authenticated caller is a
	// service-account principal (the acr-exempt #58 bootstrap-admin SA, or any
	// system_admin SA the gateway FGA-authorized for v_update@iam_service_account).
	// Its `sva…` principal id is NOT a users(id) row, so recording it as
	// created_by would fail the created_by FK (23503) as an opaque async code-9
	// (the SA-key half of #60). When true, Execute resolves created_by to the SA's
	// account OWNER (a valid users row, deterministic) instead of the SA id. The
	// audit actor stays the real caller (the SA) — see `actor` in Execute.
	CallerIsServiceAccount bool

	// Name — человекочитаемое имя ключа (create-only, immutable). Пусто → "".
	Name string
	// Labels — произвольные метки ключа (create-only, immutable). Пусто → {}.
	Labels domain.Labels

	// CredentialKind — вид выдаваемого удостоверения. Не назван — сохраняется
	// прежнее поведение ДОСЛОВНО: пустой перечень доверенных субъектов даёт
	// KEYPAIR, непустой — FEDERATED.
	CredentialKind domain.CredentialKind

	// TrustedSubjects — Federation IN. When non-empty, the use-case
	// switches to FEDERATED mode: no keypair is generated, the Hydra OAuth2
	// client is registered with `grant_types=[urn:ietf:params:oauth:grant-
	// type:jwt-bearer]` + `token_endpoint_auth_method=none` (no JWKS), and
	// the response omits `private_key_pem` / `public_key_pem`. External
	// workloads sign their own assertions through the IdP that emitted one
	// of the listed `(issuer, subject_pattern)` tuples; наш проверяющий
	// принимает утверждение тогда и только тогда, когда пара (iss, sub) есть
	// в НАШЕМ перечне доверенных издателей и подпись сошлась с записанным там
	// ключом издателя (#1124). Empty slice = private_key_jwt mode.
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
	// Формат СВОЕГО идентификатора судит общая проверка, а не копия рядом
	// (задача #1791). Копия сверяла только префикс и потому принимала
	// обрезанный идентификатор, производя при этом ПОБАЙТОВО ТОТ ЖЕ отказ, —
	// расхождение было невидимо всякой пробе, сверяющей сообщение.
	if err := shared.ValidateResourceID(string(in.ServiceAccountID), domain.PrefixServiceAccount, "service account"); err != nil {
		return nil, err
	}
	if in.CreatedByUserID == "" {
		return nil, status.Error(codes.InvalidArgument, "created_by_user_id required")
	}
	if in.TTLSeconds < 0 {
		return nil, status.Error(codes.InvalidArgument, "ttl_seconds must be >= 0")
	}
	// Вид разрешается СИНХРОННО, до любой записи. У служебной учётки
	// федеративный вид достижим — поле, которым он задаётся, у неё есть.
	kind, kerr := domain.ResolveIssuedKind(in.CredentialKind, len(in.TrustedSubjects) > 0, true)
	if kerr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", kerr)
	}
	var secretTTL time.Duration
	if kind == domain.CredentialKindSecret {
		// Поля, осмысленные не для этого вида, отвергаются ЯВНО и с именем
		// поля: молча принять и выбросить запрещено — вызывающий получил бы
		// успех и был бы уверен, что его параметр применён.
		if len(in.Audience) > 0 {
			return nil, status.Errorf(codes.InvalidArgument,
				"audience: not meaningful for credential_kind %s — its holder presents the secret itself and asks for no audience",
				domain.CredentialKindSecret)
		}
		ttl, ok := tokenpolicy.ResolveSecretCredentialTTL(time.Duration(in.TTLSeconds) * time.Second)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"ttl_seconds: exceeds the %s ceiling of %d seconds for credential_kind SECRET",
				domain.CredentialKindSecret, int64(tokenpolicy.SecretCredentialTTLCeiling.Seconds()))
		}
		secretTTL = ttl
	}
	// Ceiling. A machine credential is exempt from interactive re-authentication
	// (a machine has no second factor), which is only defensible while the
	// credential is bounded in time — so the bound is enforced here, not left to
	// the caller's discretion. Inclusive: exactly MaxTTL is allowed.
	if u.MaxTTL > 0 && time.Duration(in.TTLSeconds)*time.Second > u.MaxTTL {
		return nil, status.Errorf(codes.InvalidArgument,
			"ttl_seconds must be <= %d (%s)", int64(u.MaxTTL.Seconds()), u.MaxTTL)
	}
	if len(in.Description) > 256 {
		return nil, status.Error(codes.InvalidArgument, "description too long (max 256)")
	}
	for i, ts := range in.TrustedSubjects {
		if err := ts.Validate(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "trusted_subjects[%d]: %v", i, err)
		}
	}
	// Форма имени на пути СОЗДАНИЯ: пустая строка законна и означает «назови
	// сам» — до записи её заменит умолчание, производное от идентификатора
	// (`commitMapping`). Судить её здесь доменным типом значило бы отвергнуть
	// законный вход: тот тип судит то, что БУДЕТ ЗАПИСАНО (#1279).
	if err := corevalidate.NameOnCreate("name", in.Name); err != nil {
		return nil, err
	}
	if err := in.Labels.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Resolve the owning account so the Operation metadata carries account_id —
	// the account-scoped /iam/operations feed otherwise excludes token operations.
	accountID, mayAuthenticate, err := u.repo.AccountForServiceAccount(ctx, in.ServiceAccountID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	// An account that may not authenticate does not get a new credential either.
	// Refusing only the token would leave the key itself issued, handed over and
	// waiting: it starts working the moment the account is re-enabled, granted
	// at a time when nobody was permitted to grant it. Synchronous, because the
	// request is well-formed and the answer is known now — an Operation that
	// fails later says the same thing hours downstream and in a worse place.
	if !mayAuthenticate {
		return nil, status.Errorf(codes.FailedPrecondition,
			"ServiceAccount %s is disabled and cannot be issued a key", in.ServiceAccountID)
	}

	// #60 analog (SA-key non-interactive seed path): a service-account principal
	// caller cannot be the created_by — its `sva…` id is not a users(id) row, so
	// created_by=principal would fail the created_by FK (23503) as an opaque async
	// code-9, and there is no non-interactive path to mint an SA token (SAKeyService
	// .Issue is acr=2 → only an acr-exempt SA may call it, but that same SA could
	// not supply a valid created_by). Record created_by = the SA's account OWNER (a
	// valid users row). Deterministic — the owner is resolved from the target SA,
	// never chosen by the caller, so no created_by-spoofing surface opens. The REAL
	// actor (the SA) is still captured as the audit actor (`actor` below), so
	// accountability is preserved.
	if in.CallerIsServiceAccount {
		owner, oerr := u.repo.OwnerUserForServiceAccount(ctx, in.ServiceAccountID)
		if oerr != nil {
			return nil, mapPGErr(oerr)
		}
		in.CreatedByUserID = string(owner)
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

	// Вид SECRET завершается НА ПУТИ ЗАПРОСА: секрет показывается ОДИН РАЗ, и
	// второго чтения у него нет — строка операции его не несёт ни в какой
	// момент (§4.3.1 приёмки BAT-1).
	if kind == domain.CredentialKindSecret {
		if err := u.issueSecretSync(ctx, &op, keyID, in, actor, secretTTL); err != nil {
			return nil, err
		}
		return &op, nil
	}

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
		// — re-running on an already-cleared field writes nothing.
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
			go u.scheduleSecretRedact(ctx, op.ID) // deliberate lifetime detach (baggage preserved via WithoutCancel; see comment above).
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
// `response.private_key_pem` ОЧИЩАЕТ (поле сбрасывается в пустое). Legacy-поле `response.client_secret`
// затирается тем же образом для wire-compat, хотя новые ключи оставляют его пустым.
//
// Grace-окно (redactGrace) даёт поллящему клиенту время прочитать и сохранить
// одноразовый ключ ДО затирания — без него клиент гарантированно проигрывает гонку
// и получает пустое поле. По истечении окна секрет всё равно вычищается из LRO.
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
//
// РЕПЛИКИ: запрос — петля принадлежит ОДНОМУ запросу выдачи и ждёт исхода его же операции;
// у каждой реплики свои запросы.
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
// idempotent — повтор на уже-очищенном поле ничего не пишет. Провал затирания оставляет
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

// issueSecretSync чеканит базовый секрет служебной учётки. Зеркалит полосу
// личности: строка коммитится, тело для строки операции секрета НЕ НЕСЁТ, тело
// для вызывающего его несёт.
//
// Регистрации у внешнего поставщика этот вид не заводит и заводить не может —
// в этом и состоит предмет фазы, — поэтому колонка зеркала остаётся пустой, а
// не получает синтетического значения.
func (u *IssueSAKeyUseCase) issueSecretSync(
	ctx context.Context,
	op *operations.Operation,
	keyID domain.SAOAuthClientID,
	in IssueInput,
	actor string,
	ttl time.Duration,
) error {
	var shownAny *anypb.Any
	if err := operations.RunSync(ctx, u.opsRepo, op, func(ctx context.Context) (*anypb.Any, error) {
		secret, hash, err := credsecret.Mint(string(keyID))
		if err != nil {
			return nil, status.Error(codes.Internal, "credential minting failed")
		}
		expires := u.now().UTC().Add(ttl)
		row := domain.ServiceAccountOAuthClient{
			ID:              keyID,
			SvaID:           in.ServiceAccountID,
			Description:     domain.Description(in.Description),
			CreatedByUserID: domain.UserID(in.CreatedByUserID),
			Name:            domain.OAuthClientName(in.Name),
			Labels:          in.Labels,
			CredentialKind:  domain.CredentialKindSecret,
			SecretHash:      hash,
			ExpiresAt:       &expires,
		}
		persisted, err := u.commitMapping(ctx, row, "", actor, "")
		if err != nil {
			return nil, err
		}
		pbKey, err := saClientToProto(persisted)
		if err != nil {
			return nil, err
		}
		stored := &iamv1.IssueSAKeyResponse{
			Key:      pbKey,
			ClientId: string(keyID),
			KeyId:    string(keyID),
		}
		storedAny, err := anypb.New(stored)
		if err != nil {
			return nil, err
		}
		shown := proto.Clone(stored).(*iamv1.IssueSAKeyResponse)
		shown.Secret = secret
		shownAny2, err := anypb.New(shown)
		if err != nil {
			return nil, err
		}
		shownAny = shownAny2
		return storedAny, nil
	}); err != nil {
		return err
	}
	if shownAny != nil && op.Error == nil {
		op.Response = shownAny
	}
	return nil
}

// hydraUnavailable maps a failed Hydra-admin call to a fixed, opaque
// codes.Unavailable status and logs the raw cause.
//
// This runs on the async operations worker (operations.Run). That worker maps any
// UNRECOGNIZED error — anything status.FromError can't read as a gRPC status,
// including a plain fmt.Errorf even when it wraps iamerr.ErrUnavailable — to a
// generic codes.Internal "internal worker error" and logs NOTHING. So the previous
// `fmt.Errorf("%w: hydra create-client: %w", iamerr.ErrUnavailable, err)` degraded a
// peer-UNREACHABLE hydra-admin (e.g. KANAME_HYDRA_ADMIN_URL absent → issuer-derived
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
	// Текст НЕ называет ни поставщика, ни его административный API: арендатору
	// о них знать не полагается, а знание не даёт ему следующего шага — тот же
	// довод, которым `shared.MapRepoErr` держит фиксированный текст на признаке
	// недоступности. Подробность остаётся в цепочке и уходит в журнал.
	return status.Error(codes.Unavailable, "service unavailable")
}

// doIssuePrivateKeyJWT — mint ECDSA P-256 keypair, name the client (registering it
// with the previous issuer only while the contour is not translated — see
// nameClient), persist mapping with PublicKeyPEM + KeyAlgorithm, return
// PrivateKeyPEM exactly once.
func (u *IssueSAKeyUseCase) doIssuePrivateKeyJWT(ctx context.Context, keyID domain.SAOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	// 1. Mint ECDSA P-256 keypair locally. The JWK `kid` is the kaname
	//    SA-OAuth-client id (`soc_*`) so caller→Hydra assertions are
	//    self-describing.
	key, err := generateES256Key(string(keyID))
	if err != nil {
		return nil, fmt.Errorf("generate sa keypair: %w", err)
	}

	// 2. Собрать регистрацию клиента: private_key_jwt + публичный JWK.
	//
	//    ЗАПРОС СТРОИТСЯ ВСЕГДА, А ОТПРАВЛЯЕТСЯ НЕ ВСЕГДА. Перечень адресатов
	//    из него уезжает в ответ выдачи и на непереведённом контуре — в саму
	//    регистрацию; отправлять ли её, решает nameClient. Строить перечень
	//    внутри ветки значило бы завести ВТОРОЕ место, вычисляющее адресатов, и
	//    ответ переведённого контура разошёлся бы с ответом прежнего молча.
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
	// Pin the per-client access-token lifetime. Without it every token minted
	// from a machine credential inherits the provider-global default, which is
	// set by whatever the identity provider happens to ship with.
	hydraReq.AccessTokenLifespan = u.accessTokenLifespan()
	// Ask for sender-constrained tokens. Without this the minted token is an
	// ordinary bearer: whoever holds the bytes can replay it, and the asymmetric
	// key that authenticated the client is irrelevant to that replay.
	hydraReq.DPoPBoundAccessTokens = u.BindDPoP
	identity, err := u.nameClient(ctx, keyID, hydraReq)
	if err != nil {
		return nil, err
	}

	// 3. Persist mapping row in TX.
	row := domain.ServiceAccountOAuthClient{
		ID:              keyID,
		SvaID:           in.ServiceAccountID,
		OAuthClientID:   domain.OAuthClientID(identity.ClientID),
		Description:     domain.Description(in.Description),
		CreatedByUserID: domain.UserID(in.CreatedByUserID),
		PublicKeyPEM:    key.PublicPEM,
		KeyAlgorithm:    key.Algorithm,
		Name:            domain.OAuthClientName(in.Name),
		Labels:          in.Labels,
		// Сужение адресатов — то, что назвал ЗАКАЗЧИК, и ничего сверх (#1136).
		DeclaredAudiences: declaredAudiences(in),
		// Вид ЗАПИСЫВАЕТСЯ, а не вычисляется читателем.
		CredentialKind: domain.CredentialKindKeypair,
	}
	if exp := u.resolveExpiry(in); exp != nil {
		row.ExpiresAt = exp
	}
	persisted, err := u.commitMapping(ctx, row, identity.ProviderCoordinate, actor, key.Algorithm)
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
		ClientId:      identity.ClientID,
		ClientSecret:  "", // private_key_jwt: no shared secret exists.
		PrivateKeyPem: key.PrivatePEM,
		PublicKeyPem:  key.PublicPEM,
		Algorithm:     key.Algorithm,
		KeyId:         string(keyID),
		// Перечень адресатов ключа. На переведённом контуре это ЗАПИСАННОЕ
		// сужение, на непереведённом — перечень зеркала: см. responseAudiences.
		Audiences: u.responseAudiences(hydraReq.Audience, persisted.DeclaredAudiences),
	}
	return anypb.New(resp)
}

// responseAudiences — что ответ выдачи называет перечнем адресатов ключа.
//
// # Почему величина зависит от контура, а не одна на оба
//
// Она отвечает на вопрос «что этот ключ сможет заказать», и ответ на него на
// двух контурах даёт РАЗНАЯ величина. Пока зеркало заводится, решает его
// перечень: обмен идёт у прежнего издателя, и он сверяет с ним. На переведённом
// контуре зеркала нет — перечень зеркала не регистрируется нигде и не читается
// ничем, — а решает записанное на строке сужение (задача #1136).
//
// Отдать одно вместо другого значило бы назвать адресатов, которых ключ заказать
// не сможет, и не назвать тех, кого сможет. Поле объявлено справочным, но
// справка, которая неверна, хуже её отсутствия: по ней принимают решение.
//
// Пустой перечень на переведённом контуре — утверждение, а не умолчание:
// «сужения нет, действует перечень посадки».
func (u *IssueSAKeyUseCase) responseAudiences(mirror, declared []string) []string {
	if u.ownIssuance {
		return declared
	}
	return mirror
}

// declaredAudiences — сужение адресатов в той форме, в какой его объявляет
// контракт выдачи: порядок сохраняется, пустые элементы снимаются, повторы
// схлопываются.
//
// ЗДЕСЬ НЕТ НИ ОДНОГО ЗНАЧЕНИЯ СВЕРХ НАЗВАННЫХ ЗАКАЗЧИКОМ, и это отличает его от
// `resolveAudience`. Тот строит перечень ЗЕРКАЛА и добавляет к нему адресат
// реестра и внутреннее умолчание — величины, нужные обмену у прежнего издателя.
// Попади они в сужение, ключ получил бы доступ к адресатам, которых заказчик не
// называл: расширение вместо сужения, молча и в сторону большего.
//
// Пустой элемент снимается потому, что заказать его нельзя ничем: он не совпал
// бы ни с одним запросом и молча сузил бы ключ до недостижимого.
func declaredAudiences(in IssueInput) []string {
	if len(in.Audience) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in.Audience))
	out := make([]string, 0, len(in.Audience))
	for _, a := range in.Audience {
		if a == "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// clientNaming — идентификатор, которым выданный клиент себя называет, и
// координата его записи у прежнего издателя.
//
// ПОЧЕМУ ДВЕ ВЕЛИЧИНЫ, А НЕ ОДНА. Пока чеканил прежний издатель, они совпадали —
// он и заводил запись, и назначал имя. На переведённом контуре имя назначаем мы,
// а записи у него нет вовсе, и «нечего снимать» обязано быть выражено ОТСУТСТВИЕМ
// координаты, а не выводом «имя похоже на наше». Вывод по форме имени пережил бы
// первую же смену формата идентификатора, и пережил бы молча: компенсация
// уехала бы к постороннему с просьбой снять то, чего он не заводил.
type clientNaming struct {
	// ClientID — то, чем клиент себя называет. Он же уходит в строку реестра,
	// в ответ выдачи и в подписанное утверждение (`iss`/`sub`).
	ClientID string
	// ProviderCoordinate — координата записи у прежнего издателя. Пусто, когда
	// записи нет: снимать тогда нечего.
	ProviderCoordinate string
}

// nameClient называет клиента и, если контур не переведён, заводит его зеркало.
//
// ПЕРЕВЕДЁННЫЙ КОНТУР К ПРЕЖНЕМУ ИЗДАТЕЛЮ НЕ ХОДИТ. Клиента резолвит НАШ реестр
// утверждений, и резолвит он по нашему идентификатору — зеркальная колонка на
// том пути не участвует ни как второй ключ поиска, ни как запасной
// (`repo/kaname/pg/assertion_client_repo.go`). Значит зеркало на переведённом
// контуре — запись у постороннего, которую никто не читает, при живой
// административной дороге к нему.
//
// ГРАНИЦА НАЗВАНА: ЗЕРКАЛО СНИМАЕТСЯ ТОЛЬКО У ПЕРЕВЕДЁННОГО КОНТУРА. Пока
// подписант не подключён, прежний издатель — ЕДИНСТВЕННЫЙ производитель токена
// на этом ключе, и ключ без зеркала обменять было бы негде ни одним путём.
//
// ПОЧЕМУ НАШ ИДЕНТИФИКАТОР, А НЕ ПУСТО. У клиента ровно одно имя, и именно им он
// себя называет: докерная полоса ищет строку по имени клиента, состав утверждений
// кладёт его значением, а снятие ключа адресует им же. Пустое имя оставило бы
// каждого из этих читателей без величины — то есть сняло бы не зеркало, а
// возможность.
func (u *IssueSAKeyUseCase) nameClient(
	ctx context.Context, keyID domain.SAOAuthClientID, req clients.CreateOAuthClientRequest,
) (clientNaming, error) {
	if u.ownIssuance {
		return clientNaming{ClientID: string(keyID)}, nil
	}
	mirrored, err := u.hydra.CreateOAuthClient(ctx, req)
	if err != nil {
		return clientNaming{}, u.hydraUnavailable(ctx, "create-client", err)
	}
	return clientNaming{ClientID: mirrored.ClientID, ProviderCoordinate: mirrored.ClientID}, nil
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

// doIssueFederated — выдача федеративного ключа: ключевого материала у него нет,
// а его перечень доверенных издателей пишется НАШЕЙ таблицей в той же
// транзакции, что и строка ключа (задача #1124).
//
// # Что изменилось и почему это одно изменение, а не два
//
// Прежде здесь стояла пара обращений к поставщику: зеркало клиента и веер
// доверительных грантов. Первое было нужно затем, что внешняя нагрузка
// обменивала своё утверждение У НЕГО; второе — затем, что перечень доверенных
// издателей вёл он же. Обе причины — одна: решение о федеративном ключе
// принималось не нами.
//
// Теперь утверждение проверяет наш проверяющий (`internal/clientassertion`,
// федеративная полоса) по нашему перечню, и обе причины исчезли вместе. На
// переведённом контуре зеркало не заводится — как и на полосе ключа с ключевым
// материалом (#1120); решение принимает `nameClient`, а не эта ветка.
func (u *IssueSAKeyUseCase) doIssueFederated(ctx context.Context, keyID domain.SAOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	clientName := u.HydraClientNamePrefix + string(in.ServiceAccountID)
	hydraReq := clients.CreateOAuthClientRequest{
		ClientName: clientName,
		Owner:      string(in.ServiceAccountID),
		Scope:      u.DefaultScope,
		// Вид выдачи по RFC 7521/7523. Запрос СТРОИТСЯ всегда, а отправляется
		// не всегда: на переведённом контуре зеркала нет, и решает это
		// nameClient. Перечень адресатов уезжает из него в ответ выдачи на
		// обеих посадках, поэтому строить его внутри ветки значило бы завести
		// второе место, вычисляющее адресатов.
		GrantTypes: []string{tokenpolicy.GrantTypeJWTBearer},
		// Аутентификации клиента здесь нет: утверждение И ЕСТЬ основание
		// выдачи, а подписал его внешний издатель.
		TokenEndpointAuthMethod: "none",
		// Своего ключевого материала федеративная строка не несёт: подпись
		// проверяется ключом издателя из нашего перечня доверенных издателей.
		JWKS: nil,
	}
	hydraReq.Audience = u.resolveAudience(in)
	// Pin the per-client access-token lifetime. Without it every token minted
	// from a machine credential inherits the provider-global default, which is
	// set by whatever the identity provider happens to ship with.
	hydraReq.AccessTokenLifespan = u.accessTokenLifespan()
	// Ask for sender-constrained tokens. Without this the minted token is an
	// ordinary bearer: whoever holds the bytes can replay it, and the asymmetric
	// key that authenticated the client is irrelevant to that replay.
	hydraReq.DPoPBoundAccessTokens = u.BindDPoP

	// Писатель перечня обязателен ЗДЕСЬ, до всякой записи. Ключ, чей перечень
	// не записан, не примет никого, и выдача ответила бы успехом на
	// невыполнимое — то есть объявила бы возможность, которой нет.
	if u.trustedIssuers == nil {
		return nil, status.Error(codes.Unavailable,
			"trusted issuer list writer is not wired: a federated key without its list would trust nobody")
	}

	identity, err := u.nameClient(ctx, keyID, hydraReq)
	if err != nil {
		return nil, err
	}

	row := domain.ServiceAccountOAuthClient{
		ID:              keyID,
		SvaID:           in.ServiceAccountID,
		OAuthClientID:   domain.OAuthClientID(identity.ClientID),
		Description:     domain.Description(in.Description),
		CreatedByUserID: domain.UserID(in.CreatedByUserID),
		// PublicKeyPEM + KeyAlgorithm intentionally empty — no key
		// material in kaname for federated rows.
		TrustedSubjects: append([]domain.TrustedSubject(nil), in.TrustedSubjects...),
		Name:            domain.OAuthClientName(in.Name),
		Labels:          in.Labels,
		// Сужение записывается и здесь. Разойдись две полосы, федеративный ключ
		// стал бы несужаемой дорогой внутрь — ровно та форма, которую ищут.
		DeclaredAudiences: declaredAudiences(in),
		// Вид ЗАПИСЫВАЕТСЯ, а не вычисляется читателем.
		CredentialKind: domain.CredentialKindFederated,
	}
	if exp := u.resolveExpiry(in); exp != nil {
		row.ExpiresAt = exp
	}
	// Federated rows carry no kacho-held key material — key_algorithm is "".
	//
	// Перечень доверенных издателей уезжает в ТУ ЖЕ транзакцию, что строка
	// ключа: откат снимает оба, полусделанного состояния между ними не бывает.
	persisted, err := u.commitMapping(ctx, row, identity.ProviderCoordinate, actor, "")
	if err != nil {
		return nil, err
	}

	pbKey, err := saClientToProto(persisted)
	if err != nil {
		return nil, err
	}
	resp := &iamv1.IssueSAKeyResponse{
		Key:      pbKey,
		ClientId: identity.ClientID,
		// Federated: no key material. Algorithm + KeyId are likewise empty
		// because the asserting party owns its own kid scheme.
		ClientSecret:  "",
		PrivateKeyPem: "",
		PublicKeyPem:  "",
		Algorithm:     "",
		KeyId:         string(keyID),
		// Перечень адресатов ключа: записанное сужение на переведённом контуре,
		// перечень зеркала на непереведённом (см. responseAudiences).
		Audiences: u.responseAudiences(hydraReq.Audience, persisted.DeclaredAudiences),
	}
	return anypb.New(resp)
}

// resolveExpiry returns the absolute expiry for the key being issued, or nil
// when the key is non-expiring.
//
// Precedence: an explicit `ttl_seconds` wins; otherwise the configured
// DefaultTTL applies. nil is returned ONLY when the caller omitted the TTL and
// no default is configured — the legacy behaviour, preserved so wiring the knob
// is what changes behaviour rather than this refactor.
func (u *IssueSAKeyUseCase) resolveExpiry(in IssueInput) *time.Time {
	var d time.Duration
	switch {
	case in.TTLSeconds > 0:
		d = time.Duration(in.TTLSeconds) * time.Second
	case u.DefaultTTL > 0:
		d = u.DefaultTTL
	default:
		return nil
	}
	t := u.now().Add(d)
	return &t
}

// accessTokenLifespan renders the per-client `access_token_lifespan` for the
// Hydra registration. Empty string → field omitted → provider default.
func (u *IssueSAKeyUseCase) accessTokenLifespan() string {
	if u.AccessTokenLifespan <= 0 {
		return ""
	}
	return u.AccessTokenLifespan.String()
}

// compensationOriginSAKey — атрибуция саги в компенсирующем намерении.
const compensationOriginSAKey = "sa_key"

// providerReleaseTimeout — верхняя граница на снятие уже созданного клиента
// (запись намерения ИЛИ прямой вызов). Отвязан от отмены вызывающего: снятие
// обязано исполниться, даже если запрос уже отменён.
const providerReleaseTimeout = 5 * time.Second

// releaseProviderClient снимает OAuth-клиента, созданного у провайдера до того,
// как своя строка была закоммичена.
//
// Порядок обратный порядку захвата и ровно из одного шага: клиент — последнее и
// единственное, что сага заняла у провайдера к этому моменту.
//
// Первичный путь — DURABLE намерение (переживает смерть процесса и провал
// самого снятия, доставляется дренажом at-least-once). Прямой вызов остаётся
// ЗАПАСНЫМ и срабатывает только если намерение записать не удалось: тогда мы не
// хуже прежнего, и это видно в логе. Оба пути идемпотентны — повторное снятие
// уже снятого клиента провайдер отдаёт как исполненное.
func (u *IssueSAKeyUseCase) releaseProviderClient(ctx context.Context, clientID, reason string) {
	if clientID == "" {
		return
	}
	// Отвязано от отмены вызывающего, baggage (trace/request-id) сохранено.
	relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerReleaseTimeout)
	defer cancel()

	if u.compensation != nil {
		if err := u.compensation.EmitHydraClientDelete(relCtx, clientID, compensationOriginSAKey, reason); err == nil {
			return
		} else if u.logger != nil {
			u.logger.ErrorContext(relCtx,
				"sa key: durable compensation intent could not be recorded, falling back to a direct release",
				"provider_client_id", clientID, "reason", reason, "err", err.Error())
		}
	}
	if err := u.hydra.DeleteOAuthClient(relCtx, clientID); err != nil && u.logger != nil {
		// Ни намерения, ни снятия — клиент остался у провайдера, и назвать его
		// потом можно только по этой строке лога.
		u.logger.ErrorContext(relCtx,
			"sa key: provider registration left behind after a failed issue",
			"provider_client_id", clientID, "reason", reason, "err", err.Error())
	}
}

// commitMapping persists the SA-OAuth-client mapping row in a fresh tx and
// rolls back + releases the Hydra client on failure. Shared by both the
// private_key_jwt and federated paths.
//
// The durable iam.sa_key.issued audit_outbox row is emitted in the SAME tx as
// the Insert (atomic, запрет #10): the audit row commits iff the mapping
// commits, so a rolled-back Insert (e.g. sva_unique 23505) leaves no orphan
// compliance row. The Hydra client is created BEFORE this tx (external side-
// effect); on failure it is released through releaseProviderClient (durable
// intent, direct call as fallback) — the compensating intent CANNOT ride this
// tx, because this tx is precisely the one that rolls back.
func (u *IssueSAKeyUseCase) commitMapping(ctx context.Context, row domain.ServiceAccountOAuthClient, hydraClientID, actor, keyAlgorithm string) (domain.ServiceAccountOAuthClient, error) {
	// Пустое имя до записи не доживает: оно означало «назови сам», и здесь, где
	// идентификатор уже назначен, его заменяет имя, производное от него (#1279).
	// Подстановка стоит в ОДНОЙ точке — той, через которую проходит КАЖДЫЙ вид
	// выпуска: рассыпанная по видам, она разошлась бы между ними молча.
	row.Name = domain.OAuthClientName(corevalidate.NameOrDefault(string(row.Name), string(row.ID)))

	tx, err := u.tx.Begin(ctx)
	if err != nil {
		u.releaseProviderClient(ctx, hydraClientID, "mapping tx could not be started")
		return domain.ServiceAccountOAuthClient{}, mapPGErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
			u.releaseProviderClient(ctx, hydraClientID, "mapping row was not committed")
		}
	}()
	persisted, err := u.repo.Insert(ctx, tx, row)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapPGErr(err)
	}
	// Перечень доверенных издателей — в ТОЙ ЖЕ транзакции, что строка ключа
	// (#1124). Ключ без перечня не примет никого; перечень без ключа ручался бы
	// за постороннего от имени того, кого нет. Записанные двумя обращениями, они
	// разъезжаются на отказе между ними — и разъезжаются в сторону, которую
	// никто не увидит, потому что выдача ответит успехом.
	if len(row.TrustedSubjects) > 0 {
		if terr := u.trustedIssuers.InsertTrustedIssuers(
			ctx, tx, persisted.ID, row.TrustedSubjects, row.ExpiresAt,
		); terr != nil {
			return domain.ServiceAccountOAuthClient{}, mapPGErr(terr)
		}
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

// RevokeSAKeyUseCase deletes both the kaname mapping row and the Hydra
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
	// state-not-consulted: отзыв ключа — уборка, а не аутентификация. Состояние
	// говорит, что учётке нельзя ВХОДИТЬ; отняв вместе с этим возможность
	// отозвать её ключи, мы сделали бы отключение учётки действием, которое
	// оператор не может довести до конца, и оставили бы живые учётные данные
	// ровно там, где их нужнее всего снять.
	accountID, _, err := u.repo.AccountForServiceAccount(ctx, in.ServiceAccountID)
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

// doRevoke removes the key and is IDEMPOTENT: revoking twice, revoking an id
// that never existed, and revoking SOMEONE ELSE'S key all produce the same
// outcome — success with nothing removed.
//
// Why one outcome and not three. The basic-access-token acceptance (BAT-1-44)
// requires a repeat revoke to answer success. Hide-existence (security.md
// §Hardening #6) requires a refusal on a foreign credential to be
// indistinguishable from a genuine miss. The two pull apart only while there is
// more than one outcome: the moment "already revoked" answers success and
// "foreign" answers a refusal, the caller learns from the difference whether
// SOMEONE ELSE'S credential exists — chasing idempotency would have installed
// an oracle.
//
// This is settled by removing the branch, not by matching two texts to each
// other: ownership sits inside the removal statement itself (`WHERE id AND
// sva_id`), so the place where "foreign" and "absent" could diverge does not
// exist in the code. The foreign row survives the call — success means "no such
// credential in the caller's namespace", never a licence to remove another's.
//
// The right to manage THIS service account's keys is checked at the edge before
// the call: `scope_extractor` takes the `iam_service_account` object out of the
// `service_account_id` field (sa_key_service.proto). The key id is not checked
// there — narrowing it is what the statement below does.
func (u *RevokeSAKeyUseCase) doRevoke(ctx context.Context, in RevokeInput, actor string) (*anypb.Any, error) {
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
	cur, found, err := u.repo.DeleteOwnedByID(ctx, tx, in.ServiceAccountID, in.KeyID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	if !found {
		// Nothing to remove. The tx rolls back (there is no removal to persist),
		// no audit row is emitted — there is no event without a state change —
		// and no provider call is made: calling out on a foreign or absent id
		// would be the same oracle again, only in someone else's log.
		return revokeSAKeyResponse(in.KeyID)
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
		// The DB delete already committed, so the RPC stays successful and the
		// provider-side client registration outlives it. There is no cleanup
		// worker in this service and deliberately none is added: what makes a
		// revocation a revocation is that the credential stops working, and
		// that no longer depends on this call succeeding.
		//
		// The mapping row IS the authority on whether a client is a kacho
		// credential, and the token hook consults it on every single mint. With
		// the row gone the surviving client resolves to no principal, so the
		// hook refuses it (`invalid_client`, 403) and records an
		// `authn.token.denied` with reason `principal_not_found` each time it
		// tries — see handler/iamhooks/token_hook_handler.go. So at commit this
		// key can obtain NOTHING FURTHER, and that no longer waits on the
		// provider being reachable.
		//
		// What it does not do is reach back for what was already handed out. An
		// access token minted before this commit is self-contained and stays
		// valid until it expires; revocation bounds the credential, not the
		// tokens already in flight. The window is therefore the access-token
		// lifetime — minutes in production, deliberately wider on the local
		// stand — and that is the property to state when someone asks how fast
		// a revoke takes effect.
		//
		// A compensating outbox or sweeper was considered and rejected: both
		// are EVENTUAL, so neither would have closed the window the hook closes
		// outright, and what they would buy — deleting a registration that can
		// no longer obtain a token — is inventory hygiene, not security. That
		// leftover is what this WARN is for; an operator can delete it by hand.
		if u.logger != nil {
			u.logger.WarnContext(ctx, "sa-key hydra oauth-client delete failed after DB commit — the registration outlives its row (it can no longer mint; delete it by hand)",
				slog.String("oauth_client_id", string(cur.OAuthClientID)),
				slog.String("key_id", string(in.KeyID)),
				slog.String("err", err.Error()),
			)
		}
	}
	return revokeSAKeyResponse(in.KeyID)
}

// revokeSAKeyResponse is the SINGLE producer of a successful revoke body.
//
// One producer on purpose. Two assembly sites would drift on the first edit —
// and drift exactly where drift is dangerous: from the difference in bodies the
// caller would learn whether anything was actually removed, i.e. whether the
// credential exists. The timestamp is stamped ALWAYS for the same reason: an
// empty timestamp on a no-op revoke reads straight off the body as "there was
// nothing to remove".
func revokeSAKeyResponse(keyID domain.SAOAuthClientID) (*anypb.Any, error) {
	return anypb.New(&iamv1.RevokeSAKeyResponse{
		KeyId:     string(keyID),
		RevokedAt: timestamppb.Now(),
	})
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
		CredentialKind:  credentialKindToProto(c.CredentialKind),
	}
	if c.ExpiresAt != nil {
		pb.ExpiresAt = shared.TimestampProto(*c.ExpiresAt)
	}
	if c.LastUsedAt != nil {
		pb.LastUsedAt = shared.TimestampProto(*c.LastUsedAt)
	}
	return pb, nil
}

// credentialKindToProto / CredentialKindFromProto — отображение вида домена в
// вид контракта и обратно. Объявлено ОДНИМ местом на пакет: второе отображение
// разошлось бы с первым молча.
func credentialKindToProto(k domain.CredentialKind) iamv1.CredentialKind {
	switch k {
	case domain.CredentialKindKeypair:
		return iamv1.CredentialKind_CREDENTIAL_KIND_KEYPAIR
	case domain.CredentialKindSecret:
		return iamv1.CredentialKind_CREDENTIAL_KIND_SECRET
	case domain.CredentialKindFederated:
		return iamv1.CredentialKind_CREDENTIAL_KIND_FEDERATED
	case domain.CredentialKindLegacy:
		return iamv1.CredentialKind_CREDENTIAL_KIND_LEGACY
	default:
		return iamv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED
	}
}

// CredentialKindFromProto — обратное отображение, для входа выдачи.
func CredentialKindFromProto(k iamv1.CredentialKind) domain.CredentialKind {
	switch k {
	case iamv1.CredentialKind_CREDENTIAL_KIND_KEYPAIR:
		return domain.CredentialKindKeypair
	case iamv1.CredentialKind_CREDENTIAL_KIND_SECRET:
		return domain.CredentialKindSecret
	case iamv1.CredentialKind_CREDENTIAL_KIND_FEDERATED:
		return domain.CredentialKindFederated
	case iamv1.CredentialKind_CREDENTIAL_KIND_LEGACY:
		return domain.CredentialKindLegacy
	default:
		return domain.CredentialKindUnspecified
	}
}

func mapPGErr(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	// Отказ учёта — ПЕРЕД общим разбором и ЧУЖИМ производителем.
	//
	// Полосу учёта различает не только код: клиент ключуется на признак
	// `google.rpc.ErrorInfo`, и приклеивает его один производитель на весь домен
	// (`shared.MapRepoErr`). Разобрать эти признаки здесь своими словами значило
	// бы завести второе место об одном контракте — и разойтись с ним на первом же
	// уточнении текста. Без этой ветви отказ уходил бы в фиксированный INTERNAL:
	// вызывающий видел бы поломку платформы там, где платформа сработала как
	// задумана, и не узнал бы ни носителя, ни предела, ни вида.
	if errors.Is(err, iamerr.ErrQuotaExceeded) ||
		errors.Is(err, iamerr.ErrQuotaRateExceeded) ||
		errors.Is(err, iamerr.ErrQuotaNotProvisioned) {
		return shared.MapRepoErr(err)
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
