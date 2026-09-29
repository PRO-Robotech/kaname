// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sa_keys — SAKeyService use-cases (Class A static SA-keys: a key
// pair, a federated key or a basic secret of a service account).
//
// On Issue (private_key_jwt mode):
//
//  1. Generate an ECDSA P-256 keypair locally; the private half NEVER
//     leaves kaname's response and is NEVER stored in DB.
//  2. Name the client. Имя клиента назначаем МЫ, и оно совпадает с
//     идентификатором нашей строки: подписанное утверждение называет им себя,
//     а обменивает его токен-эндпоинт платформы (`authn.client-token.enabled`).
//     Посадка без эндпоинта ключ, который обменять негде, не выдаёт
//     (kaname#362). Регистрации у внешнего поставщика выдача не заводит и
//     имени, назначенного им, не хранит — столбец, где оно лежало, снят.
//  3. Persist `service_account_oauth_clients` row (public PEM + algorithm).
//  4. Return IssueSAKeyResponse with the plaintext PRIVATE PEM + kid
//     in `Operation.response` (one-shot delivery; redacted post-completion
//     by OpsResponseRedactor so re-polling Operation.Get yields no secret).
//
// On Revoke:
//
//  1. Delete the row, scoped by sva_id in the same statement (Authorization
//     Cross-Tenant check). Removal of the row cuts off what the key minted
//     (trigger of the schema); no call leaves the service.
//
// On List: paged read of own SA's clients.
package sa_keys

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	corevalidate "github.com/PRO-Robotech/corelib/validate"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
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

// IssueSAKeyUseCase mints a new SA key + persists its row.
type IssueSAKeyUseCase struct {
	repo    SAClientRepo
	tx      service.TxBeginner
	opsRepo operations.Repo
	// trustedIssuers — писатель нашего перечня доверенных издателей. Nil на
	// федеративной выдаче — ОТКАЗ, а не «пропустить»: ключ, чей перечень не
	// записан, не примет никого, и выдача ответила бы успехом на невыполнимое.
	trustedIssuers TrustedIssuerWriter
	// ownIssuance — посадка обменивает ключ своим токен-эндпоинтом (задача
	// kacho#1120, `authn.client-token.enabled`). Без него ключевая пара и
	// федеративный ключ не выдаются: другого исполнителя обмена у ключа нет
	// (kaname#362). Умолчание — отказ: полусобранная сборка не выдаёт ключ,
	// который нечем обменять.
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

	// MaxTTL — inclusive ceiling on `ttl_seconds`. A request above it is
	// refused with InvalidArgument before anything is written.
	// Zero → no ceiling (degraded/legacy wiring); the composition root sets it
	// from config so the machine credential cannot outlive policy.
	MaxTTL time.Duration
	// DefaultTTL — lifetime applied when the caller omits `ttl_seconds`.
	// Zero → the legacy non-expiring behaviour is kept (so an un-migrated
	// deployment is unchanged until the knob is wired). A non-zero value is
	// what turns "0 means never expires" into "0 means the policy default".
	DefaultTTL time.Duration
}

// WithResponseRedactor wires the post-Issue secret redactor.}

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

// WithOwnIssuance объявляет, что посадка обменивает ключ СВОИМ токен-эндпоинтом
// (задача kacho#1120, `authn.client-token.enabled`).
//
// Composition-root only: есть ли у посадки эндпоинт — её свойство, а не
// запроса, и вызывающий его не выбирает. Без объявления ключевая пара и
// федеративный ключ отвергаются синхронно (kaname#362).
func (u *IssueSAKeyUseCase) WithOwnIssuance() *IssueSAKeyUseCase {
	u.ownIssuance = true
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
func NewIssueSAKeyUseCase(r SAClientRepo, tx service.TxBeginner, ops operations.Repo) *IssueSAKeyUseCase {
	return &IssueSAKeyUseCase{
		repo:    r,
		tx:      tx,
		opsRepo: ops,
		now:     time.Now,
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
	// switches to FEDERATED mode: no keypair is generated and the response
	// omits `private_key_pem` / `public_key_pem`. External
	// workloads sign their own assertions through the IdP that emitted one
	// of the listed `(issuer, subject_pattern)` tuples; наш проверяющий
	// принимает утверждение тогда и только тогда, когда пара (iss, sub) есть
	// в НАШЕМ перечне доверенных издателей и подпись сошлась с записанным там
	// ключом издателя (#1124). Empty slice = private_key_jwt mode.
	TrustedSubjects []domain.TrustedSubject

	// Audience — сужение адресатов, объявленное заказчиком (#1136): ключ
	// сможет заказать только адресатов из этого перечня и только внутри
	// перечня посадки (`authn.client-token.allowed-audiences`). Порядок
	// сохраняется, пустые элементы снимаются, повторы схлопываются. Пустой
	// перечень = сужения не объявлено; действует перечень посадки.
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

	// Ключевая пара и федеративный ключ предъявляются ОБМЕНОМ, и обменивает их
	// только токен-эндпоинт платформы. Посадка без него выдала бы ключ, который
	// обменять негде, — объявленную возможность, не исполнимую ни при каком
	// входе. Отказ синхронный и стоит ПОСЛЕ разбора запроса: сформированный
	// неверно запрос получает свой отказ с именем поля на любой посадке, а
	// верный — ответ, известный до всякого чтения и записи. Секрет обмена не
	// требует — его предъявляют как есть.
	if kind != domain.CredentialKindSecret && !u.ownIssuance {
		return nil, status.Errorf(codes.FailedPrecondition,
			"credential_kind %s: authn.client-token.enabled is false — this key is exchanged for a "+
				"token on the platform token endpoint, and this landing does not run one", kind)
	}

	// Resolve the owning account so the Operation metadata carries account_id —
	// the account-scoped /iam/operations feed otherwise excludes token operations.
	accountID, mayAuthenticate, err := u.repo.AccountForServiceAccount(ctx, in.ServiceAccountID)
	if err != nil {
		return nil, mapPGErrLogged(ctx, u.logger, "sa_keys.Issue.accountForServiceAccount", err)
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
			return nil, mapPGErrLogged(ctx, u.logger, "sa_keys.Issue.ownerUserForServiceAccount", oerr)
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
		persisted, err := u.commitMapping(ctx, row, actor, "")
		if err != nil {
			return nil, err
		}
		pbKey := saClientToProto(persisted)
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

// doIssuePrivateKeyJWT — mint ECDSA P-256 keypair, persist the row with
// PublicKeyPEM + KeyAlgorithm, return PrivateKeyPEM exactly once. The client is
// named by the id of the row: that name signs the assertion (`iss`/`sub`), and
// the platform token endpoint resolves it.
func (u *IssueSAKeyUseCase) doIssuePrivateKeyJWT(ctx context.Context, keyID domain.SAOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	// 1. Mint ECDSA P-256 keypair locally.
	key, err := generateES256Key()
	if err != nil {
		return nil, fmt.Errorf("generate sa keypair: %w", err)
	}

	// 2. Persist the row in TX.
	row := domain.ServiceAccountOAuthClient{
		ID:              keyID,
		SvaID:           in.ServiceAccountID,
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
	persisted, err := u.commitMapping(ctx, row, actor, key.Algorithm)
	if err != nil {
		return nil, err
	}

	// 3. Build response — return PRIVATE PEM + kid ONCE. `client_secret`
	//    is kept empty (deprecated field, retained for wire-compat).
	pbKey := saClientToProto(persisted)
	resp := &iamv1.IssueSAKeyResponse{
		Key:           pbKey,
		ClientId:      string(keyID),
		ClientSecret:  "", // private_key_jwt: no shared secret exists.
		PrivateKeyPem: key.PrivatePEM,
		PublicKeyPem:  key.PublicPEM,
		Algorithm:     key.Algorithm,
		KeyId:         string(keyID),
		// Перечень адресатов ключа — ЗАПИСАННОЕ сужение (#1136). Пустой перечень
		// — утверждение, а не умолчание: «сужения нет, действует перечень
		// посадки».
		Audiences: persisted.DeclaredAudiences,
	}
	return anypb.New(resp)
}

// declaredAudiences — сужение адресатов в той форме, в какой его объявляет
// контракт выдачи: порядок сохраняется, пустые элементы снимаются, повторы
// схлопываются.
//
// ЗДЕСЬ НЕТ НИ ОДНОГО ЗНАЧЕНИЯ СВЕРХ НАЗВАННЫХ ЗАКАЗЧИКОМ. Попади сюда что-то
// сверх — адресат реестра, внутреннее умолчание, — ключ получил бы доступ к
// адресатам, которых заказчик не называл: расширение вместо сужения, молча и в
// сторону большего.
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

// doIssueFederated — выдача федеративного ключа: ключевого материала у него нет,
// а его перечень доверенных издателей пишется НАШЕЙ таблицей в той же
// транзакции, что и строка ключа (задача #1124).
//
// Утверждение внешней нагрузки проверяет наш проверяющий
// (`internal/clientassertion`, федеративная полоса) по нашему перечню, а
// обменивает его токен-эндпоинт платформы. Регистрации у внешнего поставщика
// эта выдача не заводит.
func (u *IssueSAKeyUseCase) doIssueFederated(ctx context.Context, keyID domain.SAOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	// Писатель перечня обязателен ЗДЕСЬ, до всякой записи. Ключ, чей перечень
	// не записан, не примет никого, и выдача ответила бы успехом на
	// невыполнимое — то есть объявила бы возможность, которой нет.
	if u.trustedIssuers == nil {
		return nil, status.Error(codes.Unavailable,
			"trusted issuer list writer is not wired: a federated key without its list would trust nobody")
	}

	row := domain.ServiceAccountOAuthClient{
		ID:              keyID,
		SvaID:           in.ServiceAccountID,
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
	// Federated rows carry no kaname-held key material — key_algorithm is "".
	//
	// Перечень доверенных издателей уезжает в ТУ ЖЕ транзакцию, что строка
	// ключа: откат снимает оба, полусделанного состояния между ними не бывает.
	persisted, err := u.commitMapping(ctx, row, actor, "")
	if err != nil {
		return nil, err
	}

	pbKey := saClientToProto(persisted)
	resp := &iamv1.IssueSAKeyResponse{
		Key:      pbKey,
		ClientId: string(keyID),
		// Federated: no key material. Algorithm + KeyId are likewise empty
		// because the asserting party owns its own kid scheme.
		ClientSecret:  "",
		PrivateKeyPem: "",
		PublicKeyPem:  "",
		Algorithm:     "",
		KeyId:         string(keyID),
		// Перечень адресатов ключа — записанное сужение (#1136).
		Audiences: persisted.DeclaredAudiences,
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

// commitMapping persists the SA key row in a fresh tx. Shared by all three
// kinds.
//
// The durable iam.sa_key.issued audit_outbox row is emitted in the SAME tx as
// the Insert (atomic, запрет #10): the audit row commits iff the row commits, so
// a rolled-back Insert (e.g. sva_unique 23505) leaves no orphan compliance row.
// Nothing is created outside the service before this tx, so a failed tx leaves
// nothing to compensate.
func (u *IssueSAKeyUseCase) commitMapping(ctx context.Context, row domain.ServiceAccountOAuthClient, actor, keyAlgorithm string) (domain.ServiceAccountOAuthClient, error) {
	// Пустое имя до записи не доживает: оно означало «назови сам», и здесь, где
	// идентификатор уже назначен, его заменяет имя, производное от него (#1279).
	// Подстановка стоит в ОДНОЙ точке — той, через которую проходит КАЖДЫЙ вид
	// выпуска: рассыпанная по видам, она разошлась бы между ними молча.
	row.Name = domain.OAuthClientName(corevalidate.NameOrDefault(string(row.Name), string(row.ID)))

	tx, err := u.tx.Begin(ctx)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapPGErrLogged(ctx, u.logger, "sa_keys.Issue.mappingTxBegin", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	persisted, err := u.repo.Insert(ctx, tx, row)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapPGErrLogged(ctx, u.logger, "sa_keys.Issue.insert", err)
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
			return domain.ServiceAccountOAuthClient{}, mapPGErrLogged(ctx, u.logger, "sa_keys.Issue.replaceTrustedSubjects", terr)
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
			return domain.ServiceAccountOAuthClient{}, mapPGErrLogged(ctx, u.logger, "sa_keys.Issue.emitAudit", aerr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ServiceAccountOAuthClient{}, mapPGErrLogged(ctx, u.logger, "sa_keys.Issue.commit", err)
	}
	committed = true
	return persisted, nil
}

// ───────────────── Revoke use-case ─────────────────

// RevokeSAKeyUseCase deletes the key row; the schema cuts off what it minted.
type RevokeSAKeyUseCase struct {
	repo    SAClientRepo
	tx      service.TxBeginner
	opsRepo operations.Repo
	// audit — durable audit_outbox emitter. nil → no audit row.
	audit auditEmitter
	// logger — reader of the mapped-error detail (mapPGErrLogged). nil → the
	// process default.
	logger *slog.Logger
}

// NewRevokeSAKeyUseCase constructs.
func NewRevokeSAKeyUseCase(r SAClientRepo, tx service.TxBeginner, ops operations.Repo) *RevokeSAKeyUseCase {
	return &RevokeSAKeyUseCase{repo: r, tx: tx, opsRepo: ops}
}

// WithAuditEmitter wires the durable audit_outbox emitter.
// Composition-root only. nil emitter → audit emit is skipped.
func (u *RevokeSAKeyUseCase) WithAuditEmitter(a auditEmitter) *RevokeSAKeyUseCase {
	u.audit = a
	return u
}

// WithLogger wires the reader of the mapped-error detail. Composition-root only;
// returns the receiver.
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
		return nil, mapPGErrLogged(ctx, u.logger, "sa_keys.Revoke.accountForServiceAccount", err)
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
// requires a repeat revoke to answer success. Hide-existence
// (§Hardening #6) requires a refusal on a foreign credential to be
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
//
// # How fast a revocation takes effect
//
// At commit the key can obtain NOTHING FURTHER: the row IS the authority on
// whether a client is a kacho credential, and with it gone the key resolves to
// no principal on every exchange.
//
// What the key minted before is cut off by the SAME transaction: the trigger
// `sa_oauth_client_removal_cuts_minted_tokens` writes a revocation addressed by
// the id of our row. The claim set of our token carries that id
// (`kaname_sa_key_id`), it is in the closed list of cut-off keys of the
// revocation rule, and both accepting surfaces ask the rule ON THE REQUEST PATH
// — the revocation authority on the internal listener and the reader of the
// presented credential on the public one. So the residual window is the cache
// lifetime of a positive verdict at the reader — a value the OPERATOR declares
// and sees — not the lifetime of the credential itself.
//
// ПОВЕРХНОСТЕЙ, ЧИТАЮЩИХ ОТСЕЧКУ: 2
//
// The number above is checked against the tree by `revoke_window_doc_test.go`,
// which counts the call sites itself.
//
// No call leaves the service. A key row used to carry the name a previous
// external issuer gave its client, and revocation deleted that registration
// after the commit; the column and every registration it named are gone
// (kaname#362, order of the removal —
// docs/engineering/architecture/provider-mirror-column-retirement.md), so
// there is nothing outside to remove.
func (u *RevokeSAKeyUseCase) doRevoke(ctx context.Context, in RevokeInput, actor string) (*anypb.Any, error) {
	tx, err := u.tx.Begin(ctx)
	if err != nil {
		return nil, mapPGErrLogged(ctx, u.logger, "sa_keys.Revoke.txBegin", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	cur, found, err := u.repo.DeleteOwnedByID(ctx, tx, in.ServiceAccountID, in.KeyID)
	if err != nil {
		return nil, mapPGErrLogged(ctx, u.logger, "sa_keys.Revoke.deleteOwnedByID", err)
	}
	if !found {
		// Nothing to remove. The tx rolls back (there is no removal to persist)
		// and no audit row is emitted — there is no event without a state
		// change.
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
			return nil, mapPGErrLogged(ctx, u.logger, "sa_keys.Revoke.emitAudit", aerr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapPGErrLogged(ctx, u.logger, "sa_keys.Revoke.commit", err)
	}
	committed = true
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

// saClientToProto — проекция строки клиента в форму контракта.//
// Ошибки НЕ возвращает: собрать проекцию нечем — все поля берутся у уже
// прочитанной строки. Прежде возвращалась всегда-nil ошибка, и у вызывающих
// стояли недостижимые ветви `if err != nil`: ветвь, которая не может
// исполниться, есть форма проверки без содержания — её читают как покрытый
// случай (kaname#115).
func saClientToProto(c domain.ServiceAccountOAuthClient) *iamv1.ServiceAccountOAuthClient {
	pb := &iamv1.ServiceAccountOAuthClient{
		Id:              string(c.ID),
		SvaId:           string(c.SvaID),
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
	return pb
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
	default:
		return iamv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED
	}
}

// CredentialKindFromProto — обратное отображение, для входа выдачи.
//
// Номер вне словаря — ОТКАЗ с именем поля, а не «вид не назван». Вид назван, и
// назван тем, чего нет: отобразить его в UNSPECIFIED значило бы выпустить
// ключевую пару на запрос, просивший другого, — принять параметр и молча его
// проигнорировать. Номер снятого вида (4, LEGACY, kaname#362) стал ровно таким
// номером и отвергается этой же ветвью.
func CredentialKindFromProto(k iamv1.CredentialKind) (domain.CredentialKind, error) {
	switch k {
	case iamv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED:
		return domain.CredentialKindUnspecified, nil
	case iamv1.CredentialKind_CREDENTIAL_KIND_KEYPAIR:
		return domain.CredentialKindKeypair, nil
	case iamv1.CredentialKind_CREDENTIAL_KIND_SECRET:
		return domain.CredentialKindSecret, nil
	case iamv1.CredentialKind_CREDENTIAL_KIND_FEDERATED:
		return domain.CredentialKindFederated, nil
	default:
		return "", status.Errorf(codes.InvalidArgument,
			"%s: unknown credential kind %d", domain.ErrCredentialKindField, int32(k))
	}
}

// mapPGErrLogged — тот же перевод, что `mapPGErr`, и ЧИТАТЕЛЬ у подробности.
//
// Переводчик остаётся свободной функцией: его текст `INTERNAL` — часть
// контракта ЭТОГО домена («internal SA key error»), и подменить его общим
// значило бы сменить контракт мимо приёмки. Читателя даёт
// `shared.LogMappedErr`, у которого решение «какие исходы называть журналу»
// живёт в единственном экземпляре: разойдясь в нём, домены разошлись бы в том,
// что считается заметным (задача #2507).
//
// Логгер берётся у вызывающего, а если у того его нет — у умолчания процесса.
// Умолчание ЗАДАНО композиционным корнем (`slog.SetDefault`, cmd/kaname), так
// что запись доезжает до того же приёмника, а не уходит в никуда: провязка «на
// всякий случай», у которой нет читателя, была бы ровно тем мёртвым глаголом,
// который эта задача и снимает.
func mapPGErrLogged(ctx context.Context, logger *slog.Logger, op string, err error) error {
	if logger == nil {
		logger = slog.Default()
	}
	return shared.LogMappedErr(ctx, logger, op, err, mapPGErr(err))
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
	case errors.Is(err, iamerr.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrAborted):
		// ПОВТОРЯЕМЫЙ отказ, а не поломка. Признак ставит `pgmaperr` на 40001/40P01
		// — сериализационный конфликт и взаимная блокировка, — и повтор того же
		// запроса проходит. Без этой ветви он уезжал в терминальный INTERNAL:
		// вызывающий читал «сервис сломан» на состоянии, которое проходит само, и
		// не повторял (задача #114).
		return status.Error(codes.Aborted, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		// Фиксированный текст, как у INTERNAL ниже, и по той же причине: цепочка
		// признака недоступности ведёт к ЧУЖОМУ производителю (база, сосед, гейт
		// прав), и её текст вызывающему не адресован. Прежде здесь стоял разбор
		// цепочки, то есть обёртка вызывающего доезжала до провода дословно;
		// утечки не случалось лишь потому, что производители этого признака в
		// службе опаковы сами — «by construction» на деле означало «пока никто не
		// обернул» (задача #2464).
		//
		// Текст — тот же, что у канонического переводчика, и берётся У НЕГО:
		// свой литерал здесь был бы вторым местом об одном контракте, и разошлись
		// бы они ровно так, как разошлись эти переводчики.
		//
		// Подробность остаётся в цепочке, и у неё ЕСТЬ читатель: вызывающие зовут
		// `mapPGErrLogged`, который называет причину журналу (задача #2507).
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		// Конец контекста — повторяемый отказ, а не поломка (kaname#383); текст —
		// канонический текст недоступности. Набор полос сходится с каноном
		// (`shared.MapRepoErr`), и сходимость держит гейт.
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	case errors.Is(err, iamerr.ErrInternal):
		// Ветвь ЯВНАЯ, хотя исход совпадает с запасным ниже. Так набор различаемых
		// полос сходится с каноном, а сходимость держит гейт: копия, у которой
		// полос меньше, молча отправляет чужие в терминальный INTERNAL. Текст
		// остаётся СВОИМ — он называет предмет и есть часть контракта домена;
		// подробность цепочки на провод не идёт ни здесь, ни в запасной ветви
		// (hardening-инвариант #1).
		return status.Error(codes.Internal, "internal SA key error")
	}
	return status.Error(codes.Internal, "internal SA key error")
}
