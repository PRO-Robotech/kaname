// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package user_tokens — use-cases UserTokenService (персональные access-токены
// пользователя через Hydra OAuth2 client_credentials + private_key_jwt).
//
// На Issue:
//
//  1. Генерируем пару ключей ECDSA P-256 локально; приватная половина НИКОГДА не
//     покидает response kacho-iam и НИКОГДА не хранится в БД.
//  2. Регистрируем OAuth2-клиент в Hydra Admin с
//     `token_endpoint_auth_method=private_key_jwt`,
//     `grant_types=[client_credentials]`, `jwks={keys:[<public JWK>]}`,
//     `owner=<user_id>`. Hydra не возвращает `client_secret` — его нет.
//  3. Персистим строку `user_oauth_clients` (hydra_client_id-маппинг + public PEM
//     + algorithm).
//  4. Возвращаем IssueUserTokenResponse с plaintext приватным PEM + kid в
//     `Operation.response` (одноразовая выдача; затирается post-completion
//     OpsResponseRedactor'ом, так что re-poll Operation.Get секрета не отдаёт).
//
// На Revoke:
//
//  1. Fetch строки по id, scoped по user_id (cross-user isolation).
//  2. Delete строки + DELETE Hydra OAuth2-клиента (idempotent — Hydra 404 OK).
//
// На List: paged read токенов своего User (без round-trip в Hydra).
package user_tokens

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

// UserClientRepo абстрагирует репо user-oauth-clients. Tx-scoped записи берут
// непрозрачный service.Tx handle (конкретный pgx.Tx восстанавливается внутри pg
// adapter'а через txAsPgx), чтобы этот use-case-пакет оставался свободен от
// pgx-драйвера.
type UserClientRepo interface {
	Get(ctx context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error)
	Insert(ctx context.Context, tx service.Tx, c domain.UserOAuthClient) (domain.UserOAuthClient, error)
	DeleteByID(ctx context.Context, tx service.Tx, id domain.UserOAuthClientID) error
	List(ctx context.Context, userID domain.UserID, pageToken string, pageSize int32) ([]domain.UserOAuthClient, string, error)
	// AccountForUser резолвит account владельца-User, чтобы Issue/Revoke стемпили
	// `account_id` на Operation-метаданных (account-scoped /iam/operations feed).
	// Нет User → ErrNotFound.
	AccountForUser(ctx context.Context, id domain.UserID) (domain.AccountID, error)
}

// OAuthClientAdmin абстрагирует hydra-admin операции, нужные Issue/Revoke.
type OAuthClientAdmin interface {
	CreateOAuthClient(ctx context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error
}

// OpsResponseRedactor затирает именованное поле в proto-marshalled success-response
// строки `operations`. Идемпотентно: повторный прогон на уже-затёртом поле — no-op.
type OpsResponseRedactor interface {
	RedactResponseField(ctx context.Context, opID string, fieldPath []string) error
}

// ───────────────── Issue use-case ─────────────────

// IssueUserTokenUseCase выпускает новый Hydra OAuth2-клиент + персистит маппинг.
type IssueUserTokenUseCase struct {
	repo    UserClientRepo
	tx      service.TxBeginner
	hydra   OAuthClientAdmin
	opsRepo operations.Repo
	// redactor для post-MarkDone private_key_pem-редакции. nil → редакция
	// пропускается (тест/legacy wiring). Прод main.go проводит pg-adapter, так что
	// секрет заменяется на `"<redacted>"` после первого polling'а клиента.
	redactor OpsResponseRedactor
	// audit — durable audit_outbox emitter. nil → без audit-строки.
	audit auditEmitter
	now   func() time.Time
	// logger — поверхность для сбоев detached redaction-goroutine.
	logger *slog.Logger
	// redactGrace — задержка между тем как Operation стал Done, и затиранием
	// одноразового private_key_pem. Даёт поллящему клиенту окно. 0 → без окна.
	redactGrace time.Duration

	// HydraClientNamePrefix — используется для сборки Hydra `client_name`
	// (default "kacho-usr-<userID>"). Конфигурируется через env на wire-time.
	HydraClientNamePrefix string
	// DefaultScope — scope, выдаваемый выпущенным токенам (default пусто).
	DefaultScope string
	// AudiencePrefix — добавляется с `/<userID>` как Hydra audience.
	AudiencePrefix string
}

// WithResponseRedactor проводит post-Issue секрет-редактор.
func (u *IssueUserTokenUseCase) WithResponseRedactor(r OpsResponseRedactor) *IssueUserTokenUseCase {
	u.redactor = r
	return u
}

// WithAuditEmitter проводит durable audit_outbox emitter. Composition-root only.
func (u *IssueUserTokenUseCase) WithAuditEmitter(a auditEmitter) *IssueUserTokenUseCase {
	u.audit = a
	return u
}

// WithLogger проводит logger detached redaction-goroutine.
func (u *IssueUserTokenUseCase) WithLogger(l *slog.Logger) *IssueUserTokenUseCase {
	u.logger = l
	return u
}

// WithRedactGrace задаёт grace-окно между Done-ом Operation и затиранием
// одноразового private_key_pem. Composition-root передаёт значение из конфига
// (KACHO_IAM_USERTOKEN_REDACT_GRACE, дефолт 120s); нулевое/отрицательное — «без окна».
func (u *IssueUserTokenUseCase) WithRedactGrace(d time.Duration) *IssueUserTokenUseCase {
	u.redactGrace = d
	return u
}

// NewIssueUserTokenUseCase конструирует.
func NewIssueUserTokenUseCase(r UserClientRepo, tx service.TxBeginner, h OAuthClientAdmin, ops operations.Repo) *IssueUserTokenUseCase {
	return &IssueUserTokenUseCase{
		repo:                  r,
		tx:                    tx,
		hydra:                 h,
		opsRepo:               ops,
		now:                   time.Now,
		HydraClientNamePrefix: "kacho-usr-",
	}
}

// IssueInput — sanitized.
type IssueInput struct {
	UserID          domain.UserID
	Description     string
	TTLSeconds      int64
	CreatedByUserID string

	// Name — человекочитаемое имя токена (create-only, immutable). Пусто → "".
	Name string
	// Labels — произвольные метки токена (create-only, immutable). Пусто → {}.
	Labels domain.Labels
}

// Execute возвращает стартованную Operation.
func (u *IssueUserTokenUseCase) Execute(ctx context.Context, in IssueInput) (*operations.Operation, error) {
	if in.UserID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if !strings.HasPrefix(string(in.UserID), domain.PrefixUser) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user id '%s'", in.UserID)
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
	if err := domain.OAuthClientName(in.Name).Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := in.Labels.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Резолвим account владельца, чтобы Operation-метаданные несли account_id —
	// иначе account-scoped /iam/operations исключает token-операции.
	accountID, err := u.repo.AccountForUser(ctx, in.UserID)
	if err != nil {
		return nil, mapPGErr(err)
	}

	tokenID := domain.UserOAuthClientID(ids.NewID(domain.PrefixUserOAuthClient))
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Issue user token for %s", in.UserID),
		&iamv1.IssueUserTokenMetadata{
			UserId:    string(in.UserID),
			KeyId:     string(tokenID),
			AccountId: string(accountID),
		},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	// Захватываем верифицированный принципал СИНХРОННО (до spawn'а worker-goroutine)
	// — audit-actor обязан быть аутентифицированным принципалом (anti-spoofing),
	// никогда полем тела запроса.
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		resp, derr := u.doIssue(ctx, tokenID, in, actor)
		// Планируем post-completion редакцию: worker сейчас вызовет MarkDone(opID,
		// resp) с plaintext private_key_pem; после этого мы заменяем поле секрета
		// in-place одним UPDATE на строке operations (идемпотентно). Goroutine
		// переживает request-scoped ctx (клиент уже получил Operation-конверт).
		if derr == nil && u.redactor != nil {
			go u.scheduleSecretRedact(ctx, op.ID) // #nosec G118 -- deliberate lifetime detach (baggage preserved via WithoutCancel; see scheduleSecretRedact).
		}
		return resp, derr
	})
	return &op, nil
}

// redactCtxMargin — запас поверх grace-окна для ctx-таймаута redact-goroutine.
const redactCtxMargin = 10 * time.Second

// scheduleSecretRedact дожидается Done, выдерживает grace-окно, затем одним UPDATE
// заменяет `response.private_key_pem` на `"<redacted>"`. Grace-окно даёт поллящему
// клиенту время прочитать одноразовый ключ ДО затирания.
func (u *IssueUserTokenUseCase) scheduleSecretRedact(callerCtx context.Context, opID string) {
	// recover-guard: goroutine детачена от запроса, неперехваченная паника убила бы
	// весь IAM-процесс (он на critical path каждого InternalIAMService.Check).
	defer func() {
		if r := recover(); r != nil && u.logger != nil {
			u.logger.Error("user-token secret redaction panicked — key material may remain in the operation response",
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
	// Detach от cancellation вызывающего (редакция обязана пережить request-scoped
	// ctx), но СОХРАНИТЬ trace/request-id/slog baggage через WithoutCancel.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), grace+redactCtxMargin)
	defer cancel()

	if !u.awaitOpDone(ctx, opID) {
		return // причина уже залогирована внутри awaitOpDone
	}

	if grace > 0 {
		select {
		case <-time.After(grace):
		case <-ctx.Done():
			if u.logger != nil {
				u.logger.WarnContext(ctx, "user-token secret redaction ctx expired during the grace window — key material may remain",
					slog.String("operation_id", opID))
			}
			return
		}
	}

	u.redactSecretFields(ctx, opID)
}

// awaitOpDone поллит операцию, пока она не станет Done. Bounded: 100 попыток по 20ms.
func (u *IssueUserTokenUseCase) awaitOpDone(ctx context.Context, opID string) bool {
	for attempt := 0; attempt < 100; attempt++ {
		op, err := u.opsRepo.Get(ctx, opID)
		if err == nil && op != nil && op.Done {
			return true
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			if u.logger != nil {
				u.logger.WarnContext(ctx, "user-token secret redaction gave up before the operation completed — key material may remain",
					slog.String("operation_id", opID))
			}
			return false
		}
	}
	if u.logger != nil {
		u.logger.WarnContext(ctx, "user-token secret redaction exhausted retries before the operation completed — key material may remain",
			slog.String("operation_id", opID))
	}
	return false
}

// redactSecretFields затирает одноразовый private_key_pem одним UPDATE; idempotent.
func (u *IssueUserTokenUseCase) redactSecretFields(ctx context.Context, opID string) {
	if rerr := u.redactor.RedactResponseField(ctx, opID,
		[]string{"private_key_pem"}); rerr != nil && u.logger != nil {
		u.logger.ErrorContext(ctx, "user-token private_key_pem redaction failed — plaintext key may remain in the operation response",
			slog.String("operation_id", opID), slog.Any("err", rerr))
	}
}

// doIssue — mint ECDSA P-256 keypair, регистрирует Hydra-клиент с private_key_jwt +
// embedded JWK, персистит маппинг с PublicKeyPEM + KeyAlgorithm, возвращает
// PrivateKeyPEM ровно один раз.
func (u *IssueUserTokenUseCase) doIssue(ctx context.Context, tokenID domain.UserOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	// 1. Mint ECDSA P-256 keypair локально. JWK `kid` — id kacho-iam
	//    UserOAuthClient'а (`uoc_*`), так что caller→Hydra assertion'ы
	//    self-describing.
	key, err := generateES256Key(string(tokenID))
	if err != nil {
		return nil, fmt.Errorf("generate user token keypair: %w", err)
	}

	// 2. Регистрируем OAuth2-клиент в Hydra с private_key_jwt + публичным JWK.
	//    Hydra не возвращает client_secret. `owner=<user_id>` — так token-hook
	//    маппит минтованный токен на принципал `user:<user_id>`.
	clientName := u.HydraClientNamePrefix + string(in.UserID)
	// #nosec G101 -- "client_credentials" — OAuth2 grant-type идентификатор (RFC 6749 §4.4),
	// не credential. То же для "private_key_jwt" (RFC 7521 client_assertion_type).
	hydraReq := clients.CreateOAuthClientRequest{
		ClientName:              clientName,
		Owner:                   string(in.UserID),
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
		return nil, fmt.Errorf("%w: hydra create-client: %w", iamerr.ErrUnavailable, err)
	}

	// 3. Персистим маппинг-строку в TX.
	row := domain.UserOAuthClient{
		ID:              tokenID,
		UserID:          in.UserID,
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

	// 4. Строим response — возвращаем ПРИВАТНЫЙ PEM + kid ОДИН РАЗ.
	pbToken, err := userTokenToProto(persisted)
	if err != nil {
		return nil, err
	}
	resp := &iamv1.IssueUserTokenResponse{
		Token:         pbToken,
		ClientId:      hydraClient.ClientID,
		PrivateKeyPem: key.PrivatePEM,
		PublicKeyPem:  key.PublicPEM,
		Algorithm:     key.Algorithm,
		KeyId:         string(tokenID),
	}
	return anypb.New(resp)
}

// resolveAudience выводит Hydra `audience` для нового токена. Пусто → kacho-internal
// audience `<prefix>/user/<userID>` (если AudiencePrefix задан), иначе nil.
func (u *IssueUserTokenUseCase) resolveAudience(in IssueInput) []string {
	if u.AudiencePrefix != "" {
		return []string{strings.TrimRight(u.AudiencePrefix, "/") + "/user/" + string(in.UserID)}
	}
	return nil
}

// commitMapping персистит маппинг-строку в свежей tx, откатывает + удаляет
// Hydra-клиент на сбое. Durable iam.user_token.issued audit_outbox-строка эмитится в
// ТОЙ ЖЕ tx, что Insert (атомарно, запрет #10): audit-строка коммитится iff маппинг
// коммитится. Hydra-клиент создан ДО этой tx (external side-effect) и откатывается
// через DeleteOAuthClient.
func (u *IssueUserTokenUseCase) commitMapping(ctx context.Context, row domain.UserOAuthClient, hydraClientID, actor, keyAlgorithm string) (domain.UserOAuthClient, error) {
	// cleanupCtx — detached от cancellation вызывающего (Hydra-rollback обязан
	// исполниться даже при отменённом request ctx), но СОХРАНЯЕТ baggage. Bounded.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cleanupCancel()

	tx, err := u.tx.Begin(ctx)
	if err != nil {
		_ = u.hydra.DeleteOAuthClient(cleanupCtx, hydraClientID)
		return domain.UserOAuthClient{}, mapPGErr(err)
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
		return domain.UserOAuthClient{}, mapPGErr(err)
	}
	// Durable audit-строка в ТОЙ ЖЕ tx (атомарно с Insert). Payload несёт только
	// не-секретные идентификаторы (нет key material).
	if u.audit != nil {
		if aerr := u.audit.EmitTx(ctx, tx, service.AuditEvent{
			EventType:       auditEventUserTokenIssued,
			TenantAccountID: "",
			Payload: userTokenAuditPayload(
				actor, string(row.UserID), string(persisted.ID), keyAlgorithm),
		}); aerr != nil {
			return domain.UserOAuthClient{}, mapPGErr(aerr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.UserOAuthClient{}, mapPGErr(err)
	}
	committed = true
	return persisted, nil
}

// ───────────────── Revoke use-case ─────────────────

// RevokeUserTokenUseCase удаляет и kacho-iam маппинг-строку, и Hydra OAuth2-клиента.
type RevokeUserTokenUseCase struct {
	repo    UserClientRepo
	tx      service.TxBeginner
	hydra   OAuthClientAdmin
	opsRepo operations.Repo
	audit   auditEmitter
	// logger — surfaces the post-commit Hydra orphan-cleanup warning.
	// nil → skipped (degraded wiring).
	logger *slog.Logger
}

// NewRevokeUserTokenUseCase конструирует.
func NewRevokeUserTokenUseCase(r UserClientRepo, tx service.TxBeginner, h OAuthClientAdmin, ops operations.Repo) *RevokeUserTokenUseCase {
	return &RevokeUserTokenUseCase{repo: r, tx: tx, hydra: h, opsRepo: ops}
}

// WithAuditEmitter проводит durable audit_outbox emitter. Composition-root only.
func (u *RevokeUserTokenUseCase) WithAuditEmitter(a auditEmitter) *RevokeUserTokenUseCase {
	u.audit = a
	return u
}

// WithLogger wires the logger used to surface the post-commit Hydra
// orphan-cleanup warning. Composition-root only; returns the receiver.
func (u *RevokeUserTokenUseCase) WithLogger(l *slog.Logger) *RevokeUserTokenUseCase {
	u.logger = l
	return u
}

// RevokeInput — sanitized.
type RevokeInput struct {
	UserID  domain.UserID
	TokenID domain.UserOAuthClientID
}

// Execute возвращает стартованную Operation.
func (u *RevokeUserTokenUseCase) Execute(ctx context.Context, in RevokeInput) (*operations.Operation, error) {
	if in.UserID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if in.TokenID == "" {
		return nil, status.Error(codes.InvalidArgument, "token_id required")
	}
	// Резолвим account владельца, чтобы Operation-метаданные несли account_id —
	// иначе account-scoped /iam/operations исключает token-операции.
	accountID, err := u.repo.AccountForUser(ctx, in.UserID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke user token %s", in.TokenID),
		&iamv1.RevokeUserTokenMetadata{
			UserId:    string(in.UserID),
			TokenId:   string(in.TokenID),
			AccountId: string(accountID),
		},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doRevoke(ctx, in, actor)
	})
	return &op, nil
}

func (u *RevokeUserTokenUseCase) doRevoke(ctx context.Context, in RevokeInput, actor string) (*anypb.Any, error) {
	cur, err := u.repo.Get(ctx, in.TokenID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	// Cross-user isolation — проверяем владение перед delete.
	if cur.UserID != in.UserID {
		return nil, status.Errorf(codes.NotFound, "UserToken %s not found for user %s", in.TokenID, in.UserID)
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
	if err := u.repo.DeleteByID(ctx, tx, in.TokenID); err != nil {
		return nil, mapPGErr(err)
	}
	// Durable iam.user_token.revoked audit-строка в ТОЙ ЖЕ tx, что маппинг-delete
	// (атомарно, запрет #10): нет key material в payload.
	if u.audit != nil {
		if aerr := u.audit.EmitTx(ctx, tx, service.AuditEvent{
			EventType:       auditEventUserTokenRevoked,
			TenantAccountID: "",
			Payload: userTokenAuditPayload(
				actor, string(cur.UserID), string(in.TokenID), cur.KeyAlgorithm),
		}); aerr != nil {
			return nil, mapPGErr(aerr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapPGErr(err)
	}
	committed = true
	// Delete из Hydra (idempotent — 404 OK).
	if err := u.hydra.DeleteOAuthClient(ctx, string(cur.OAuthClientID)); err != nil {
		if !errors.Is(err, clients.ErrHydraClientNotFound) {
			// DB-delete уже закоммичен; eventual-consistency — orphan подметёт
			// Hydra orphan-cleanup позже. Эмитим обещанное structured-warning
			// (было молча проглочено через `_ = err`, CWE-390), чтобы orphan был
			// наблюдаем и у sweep'а был сигнал; RPC остаётся успешным (non-fatal).
			if u.logger != nil {
				u.logger.WarnContext(ctx, "user-token hydra oauth-client delete failed after DB commit — orphaned client left for the cleanup worker",
					slog.String("oauth_client_id", string(cur.OAuthClientID)),
					slog.String("token_id", string(in.TokenID)),
					slog.String("err", err.Error()),
				)
			}
		}
	}
	resp := &iamv1.RevokeUserTokenResponse{
		TokenId:   string(in.TokenID),
		RevokedAt: timestamppb.Now(),
	}
	return anypb.New(resp)
}

// ───────────────── List use-case ─────────────────

// ListUserTokensUseCase — sync read.
type ListUserTokensUseCase struct {
	repo UserClientRepo
}

// NewListUserTokensUseCase конструирует.
func NewListUserTokensUseCase(r UserClientRepo) *ListUserTokensUseCase {
	return &ListUserTokensUseCase{repo: r}
}

// ListInput — sanitized.
type ListInput struct {
	UserID    domain.UserID
	PageSize  int32
	PageToken string
}

// Execute возвращает paged токены.
func (u *ListUserTokensUseCase) Execute(ctx context.Context, in ListInput) ([]domain.UserOAuthClient, string, error) {
	if in.UserID == "" {
		return nil, "", status.Error(codes.InvalidArgument, "user_id required")
	}
	return u.repo.List(ctx, in.UserID, in.PageToken, in.PageSize)
}

// ───────────────── helpers ─────────────────

// labelsFromProto конвертит protobuf-map меток в domain.Labels. nil/empty →
// пустая (non-nil) map (паритет с account/project/group).
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

// labelsToProto конвертит domain.Labels в protobuf-map меток. nil/empty → nil.
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

func userTokenToProto(c domain.UserOAuthClient) (*iamv1.UserOAuthClient, error) {
	pb := &iamv1.UserOAuthClient{
		Id:              string(c.ID),
		UserId:          string(c.UserID),
		HydraClientId:   string(c.OAuthClientID),
		Description:     string(c.Description),
		CreatedByUserId: string(c.CreatedByUserID),
		PublicKeyPem:    c.PublicKeyPEM,
		KeyAlgorithm:    c.KeyAlgorithm,
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
	return status.Error(codes.Internal, "internal user token error")
}
