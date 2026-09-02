// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package user_tokens — use-cases UserTokenService (персональные access-токены
// пользователя, поток private_key_jwt).
//
// # Зеркала у внешнего поставщика здесь НЕТ (задача #1121, подфаза Ф4б-3)
//
// Выдача не заводит клиента у внешнего поставщика, а отзыв его не снимает.
// Клиентом это удостоверение называется по идентификатору СВОЕЙ строки
// (`uoc…`): им подписывается `client_assertion`, и по нему же разрешает клиента
// наш реестр утверждений — зеркальная колонка на этом пути не участвует вовсе
// (см. repo/kacho/pg.AssertionClientRepo). Второе имя, которое прежде приезжало
// от поставщика, вызывающему выдавалось в поле `client_id` ответа и нашим
// издателем не разрешалось НИ ПРИ КАКОМ входе.
//
// ОКНО ДВУХ ИЗДАТЕЛЕЙ НАЗВАНО СРОКОМ УЖЕ ВЫДАННЫХ ТОКЕНОВ. Строки прежнего
// выпуска своё зеркало сохраняют, и токены, отчеканенные для них поставщиком,
// действительны до собственного истечения — платформа их не отзывает и отозвать
// не может. Остаток окна СЧИТАЕТСЯ, а не оценивается:
//
//	SELECT count(*) FROM kacho_iam.user_oauth_clients WHERE hydra_client_id IS NOT NULL;
//
// На Issue:
//
//  1. Генерируем пару ключей ECDSA P-256 локально; приватная половина НИКОГДА не
//     покидает response kacho-iam и НИКОГДА не хранится в БД.
//  2. Персистим строку `user_oauth_clients` (public PEM + algorithm; зеркало
//     поставщика пусто).
//  3. Возвращаем IssueUserTokenResponse с plaintext приватным PEM + kid в
//     `Operation.response` (одноразовая выдача; затирается post-completion
//     OpsResponseRedactor'ом, так что re-poll Operation.Get секрета не отдаёт).
//     `client_id` и `key_id` в ответе — ОДНО И ТО ЖЕ значение, идентификатор
//     строки реестра.
//
// На Revoke:
//
//  1. Fetch строки по id, scoped по user_id (cross-user isolation).
//  2. Delete строки. Отзыв доходит до ПРЕДЪЯВЛЕНИЯ схемой, а не вызовом наружу:
//     снятие строки порождает отсечку отчеканенного, ключуемую идентификатором
//     этой же строки (миграция 898002). Поэтому отзыв остаётся отзывом и при
//     недоступном, и при снятом поставщике.
//
// На List: paged read токенов своего User.
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
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
	Insert(ctx context.Context, tx service.Tx, c domain.UserOAuthClient) (domain.UserOAuthClient, error)
	// DeleteOwnedByID снимает строку удостоверения ОДНИМ оператором, суженным
	// владельцем, и возвращает снятую строку. found=false — законный исход:
	// строки нет ЛИБО она чужая, и эти случаи здесь неразличимы by construction
	// (см. реализацию и §«Скрытие существования» ниже, у doRevoke).
	DeleteOwnedByID(ctx context.Context, tx service.Tx, ownerID domain.UserID, id domain.UserOAuthClientID) (domain.UserOAuthClient, bool, error)
	List(ctx context.Context, userID domain.UserID, pageToken string, pageSize int32) ([]domain.UserOAuthClient, string, error)
	// AccountForUser резолвит account владельца-User, чтобы Issue/Revoke стемпили
	// `account_id` на Operation-метаданных (account-scoped /iam/operations feed),
	// и состояние, разрешающее ему аутентифицироваться.
	//
	// Состояние возвращается ВМЕСТЕ с account'ом, а не отдельным вызовом: иначе
	// решение принимается по полю, которое запрос мог не загрузить — ровно тот
	// дефект, ради которого эта сигнатура так выглядит.
	//
	// Нет User → ErrNotFound.
	AccountForUser(ctx context.Context, id domain.UserID) (domain.AccountID, bool, error)
}

// OpsResponseRedactor затирает именованное поле в proto-marshalled success-response
// строки `operations`. Идемпотентно: повторный прогон на уже-затёртом поле — no-op.
type OpsResponseRedactor interface {
	RedactResponseField(ctx context.Context, opID string, fieldPath []string) error
}

// ───────────────── Issue use-case ─────────────────

// IssueUserTokenUseCase чеканит удостоверение и персистит его строку.
type IssueUserTokenUseCase struct {
	repo    UserClientRepo
	tx      service.TxBeginner
	opsRepo operations.Repo
	// redactor для post-MarkDone private_key_pem-редакции. nil → редакция
	// пропускается (тест/legacy wiring). Прод main.go проводит pg-adapter, так что
	// секрет ОЧИЩАЕТСЯ (поле сбрасывается в пустое) после первого polling'а клиента.
	redactor OpsResponseRedactor
	// audit — durable audit_outbox emitter. nil → без audit-строки.
	audit auditEmitter
	now   func() time.Time
	// logger — поверхность для сбоев detached redaction-goroutine.
	logger *slog.Logger
	// redactGrace — задержка между тем как Operation стал Done, и затиранием
	// одноразового private_key_pem. Даёт поллящему клиенту окно. 0 → без окна.
	redactGrace time.Duration
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
func NewIssueUserTokenUseCase(r UserClientRepo, tx service.TxBeginner, ops operations.Repo) *IssueUserTokenUseCase {
	return &IssueUserTokenUseCase{
		repo:    r,
		tx:      tx,
		opsRepo: ops,
		now:     time.Now,
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

	// CredentialKind — вид выдаваемого удостоверения. Не назван — сохраняется
	// прежнее поведение ДОСЛОВНО (KEYPAIR).
	CredentialKind domain.CredentialKind
}

// Execute возвращает стартованную Operation.
func (u *IssueUserTokenUseCase) Execute(ctx context.Context, in IssueInput) (*operations.Operation, error) {
	if in.UserID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	// Формат СВОЕГО идентификатора судит общая проверка, а не копия рядом
	// (задача #1791). Копия сверяла только префикс и потому принимала
	// обрезанный идентификатор, производя при этом ПОБАЙТОВО ТОТ ЖЕ отказ, —
	// расхождение было невидимо всякой пробе, сверяющей сообщение.
	if err := shared.ValidateResourceID(string(in.UserID), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	if in.CreatedByUserID == "" {
		return nil, status.Error(codes.InvalidArgument, "created_by_user_id required")
	}
	// DEFECT (b) / UTM-12: created_by MUST be a user principal. An SA caller
	// (`sva…`) is not a users(id) row → without this sync guard the async Insert
	// hits the created_by FK (23503) and surfaces as an opaque done+error code-9.
	// Reject SYNC with a clear message; the admin/seed path is
	// InternalUserTokenService.MintUserToken (#60), not this public RPC.
	if !strings.HasPrefix(in.CreatedByUserID, domain.PrefixUser) {
		return nil, status.Error(codes.InvalidArgument,
			"created_by_user_id must be a user principal")
	}
	if in.TTLSeconds < 0 {
		return nil, status.Error(codes.InvalidArgument, "ttl_seconds must be >= 0")
	}
	// Вид разрешается СИНХРОННО, до любой записи: у личности федеративного вида
	// нет by construction — в её контракте нет поля, которым он задаётся.
	kind, kerr := domain.ResolveIssuedKind(in.CredentialKind, false, false)
	if kerr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", kerr)
	}
	// Срок вида SECRET разрешается ТАМ ЖЕ и ТЕМ ЖЕ объявлением, что у второго
	// глагола выдачи: сверх потолка ОТВЕРГАЕТСЯ, а не урезается молча — иначе
	// вызывающий получает успех при неприменённом параметре.
	var secretTTL time.Duration
	if kind == domain.CredentialKindSecret {
		ttl, ok := tokenpolicy.ResolveSecretCredentialTTL(time.Duration(in.TTLSeconds) * time.Second)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"ttl_seconds: exceeds the %s ceiling of %d seconds for credential_kind SECRET",
				domain.CredentialKindSecret, int64(tokenpolicy.SecretCredentialTTLCeiling.Seconds()))
		}
		secretTTL = ttl
	}
	if len(in.Description) > 256 {
		return nil, status.Error(codes.InvalidArgument, "description too long (max 256)")
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

	// Резолвим account владельца, чтобы Operation-метаданные несли account_id —
	// иначе account-scoped /iam/operations исключает token-операции.
	accountID, mayAuthenticate, err := u.repo.AccountForUser(ctx, in.UserID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	// The hooks already refuse to mint a token for a user in this state. Issuing
	// them a NEW personal token is a separate act: the secret is handed over and
	// kept, and it starts working the day the account is unblocked — granted
	// while nobody was permitted to grant it. The state that decides is the
	// TOKEN OWNER's, not the caller's; otherwise the refusal has a documented
	// detour through anyone still able to ask.
	if !mayAuthenticate {
		return nil, status.Errorf(codes.FailedPrecondition,
			"User %s is not active and cannot be issued a token", in.UserID)
	}

	// DEFECT (b) / UTM-12: created_by existence — the own-DB created_by FK
	// precondition. Validate SYNC so a well-formed-but-unknown user fails
	// FAILED_PRECONDITION here, never as an async code-9. Skipped when created_by
	// == the target user (already resolved just above — the common self-issue path).
	//
	// state-not-consulted: здесь спрашивают только про существование строки под
	// внешним ключом. Автор не назывался вызывающим — handler подставляет
	// АУТЕНТИФИЦИРОВАННОГО принципала и отвергает несовпадающий created_by в
	// теле, поэтому состояние автора уже решено на входе: заблокированный сюда
	// не доходит.
	if in.CreatedByUserID != string(in.UserID) {
		if _, _, cerr := u.repo.AccountForUser(ctx, domain.UserID(in.CreatedByUserID)); cerr != nil {
			if errors.Is(cerr, iamerr.ErrNotFound) {
				return nil, status.Errorf(codes.FailedPrecondition,
					"created_by_user_id %s is not a known user", in.CreatedByUserID)
			}
			return nil, mapPGErr(cerr)
		}
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

	// Вид SECRET завершается НА ПУТИ ЗАПРОСА, и это не отступление от ban #9:
	// предмет мутации закоммичен, а `done` означает ровно это. Асинхронный путь
	// здесь невыразим — секрет показывается ОДИН РАЗ, и второго чтения у него
	// нет: строка операции его не несёт НИ В КАКОЙ МОМЕНТ (§4.3.1).
	if kind == domain.CredentialKindSecret {
		if err := u.issueSecretSync(ctx, &op, tokenID, in, actor, secretTTL); err != nil {
			return nil, err
		}
		return &op, nil
	}

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

// issueSecretSync чеканит базовый секрет, коммитит строку и разводит ДВА тела
// ответа: то, что уходит вызывающему, и то, что ложится в строку операции.
//
// РАЗВЕДЕНИЕ — НЕСУЩЕЕ, а не оптимизация. Рядом живёт отложенное стирание
// одноразового ключевого материала, и оно остаётся механизмом СУЩЕСТВУЮЩИХ
// видов. К секрету оно не годится by construction: величина отсрочки от
// нагрузки не зависит и сама себя не сокращает, то есть «показан один раз»
// стало бы означать «показан ещё столько-то». Здесь секрет в записываемое тело
// НЕ КЛАДЁТСЯ ВОВСЕ.
func (u *IssueUserTokenUseCase) issueSecretSync(
	ctx context.Context,
	op *operations.Operation,
	tokenID domain.UserOAuthClientID,
	in IssueInput,
	actor string,
	ttl time.Duration,
) error {
	// Тело для вызывающего живёт в ЗАМЫКАНИИ, а не в поле use-case: use-case
	// один на все запросы, и поле стало бы общим состоянием — секрет одного
	// вызывающего мог бы уйти другому.
	var shownAny *anypb.Any
	if err := operations.RunSync(ctx, u.opsRepo, op, func(ctx context.Context) (*anypb.Any, error) {
		secret, hash, err := credsecret.Mint(string(tokenID))
		if err != nil {
			// Сорванный источник случайности даёт ОТКАЗ, а не строку
			// предсказуемого вида: угадываемое удостоверение хуже отсутствующего.
			return nil, status.Error(codes.Internal, "credential minting failed")
		}
		expires := u.now().UTC().Add(ttl)
		row := domain.UserOAuthClient{
			ID:              tokenID,
			UserID:          in.UserID,
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
		pbToken, err := userTokenToProto(persisted)
		if err != nil {
			return nil, err
		}
		// Тело, которое ЛОЖИТСЯ В СТРОКУ операции: без поля секрета.
		stored := &iamv1.IssueUserTokenResponse{
			Token:    pbToken,
			ClientId: string(tokenID),
			KeyId:    string(tokenID),
		}
		storedAny, err := anypb.New(stored)
		if err != nil {
			return nil, err
		}
		// Тело, которое УХОДИТ ВЫЗЫВАЮЩЕМУ: то же самое плюс секрет. Оно
		// подменяется в памяти ПОСЛЕ того, как RunSync записал `stored`, —
		// поэтому в базу секрет не попадает ни одним путём, включая срыв
		// между записью и ответом.
		shown := proto.Clone(stored).(*iamv1.IssueUserTokenResponse)
		shown.Secret = secret
		shown2, err := anypb.New(shown)
		if err != nil {
			return nil, err
		}
		shownAny = shown2
		return storedAny, nil
	}); err != nil {
		return err
	}
	// Подмена ПОСЛЕ записи: в базе лежит тело без секрета, вызывающий получает
	// тело с секретом. Если операция завершилась ошибкой, подменять нечего.
	if shownAny != nil && op.Error == nil {
		op.Response = shownAny
	}
	return nil
}

// redactCtxMargin — запас поверх grace-окна для ctx-таймаута redact-goroutine.
const redactCtxMargin = 10 * time.Second

// scheduleSecretRedact дожидается Done, выдерживает grace-окно, затем одним UPDATE
// ОЧИЩАЕТ `response.private_key_pem` (поле сбрасывается в пустое; метки-заменителя
// нет). Grace-окно даёт поллящему
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
//
// РЕПЛИКИ: запрос — петля принадлежит ОДНОМУ запросу выдачи и ждёт исхода его же операции;
// у каждой реплики свои запросы.
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

// doIssue — чеканит пару ключей ECDSA P-256, персистит строку удостоверения с
// PublicKeyPEM + KeyAlgorithm, возвращает PrivateKeyPEM ровно один раз.
//
// Клиента у внешнего поставщика здесь НЕ заводится (#1121): удостоверение
// предъявляется НАШЕМУ издателю, а он разрешает клиента по идентификатору этой
// строки. Отсюда же следует, что у выдачи больше нет полусделанного состояния,
// компенсировать которое было бы нечем: единственный след — своя строка, и она
// либо закоммичена, либо откачена.
func (u *IssueUserTokenUseCase) doIssue(ctx context.Context, tokenID domain.UserOAuthClientID, in IssueInput, actor string) (*anypb.Any, error) {
	// 1. Mint ECDSA P-256 keypair локально. JWK `kid` — id строки реестра
	//    (`uoc…`), так что утверждения вызывающего self-describing.
	key, err := generateES256Key(string(tokenID))
	if err != nil {
		return nil, fmt.Errorf("generate user token keypair: %w", err)
	}

	// 2. Персистим строку удостоверения в TX. Зеркало поставщика ПУСТО, и
	//    пустое здесь означает ровно «регистрации у него нет».
	row := domain.UserOAuthClient{
		ID:              tokenID,
		UserID:          in.UserID,
		Description:     domain.Description(in.Description),
		CreatedByUserID: domain.UserID(in.CreatedByUserID),
		PublicKeyPEM:    key.PublicPEM,
		KeyAlgorithm:    key.Algorithm,
		Name:            domain.OAuthClientName(in.Name),
		Labels:          in.Labels,
		// Вид ЗАПИСЫВАЕТСЯ, а не вычисляется читателем.
		CredentialKind: domain.CredentialKindKeypair,
	}
	if in.TTLSeconds > 0 {
		t := u.now().Add(time.Duration(in.TTLSeconds) * time.Second)
		row.ExpiresAt = &t
	}
	persisted, err := u.commitMapping(ctx, row, actor, key.Algorithm)
	if err != nil {
		return nil, err
	}

	// 3. Строим response — возвращаем ПРИВАТНЫЙ PEM + kid ОДИН РАЗ.
	//
	//    `client_id` и `key_id` несут ОДНО значение — идентификатор строки
	//    реестра. Это не избыточность ответа, а его смысл: этим именем
	//    подписывается `client_assertion`, и только его разрешает наш издатель.
	pbToken, err := userTokenToProto(persisted)
	if err != nil {
		return nil, err
	}
	resp := &iamv1.IssueUserTokenResponse{
		Token:         pbToken,
		ClientId:      string(tokenID),
		PrivateKeyPem: key.PrivatePEM,
		PublicKeyPem:  key.PublicPEM,
		Algorithm:     key.Algorithm,
		KeyId:         string(tokenID),
	}
	return anypb.New(resp)
}

// commitMapping персистит строку удостоверения в свежей tx. Durable
// iam.user_token.issued audit_outbox-строка эмитится в ТОЙ ЖЕ tx, что Insert
// (атомарно, запрет #10): audit-строка коммитится iff строка коммитится.
func (u *IssueUserTokenUseCase) commitMapping(ctx context.Context, row domain.UserOAuthClient, actor, keyAlgorithm string) (domain.UserOAuthClient, error) {
	// Пустое имя до записи не доживает: оно означало «назови сам», и здесь, где
	// идентификатор уже назначен, его заменяет имя, производное от него (#1279).
	// Подстановка стоит в ОДНОЙ точке — той, через которую проходит КАЖДЫЙ вид
	// выпуска: рассыпанная по видам, она разошлась бы между ними молча.
	row.Name = domain.OAuthClientName(corevalidate.NameOrDefault(string(row.Name), string(row.ID)))

	tx, err := u.tx.Begin(ctx)
	if err != nil {
		return domain.UserOAuthClient{}, mapPGErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
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

// RevokeUserTokenUseCase снимает строку удостоверения.
//
// Наружу отзыв не ходит, и это не упрощение: отзыв доходит до ПРЕДЪЯВЛЕНИЯ
// схемой. Снятие строки порождает отсечку отчеканенного, ключуемую
// идентификатором этой же строки (миграция 898002), поэтому отозванное перестаёт
// проходить независимо от доступности — и от существования — внешнего поставщика.
type RevokeUserTokenUseCase struct {
	repo    UserClientRepo
	tx      service.TxBeginner
	opsRepo operations.Repo
	audit   auditEmitter
}

// NewRevokeUserTokenUseCase конструирует.
func NewRevokeUserTokenUseCase(r UserClientRepo, tx service.TxBeginner, ops operations.Repo) *RevokeUserTokenUseCase {
	return &RevokeUserTokenUseCase{repo: r, tx: tx, opsRepo: ops}
}

// WithAuditEmitter проводит durable audit_outbox emitter. Composition-root only.
func (u *RevokeUserTokenUseCase) WithAuditEmitter(a auditEmitter) *RevokeUserTokenUseCase {
	u.audit = a
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
	// state-not-consulted: отзыв — уборка за собой, а не аутентификация.
	// Состояние владельца запрещает ВХОД; читать его здесь значило бы сделать
	// «заблокировать пользователя» и «отозвать его живые токены»
	// взаимоисключающими, то есть оставить учётные данные там, где их нужнее
	// всего снять.
	accountID, _, err := u.repo.AccountForUser(ctx, in.UserID)
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

// doRevoke снимает удостоверение и ИДЕМПОТЕНТЕН: повторный отзыв, отзыв
// никогда не существовавшего и отзыв ЧУЖОГО удостоверения дают один и тот же
// исход — успех, при котором ничего не снято.
//
// Почему это ОДИН исход, а не три. Приёмка базового токена (BAT-1-44) требует,
// чтобы повторный отзыв отвечал успехом. Скрытие существования (security.md
// §Hardening #6) требует, чтобы отказ по чужому удостоверению был неотличим от
// промаха. Эти два требования тянут в разные стороны ровно до тех пор, пока
// исходов больше одного: как только «уже отозвано» отвечает успехом, а «чужое»
// отказом, вызывающий узнаёт по различию, существует ли ЧУЖОЕ удостоверение —
// то есть добивавшись идемпотентности, мы бы завели оракул.
//
// Разрешено это не подгонкой текстов друг под друга, а снятием ветки: владение
// стоит в самом операторе снятия (`WHERE id AND user_id`), поэтому места, где
// «чужое» и «нет такого» могли бы разойтись, в коде НЕТ. Строка чужого
// владельца при этом переживает вызов — успех означает «в пространстве
// вызывающего такого удостоверения нет», а не право снять чужое.
//
// Право распоряжаться удостоверениями ИМЕННО ЭТОГО человека проверено на крае
// до вызова: `scope_extractor` берёт объект `iam_user` из поля `user_id`
// (user_token_service.proto). Идентификатор удостоверения край не проверяет —
// его и сужает оператор ниже.
func (u *RevokeUserTokenUseCase) doRevoke(ctx context.Context, in RevokeInput, actor string) (*anypb.Any, error) {
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
	cur, found, err := u.repo.DeleteOwnedByID(ctx, tx, in.UserID, in.TokenID)
	if err != nil {
		return nil, mapPGErr(err)
	}
	if !found {
		// Снимать было нечего. Транзакция откатывается (снятого нет, писать
		// нечего), audit не эмитится — события без изменения состояния не
		// бывает, — и ответ ниже собирается тот же, что на успешном снятии.
		return revokeUserTokenResponse(in.TokenID)
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
	// Наружу отсюда не ходят. Отзыв состоялся тем, что учётные данные перестали
	// работать, и держится это ДВУМЯ следствиями снятия строки, ни одно из
	// которых не зависит от внешнего поставщика:
	//
	//   - новое этим удостоверением не выпустить: реестр утверждений разрешает
	//     клиента по строке, а строки больше нет;
	//   - уже отчеканенное отсечено: снятие строки порождает отсечку с ключом
	//     `id` этой строки, и авторитет отзыва читает её НА ПРЕДЪЯВЛЕНИИ
	//     (миграция 898002).
	//
	// Строка ПРЕЖНЕГО выпуска несёт зеркало, и его регистрация у поставщика эту
	// строку переживает. Снимать её отсюда больше не пытаемся: клиент, чьей
	// строки нет, не резолвится ни в один принципал, поэтому получить у
	// поставщика новый токен им нельзя — остаётся гигиена инвентаря, а не
	// безопасность, и уходит она вместе с самим поставщиком (подфазы #1123/#1125).
	// Чего отзыв не делает — не отзывает уже выданное ПОСТАВЩИКОМ: такой токен
	// самодостаточен и живёт до своего истечения. Это и есть окно двух издателей,
	// и величина у него одна — срок уже выданных токенов.
	return revokeUserTokenResponse(in.TokenID)
}

// revokeUserTokenResponse — ЕДИНСТВЕННЫЙ производитель тела успешного отзыва.
//
// Производитель один намеренно. Два места, собирающих ответ, разошлись бы на
// первой же правке — и разошлись бы ровно там, где расхождение и опасно: по
// различию тел вызывающий узнавал бы, сняли ли что-нибудь на самом деле, то
// есть существует ли удостоверение. Отметка времени проставляется ВСЕГДА по
// той же причине: пустая отметка на безрезультатном отзыве читается прямо из
// тела как «снимать было нечего».
func revokeUserTokenResponse(tokenID domain.UserOAuthClientID) (*anypb.Any, error) {
	return anypb.New(&iamv1.RevokeUserTokenResponse{
		TokenId:   string(tokenID),
		RevokedAt: timestamppb.Now(),
	})
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

// credentialKindToProto — отображение вида домена в вид контракта. Объявлено
// ОДНИМ местом на сервис: второе отображение разошлось бы с первым молча.
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
	return status.Error(codes.Internal, "internal user token error")
}
