// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session_revocations — InternalSessionRevocationsService
// (kacho-only, gRPC port :9091).
//
// Ban #6 (Internal.* not on external endpoint): internal-only service. Registered
// ONLY on the internal listener (port 9091). gRPC-direct only.
//
// Revocation sources that drive Revoke:
//   - User-initiated logout (api-gateway OAuth2 logout handler — fronts Revoke).
//   - Admin force-logout (InternalIAMService.ForceLogout — uses the same writer).
//   - Back-channel logout from Hydra.
//
// Methods:
//   - Revoke    — async (Operation): write a session_revocations row, NOTIFY.
//   - IsRevoked — sync lookup, и её ЧИТАЮТ НА ПУТИ ЗАПРОСА (#1122): клиент края
//     спрашивает её на каждом предъявлении удостоверения. Разбор дерева и
//     согласие этой шапки с ним держит гейт `is_revoked_doc_test.go`.
//   - ListByUser— sync admin/audit enumeration.
//
// Why this exists: before this handler the api-gateway logout called Revoke but
// kacho-iam never registered the service → codes.Unimplemented → token
// revocation was INERT. Регистрация закрыла первую половину, ЭНФОРСМЕНТ —
// вторую, и он появился позже: до #1122 запись писалась и читалась только
// административными путями.
//
// ЧТО ИЗ ЭТОГО СЛЕДУЕТ СЕГОДНЯ. Второе действие выхода — снятие сессии входа у
// провайдера — уже выданный токен НЕ гасит: проба
// `services/iam/scripts/provider-revocation-equivalence-probe.sh` на той же
// версии провайдера, что на стенде, с контролями в обе стороны (запись 15 в
// `docs/engineering/architecture/known-divergences.md`). Поэтому выход с
// `revoke_all=false` обеспечен ИМЕННО ЭТОЙ полосой: край спрашивает наш
// источник ПЕРВЫМ и только затем провайдера (`middleware.LocalThenProviderRevocation`),
// fail-closed на недоступности. `revoke_all=true` обеспечен вторым механизмом
// (user-level cutoff, его энфорсит refresh-хук).
package session_revocations

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/pkg/safeconv"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// revoker — narrow write port. Implemented by
// *RevokeUseCase. Kept as an interface so the handler is mock-testable.
type revoker interface {
	Execute(ctx context.Context, in RevokeInput) (*operationpb.Operation, error)
}

// reader — narrow read port (CQRS-split). Implemented by an adapter over the
// SessionRevocationRepo (pool-scoped). nil when the read stack is not wired —
// IsRevoked / ListByUser then fail-closed Unavailable.
type reader interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
	GetByJTI(ctx context.Context, jti string) (domain.SessionRevocation, error)
	// ListByUser returns ONE page of the user's revocations plus the token that
	// continues the walk (empty ⇒ the history is exhausted). The cursor is part
	// of the port because an audit enumeration that cannot be continued reports
	// a prefix of the history as the whole of it.
	ListByUser(ctx context.Context, userID string, pageSize int32, pageToken string) ([]domain.SessionRevocation, string, error)
}

// Handler — gRPC server for InternalSessionRevocationsService.
type Handler struct {
	iamv1.UnimplementedInternalSessionRevocationsServiceServer

	revoke revoker
	read   reader
	// relations — the relation-Check port deciding whether the caller may read
	// the user NAMED IN THE REQUEST. See ListByUser.
	relations authzguard.RelationChecker
	// cutoffs — читатель отсечки субъекта (`user_token_revocations`). Отдельный
	// от `read`: та таблица про удостоверение, эта про человека. См.
	// session_cutoff.go.
	cutoffs cutoffReader
}

// NewHandler — builder. `revoke` carries the RevokeUseCase; `read` is the
// read-side adapter (may be nil in degraded/dev — reads then fail-closed).
func NewHandler(revoke revoker, read reader) *Handler {
	return &Handler{revoke: revoke, read: read}
}

// WithRelationStore wires the relation-Check port ListByUser authorizes against.
func (h *Handler) WithRelationStore(relations authzguard.RelationChecker) *Handler {
	h.relations = relations
	return h
}

// Revoke — record a token revocation. Async per the proto envelope: the row is
// written synchronously inside the use-case and an Operation (done=true) is
// returned. Idempotent on token_jti (ON CONFLICT DO UPDATE in the repo).
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeRequest) (*operationpb.Operation, error) {
	if strings.TrimSpace(req.GetUserId()) == "" {
		return nil, shared.InvalidArg("user_id", "required")
	}
	// Without a jti AND without the bulk flag there is nothing to revoke.
	if strings.TrimSpace(req.GetTokenJti()) == "" && !req.GetRevokeAllUserTokens() {
		return nil, shared.InvalidArg("token_jti",
			"required unless revoke_all_user_tokens is set")
	}
	if h.revoke == nil {
		return nil, status.Error(codes.Unavailable, "session revocation writer not configured")
	}

	var ttl *timestamppb.Timestamp
	if t := req.GetTtlExpiresAt(); t != nil {
		ttl = t
	}
	return h.revoke.Execute(ctx, RevokeInput{
		TokenJTI:            strings.TrimSpace(req.GetTokenJti()),
		UserID:              strings.TrimSpace(req.GetUserId()),
		Reason:              strings.TrimSpace(req.GetReason()),
		TTLExpiresAt:        ttl,
		RevokeAllUserTokens: req.GetRevokeAllUserTokens(),
	})
}

// IsRevoked — sync lookup. ВЫЗЫВАЮЩИХ В ПРОД-КОДЕ: 3.
//
// Двое внутренние (хендлер → читатель, адаптер → репозиторий), третий ВНЕШНИЙ и
// решает вопрос доступа: клиент края `gateway/internal/clients/session_revocations_client.go`
// экспонирует `IsSessionRevoked`, а тот провязан в слой аутентификации
// композиционным корнем края (`middleware.NewLocalThenProviderRevocation`).
// Значит НАШ отзыв участвует в решении на пути запроса, а не только в
// административных перечнях.
//
// ЗДЕСЬ СТОЯЛО «ВЫЗЫВАЮЩЕГО НЕТ» (#797) — утверждение пережило свой предмет:
// провязка края появилась позже (#1122), а шапку не тронули (#1156). Это не
// косметика. Комментарий, отрицающий живой контроль безопасности, провоцирует
// «починку» кода под неверный комментарий: следующий читатель вправе счесть
// полосу мёртвой и снять её. Число выше поэтому сверяется с деревом гейтом
// `is_revoked_doc_test.go` — разбором узлов вызова, а не поиском по тексту.
//
// refresh-хук сюда по-прежнему не приходит: пер-jti гейта он не несёт и прямо
// это оговаривает — в его теле нет claims предъявленного токена.
//
// fail-closed Unavailable when the read stack is unwired.
func (h *Handler) IsRevoked(ctx context.Context, req *iamv1.IsRevokedRequest) (*iamv1.IsRevokedResponse, error) {
	jti := strings.TrimSpace(req.GetTokenJti())
	if jti == "" {
		return nil, shared.InvalidArg("token_jti", "required")
	}
	if h.read == nil {
		return nil, status.Error(codes.Unavailable, "session revocation reader not configured")
	}
	revoked, err := h.read.IsRevoked(ctx, jti)
	if err != nil {
		return nil, status.Error(codes.Internal, "session revocation lookup failed")
	}
	resp := &iamv1.IsRevokedResponse{Revoked: revoked}
	if revoked {
		// Best-effort enrichment of revoked_at / reason; a lookup miss here is
		// not fatal — the boolean is the contract.
		if rev, gerr := h.read.GetByJTI(ctx, jti); gerr == nil {
			resp.RevokedAt = shared.TimestampProto(rev.RevokedAt)
			resp.Reason = rev.Reason
		}
	}
	return resp, nil
}

// ListByUser — sync admin/audit enumeration of active revocations for a user,
// cursor-paged.
//
// Page format is validated FIRST, before anything can short-circuit: a page_size
// outside [0..1000] and a page_token that does not decode are the caller's
// errors and are REJECTED (INVALID_ARGUMENT), never clamped or ignored. Both
// silent forms tell the same lie — a short page that reads as a complete audit —
// and an ignored cursor additionally re-serves page one under a token the caller
// believes advances. The repo re-checks both as the authoritative backstop; this
// gate makes the answer deterministic regardless of wiring.
//
// The caller NAMES the user whose history this returns, so the read is then
// authorized against that user — see authorizeListByUser for the predicate and
// for why the interceptors in front of this RPC do not supply it. The decision
// runs BEFORE the store is touched: a refusal that has already read the rows has
// paid for the answer it claims to withhold.
func (h *Handler) ListByUser(ctx context.Context, req *iamv1.ListByUserRequest) (*iamv1.ListByUserResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, shared.InvalidArg("user_id", "required")
	}
	if _, err := corevalidate.PageSize("page_size", req.GetPageSize()); err != nil {
		return nil, err
	}
	if err := shared.ValidatePageToken("page_token", req.GetPageToken()); err != nil {
		return nil, err
	}
	if err := authorizeListByUser(ctx, h.relations, userID); err != nil {
		return nil, err
	}
	if h.read == nil {
		return nil, status.Error(codes.Unavailable, "session revocation reader not configured")
	}
	// 0 is forwarded as 0 so the store applies its own documented default (100).
	rows, next, err := h.read.ListByUser(ctx, userID,
		safeconv.ClampNonNegInt32(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		// A page the store rejected keeps its classification; anything else is a
		// store failure and gets the fixed text (no pgx/SQL leak).
		if mapped := shared.MapRepoErr(err); status.Code(mapped) == codes.InvalidArgument {
			return nil, mapped
		}
		return nil, status.Error(codes.Internal, "session revocation list failed")
	}
	resp := &iamv1.ListByUserResponse{NextPageToken: next}
	for _, r := range rows {
		resp.Revocations = append(resp.Revocations, toProto(r))
	}
	return resp, nil
}

// toProto maps a domain SessionRevocation to the wire message.
func toProto(r domain.SessionRevocation) *iamv1.SessionRevocation {
	out := &iamv1.SessionRevocation{
		TokenJti: r.TokenJTI,
		UserId:   string(r.UserID),
		Reason:   r.Reason,
	}
	if !r.RevokedAt.IsZero() {
		out.RevokedAt = shared.TimestampProto(r.RevokedAt)
	}
	if !r.TTLExpiresAt.IsZero() {
		out.TtlExpiresAt = shared.TimestampProto(r.TTLExpiresAt)
	}
	return out
}
