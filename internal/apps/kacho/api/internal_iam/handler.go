// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package internal_iam — InternalIAMService (kacho-only, gRPC port :9091).
//
// Ban #6 (Internal.* не публикуется на external endpoint): internal-only сервис.
// Регистрируется ТОЛЬКО на internal listener (port 9091).
//
// Инвариант — INTERNAL-ONLY, а не «только gRPC». LookupSubject и Check несут
// http-аннотации, и api-gateway заводит им REST-маршруты на СВОЁМ внутреннем mux
// (`/iam/v1/internal/iam:{lookupSubject,check}`); на внешний listener они не
// выходят. Сам gateway ходит сюда gRPC-direct — чтобы его auth-интерсептор не
// рекурсировал через собственную цепочку (loop-prevention), а не потому что
// маршрута нет.
//
// Методы:
//   - LookupSubject(by external_id|id|email) — для auth-interceptor api-gateway
//     после валидации JWT (Ory Hydra).
//   - Check — single-tuple authorization gate; delegate к AuthorizeService.
//     Вызывается per-RPC authz-interceptor'ами
//     kacho-vpc / kacho-compute / kacho-loadbalancer.
package internal_iam

import (
	"context"
	stderrors "errors"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho/pkg/authz/proxytuple"
	"github.com/PRO-Robotech/kacho/pkg/subjectchange"
)

// Authorizer — narrow port-iface over service.AuthorizeService, exposing only
// the relation-native check the InternalIAMService gate needs (narrow port).
// Implemented by *service.AuthorizeService directly, or by
// the metrics-instrumented decorator (*metrics.InstrumentedAuthorizer) wired in
// the composition root. Exported so the composition root can name it when
// selecting between the plain and instrumented variant.
type Authorizer interface {
	CheckRelation(ctx context.Context, req service.CheckRelationRequest) (*service.CheckResult, error)
}

// subjectChanger — narrow port-iface over service.SubjectChangeService,
// exposing only the PollSubjectChanges use-case (narrow port). Implemented by
// *service.SubjectChangeService.
type subjectChanger interface {
	PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) ([]service.SubjectChange, int64, error)
}

// relationWriteGate — narrow authz port for the resource-registration RPCs.
// Authorize resolves the mTLS client-cert→SA identity and
// ReBAC-checks `fga_writer` on `cluster:cluster_kacho_root` (#914). Implemented by
// *authzguard.RelationWriteGate.
type relationWriteGate interface {
	Authorize(ctx context.Context) (callerDomain string, err error)
}

// resourceRegistrar — narrow use-case port for RegisterResource /
// UnregisterResource. Implemented by *RegisterResourceUseCase. Register
// consumes the mirror fields (labels + parent-scope) + the hardening
// source_version via registerInput; Unregister consumes the tuple + the
// tombstone source_version via unregisterInput (mirror row removed by PK,
// conditionally on the tombstone-version).
type resourceRegistrar interface {
	Register(ctx context.Context, in registerInput) error
	Unregister(ctx context.Context, in unregisterInput) error
}

// roleCompiledReader — narrow read port returning a Role's compiled permission
// projection (redesign-2026 F5 GetRoleCompiled). Implemented by
// *role.GetRoleCompiledUseCase, wired in the composition root. nil → the RPC fails
// closed (Unavailable). Errors (malformed id → InvalidArgument, missing → NotFound)
// are already gRPC-status shaped by the use-case.
type roleCompiledReader interface {
	Execute(ctx context.Context, id domain.RoleID) ([]string, error)
}

// Handler — gRPC server для InternalIAMService.
type Handler struct {
	iamv1.UnimplementedInternalIAMServiceServer

	lookup        *LookupSubjectUseCase
	authz         Authorizer
	subjectChange subjectChanger
	roleCompiled  roleCompiledReader

	// Resource-registration gate. Both nil when the registration
	// stack is not wired (degraded/dev) — RegisterResource then returns
	// Unavailable, fail-closed.
	registrar resourceRegistrar
	regGate   relationWriteGate

	// basicCredentials — авторитет о предъявленном базовом секрете (#1142).
	// nil → глагол fail-closed Unavailable.
	basicCredentials basicCredentialResolver

	// logger — поверхность НАБЛЮДАЕМОСТИ отказов. Различимость причин отказа
	// живёт здесь, а не в том, что видит предъявитель: «ноль отказов за всю
	// жизнь контроля» обязано быть заметно, иначе мёртвый контроль невидим.
	logger *slog.Logger

	// sessionRevoker — writer for ForceLogout. nil → the RPC
	// fails closed Unavailable. Shares the session_revocations table with the
	// user-logout Revoke path and the refresh-hook reader.
	sessionRevoker sessionRevoker

	// adminCheck — defense-in-depth ReBAC system_admin@cluster gate for the
	// privileged admin RPCs (ForceLogout). nil → fail-closed (the gate denies).
	// See force_logout.go requireSystemAdmin.
	adminCheck authzguard.RelationChecker

	// operations — Operation repository ForceLogout persists its operation row
	// in, before the mutation and terminally after it. nil → the RPC fails
	// closed Unavailable rather than returning an id that names no row.
	operations forceLogoutOperationRepo

	// providerSessions / externalIDs — the identity provider's login-session
	// surface and the resolver naming a kacho user to it, used by ForceLogout to
	// END the session rather than only record that it must not be honoured.
	// Both nil when that surface is not configured.
	providerSessions providerSessions
	externalIDs      externalIDResolver
}

// NewHandler — builder. `authz` may be nil when the FGA stack is not
// configured (dev); in that case Check returns Unavailable rather than
// Unimplemented (fail-closed for the gate).
func NewHandler(l *LookupSubjectUseCase, authz Authorizer) *Handler {
	return &Handler{lookup: l, authz: authz}
}

// WithSubjectChange — attaches the SubjectChangeService to the handler.
// Called from the composition root (cmd/kacho-iam/main.go).
func (h *Handler) WithLogger(l *slog.Logger) *Handler {
	h.logger = l
	return h
}

// WithSubjectChange — attaches the SubjectChangeService to the handler.
func (h *Handler) WithSubjectChange(sc subjectChanger) *Handler {
	h.subjectChange = sc
	return h
}

// WithResourceRegistrar — attaches the RegisterResource use-case + ReBAC authz
// gate. Both must be non-nil for the resource-registration RPCs to
// function; if either is nil the RPCs fail-closed (Unavailable on missing
// use-case, PermissionDenied when the gate denies).
func (h *Handler) WithResourceRegistrar(registrar resourceRegistrar, gate relationWriteGate) *Handler {
	h.registrar = registrar
	h.regGate = gate
	return h
}

// RegisterResource — Internal FGA-proxy: enqueue an owner-hierarchy tuple write
// into kacho_iam.fga_outbox, out of which a trigger folds the direct fact in the
// same commit. Idempotent: repeat of the same tuple → OK, never AlreadyExists.
//
// authz: exempt in proto-catalog; least-priv enforced HERE via ReBAC
// (cert-cert→SA → `fga_writer@cluster:cluster_kacho_root`). cluster-internal :9091.
// validateProxyTuple applies the shared proxy-write rule and maps its verdict to the
// transport. This is the ONE place the refusal becomes a gRPC status, so the code and
// the text cannot drift between the three RPCs that share the rule; the rule itself is
// transport-free by design (pkg/authz/proxytuple.ErrRefused) so a consumer's domain
// layer can import it without taking a dependency on gRPC.
//
// The refusal carries no reason: which clause refused is deliberately not observable
// (fail-closed, no oracle). Locked by TestProxyTupleRefusalMapsToPermissionDenied.
func validateProxyTuple(callerDomain, subject, relation, object string) error {
	// Словарь владения типом подаётся ЗДЕСЬ: правило живёт в общем фундаменте, а
	// закрытая таблица типов — за границей его видимости (см. proxy_type_owner.go).
	// Без него «чей это тип» отвечала бы приставка имени, то есть соглашение об
	// именовании, и тип, чьё имя приставке не подчиняется, был бы невыразим (#1885).
	if err := proxytuple.ValidateTuple(callerDomain, subject, relation, object,
		proxytuple.WithTypeOwner(catalogTypeOwner{})); err != nil {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handler) RegisterResource(ctx context.Context, req *iamv1.RegisterResourceRequest) (*iamv1.RegisterResourceResponse, error) {
	domain, err := h.authorizeRegistration(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateProxyTuple(domain, req.GetSubjectId(), req.GetRelation(), req.GetObject()); err != nil {
		return nil, err
	}
	if h.registrar == nil {
		return nil, status.Error(codes.Unavailable, "fga proxy not configured")
	}
	if err := h.registrar.Register(ctx, req); err != nil {
		// Map the use-case error via the single sentinel→gRPC translator:
		// validation status errors pass through, ErrUnavailable → Unavailable
		// (retriable fail-closed), any un-sentineled pgx/DB error → opaque
		// codes.Internal "internal error" (hardening-invariant #1: never echo the
		// raw driver text — host/port/user/db — nor leak it as codes.Unknown).
		return nil, shared.MapRepoErr(err)
	}
	return &iamv1.RegisterResourceResponse{}, nil
}

// UnregisterResource — Internal FGA-proxy: enqueue an owner-hierarchy tuple
// delete. Idempotent: absent tuple → OK, never NotFound (drainer
// cannot_delete→success). Same authz gate as RegisterResource.
func (h *Handler) UnregisterResource(ctx context.Context, req *iamv1.UnregisterResourceRequest) (*iamv1.UnregisterResourceResponse, error) {
	domain, err := h.authorizeRegistration(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateProxyTuple(domain, req.GetSubjectId(), req.GetRelation(), req.GetObject()); err != nil {
		return nil, err
	}
	if h.registrar == nil {
		return nil, status.Error(codes.Unavailable, "fga proxy not configured")
	}
	if err := h.registrar.Unregister(ctx, req); err != nil {
		// Same sentinel→gRPC mapping as RegisterResource (opaque Internal for
		// un-sentineled pgx/DB errors; no raw-text leak, no codes.Unknown).
		return nil, shared.MapRepoErr(err)
	}
	return &iamv1.UnregisterResourceResponse{}, nil
}

// authorizeRegistration runs the ReBAC gate and returns the caller's module
// domain (vpc/compute/nlb) for object-type binding. nil gate → fail-closed
// PermissionDenied (never silently allow an unwired gate in production).
func (h *Handler) authorizeRegistration(ctx context.Context) (string, error) {
	if h.regGate == nil {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return h.regGate.Authorize(ctx)
}

// TOMBSTONE. `WriteCreatorTuple` стоял здесь и снят (#788): он писал кортёж
// создателя в движок НАПРЯМУЮ, мимо `kacho_iam.fga_outbox`, поэтому проекция
// `relation_fact` (миграция 0098) его не увидела бы никогда. Вызывающих не
// осталось ни одного — все пять соседей ушли на RegisterResource. Порт записи
// (`relationWriter`) снят вместе с методом НАМЕРЕННО: тип без него нельзя
// переоткрыть одной строкой вызова.

func (h *Handler) LookupSubject(ctx context.Context, req *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
	return h.lookup.Execute(ctx, req)
}

// Check — single-tuple authorization gate.
//
// Thin transport-wrapper: delegates to AuthorizeService.CheckRelation, which
// runs the same FGA `Check` + OPA-guardrail pipeline as the public
// AuthorizeService.Check use-case. The InternalIAMService.CheckRequest is
// FGA-native ({subject_id, relation, object}) — the caller (vpc/compute
// per-RPC interceptor) has already resolved the RPC → relation, so no
// action→relation step is needed here.
//
// Coarse-grained gate: there is no per-call `action`/condition context on the
// wire, so the OPA overlay sees a synthesised action (object-type.relation).
func (h *Handler) Check(ctx context.Context, req *iamv1.CheckRequest) (*iamv1.CheckResponse, error) {
	if req.GetSubjectId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument subject_id: required")
	}
	if req.GetRelation() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument relation: required")
	}
	if req.GetObject() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument object: required")
	}
	if h.authz == nil {
		// Источник вердикта не провязан — fail-closed (интерсептор читает
		// Unavailable как отказ, а не как «пропустить страж»).
		return nil, status.Error(codes.Unavailable, "authz unavailable: verdict source not wired")
	}

	res, err := h.authz.CheckRelation(ctx, service.CheckRelationRequest{
		Subject:  req.GetSubjectId(),
		Relation: req.GetRelation(),
		Object:   req.GetObject(),
		// Требование свежести передаётся дальше, и оно ВЫПОЛНЕНО безусловно:
		// вердикт читает ведущую базу службы, поэтому собственная закоммиченная
		// запись вызывающего видна следующему же чтению by construction.
		//
		// Поле остаётся не «на всякий случай», а как ИМЯ требования: пути чтения с
		// отстающей реплики сегодня нет (он вне границ приёмки R7-3), и появится
		// он — различать требование будет тот, кто его заведёт. Прежде на этом
		// поле ветвился вызов к чужому хранилищу, отвечавшему со своей копии.
		HigherConsistency: req.GetConsistency() == iamv1.CheckRequest_HIGHER_CONSISTENCY,
	})
	if err != nil {
		switch {
		case strings.HasPrefix(err.Error(), "Illegal argument"):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case stderrors.Is(err, iamerr.ErrUnavailable):
			// Backend-unavailable classified by the typed sentinel (robust to
			// error-text rewording), not an error-string prefix.
			return nil, status.Error(codes.Unavailable, iamerr.StripSentinel(err))
		default:
			// Opaque INTERNAL — unmapped errors must not echo err.Error() (would
			// leak pgx/DB driver text: host/port/user/db).
			return nil, status.Error(codes.Internal, "internal error")
		}
	}

	resp := &iamv1.CheckResponse{Allowed: res.Allowed}
	if !res.Allowed {
		resp.Reason = strings.Join(res.DenyReasons, "; ")
	}
	return resp, nil
}

// Теневое сравнение формы E с движком здесь НЕ живёт, и это решение, а не
// пропуск: сравнивать надо ОКОНЧАТЕЛЬНЫЙ вердикт, а он складывается в
// `service.AuthorizeService` — к ответу движка там добавляются надзор
// администратора облака и структурный запасной путь. Сравнение, поставленное у
// транспорта, сверяло бы форму E с половиной ответа; кроме того, у транспорта
// оно покрывало ровно один вопрос из тех, что сервис отвечает. Механика — в
// `service/shadow_port.go`, свойство держит гейт
// `TestEveryEngineAskingQuestionAlsoAsksTheShadowForm`.

// PollSubjectChanges — drains subject_change_outbox by ascending-id cursor.
// Internal-only (cluster-internal listener; ban #6).
func (h *Handler) PollSubjectChanges(ctx context.Context, req *iamv1.PollSubjectChangesRequest) (*iamv1.PollSubjectChangesResponse, error) {
	if h.subjectChange == nil {
		return nil, status.Error(codes.Unavailable, "subject change service not configured")
	}
	changes, headID, err := h.subjectChange.PollSubjectChanges(ctx, req.GetSinceId(), req.GetLimit())
	if err != nil {
		// «Позиции ещё нет» — состояние холодного старта, а не отказ хранилища:
		// назвать его общим отказом значило бы посоветовать вызывающему разбирать
		// поломку там, где верный следующий шаг — переспросить. Отдельный тон
		// восстанавливает этот шаг (`retryable`), и он же не даёт вызывающему
		// принять ноль за позицию (kacho#1374).
		if stderrors.Is(err, service.ErrSubjectChangeNotSettled) {
			slog.WarnContext(ctx, "subject change journal position is not settled yet", "err", err)
			return nil, status.Error(codes.Unavailable, "subject change position not settled")
		}
		// «Позиция утрачена» — ТРЕТЬЯ полоса, и слить её нельзя ни с одной из
		// двух соседних (задача #1712).
		//
		// С «позиции ещё нет» — потому что советы противоположны: та говорит
		// «переспроси на следующем такте», эта — «повтор не пройдёт НИКОГДА,
		// пересядь». Вызывающий, прочитавший вторую как первую, повторял бы с
		// утраченной позиции вечно, и петля отзыва встала бы навсегда — молча
		// для клиента, у которого кэш вердиктов отвечает по снятым правам.
		//
		// С общим отказом — потому что `INTERNAL` текста не несёт by
		// construction (он приносит имена схемы и драйвера), а возобновимая
		// позиция ОБЯЗАНА доехать: без неё вызывающему некуда сесть.
		//
		// Отказ собирается ТЕМ ЖЕ конструктором, каким его разбирает край:
		// собственная сборка деталей здесь была бы вторым местом об одном
		// предмете и разошлась бы с настоящим читателем молча — обе непусты, обе
		// выглядят полосой, а совпасть перестают навсегда.
		var lost *service.SubjectChangePositionLostError
		if stderrors.As(err, &lost) {
			slog.WarnContext(ctx, "subject change position is no longer resumable",
				"since_id", req.GetSinceId(), "earliest_resumable_position", lost.EarliestResumable)
			return nil, subjectchange.PositionLost(lost.EarliestResumable)
		}
		slog.ErrorContext(ctx, "poll subject changes", "err", err)
		return nil, status.Error(codes.Internal, "subject change poll failed")
	}
	resp := &iamv1.PollSubjectChangesResponse{HeadId: headID}
	for _, c := range changes {
		resp.Changes = append(resp.Changes, &iamv1.SubjectChange{
			Id:          c.ID,
			SubjectId:   c.SubjectID,
			Op:          c.Op,
			SubjectType: c.SubjectType,
		})
	}
	return resp, nil
}
