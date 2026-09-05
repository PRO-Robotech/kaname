// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authorize — AuthorizeService gRPC handler.
// Thin transport-layer wrapper around the service.AuthorizeService use-case.
//
// Subject binding: the handler accepts `subject` directly from the protobuf
// request, and decides HERE who may name a subject other than themselves — see
// caller_authority.go. The proto comment claiming the gateway gates this on
// `iam.subjects.checkAuthorization` describes a permission that exists in no
// catalog and a relation that exists in no model; the catalog entry these RPCs
// actually carry is answered by every authenticated subject.
package authorize

import (
	"context"
	stderrors "errors"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho-iam/internal/authztypes"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// Fixed client-facing messages for non-validation failures. Raw use-case or
// resolver error text ("authz listObjects: <detail>", "authz unavailable: <raw>")
// embeds authz-backend internals and MUST NOT reach the caller (CWE-209). The
// detailed error is
// logged server-side instead. Deterministic "Illegal argument …" validation
// text is safe and is surfaced verbatim.
const (
	msgAuthzUnavailable = "authorization backend unavailable"
	msgAuthzInternal    = "internal error"
)

// Authorizer — порт решателя, которым пользуется ЭТОТ транспорт.
//
// Интерфейс, а не конкретный use-case, ровно по одной причине: между транспортом
// и решателем встаёт наблюдатель полос
// (`observability/metrics.InstrumentedSubjectAuthorizer`), и без порта его
// некуда поставить, не втащив сбор величин в use-case. Пока порта не было,
// полоса КРАЯ не наблюдалась вовсе: счётчик владельца прав видел только
// пообъектное звено модулей, и всякое «проверок в секунду», снятое с него, было
// занижено — на пути чтения по идентификатору ровно вдвое.
//
// Набор методов — тот, который зовёт транспорт, и ни одним больше: порт шире
// употребления обязывал бы всякого будущего дублёра реализовывать то, чего у
// него не спрашивают.
type Authorizer interface {
	Check(ctx context.Context, req service.CheckRequest) (*service.CheckResult, error)
	BatchCheck(ctx context.Context, reqs []service.CheckRequest) ([]*service.CheckResult, error)
	ListSubjects(ctx context.Context, req service.ListSubjectsRequest) (*service.ListSubjectsResult, error)
	ExpandRelations(ctx context.Context, req service.ExpandRequest) (*service.ExpandResult, error)
}

// Handler — gRPC server.
type Handler struct {
	iamv1.UnimplementedAuthorizeServiceServer
	svc    Authorizer
	whoAmI *WhoAmIUseCase
	// authority — FGA relation checker for the inner caller-authority gate
	// (caller_authority.go). Optional / nil-safe: when unset the gate can still
	// allow self-queries and passes through anonymous/system module PDP calls,
	// but denies a non-self tenant principal that cannot be proven cluster-admin
	// or resource-authority (fail-closed). Wired to the decision door in the
	// composition root via WithCallerAuthority.
	authority authzguard.RelationChecker
	// insecureAnonymousPeer — the EXCEPTION knob for the inner caller-authority
	// gate's treatment of an anonymous/system principal that carries NO verified
	// module cert. Default (false) is the RULE: such a caller reached the PUBLIC
	// listener, which has no module-cert floor, and is DENIED. Setting it opts a
	// stand without mTLS into the permissive posture, where the two listeners are
	// indistinguishable (mirroring authzguard.CallerPolicy / RelationWriteGate).
	//
	// The polarity is load-bearing, not cosmetic. It used to be `prodMode`, whose
	// zero value selected the permissive branch — so a composition that never
	// called the setter answered authorization questions about arbitrary subjects
	// to a caller presenting no credentials at all, and nothing failed to say so.
	// A knob may carry the exception; it may not carry the rule. Set via
	// WithInsecureAnonymousPeer.
	insecureAnonymousPeer bool
}

// NewHandler — builder. Both svc and whoAmI are required (composition root
// wires both unconditionally; nil at construction time means a wiring bug).
func NewHandler(svc Authorizer, whoAmI *WhoAmIUseCase) *Handler {
	return &Handler{svc: svc, whoAmI: whoAmI}
}

// WithCallerAuthority injects the FGA relation checker used by the inner
// caller-authority defense-in-depth gate. Returns the receiver for chaining.
func (h *Handler) WithCallerAuthority(checker authzguard.RelationChecker) *Handler {
	h.authority = checker
	return h
}

// WithInsecureAnonymousPeer opts a stand WITHOUT mTLS into the permissive
// treatment of an anonymous/system principal that carries no verified module
// cert. Passing false (or never calling this at all) keeps the fail-closed
// default. The composition root derives it from the AuthN mode:
// WithInsecureAnonymousPeer(!cfg.AuthN.Mode.IsProduction()).
// Returns the receiver for chaining.
func (h *Handler) WithInsecureAnonymousPeer(insecure bool) *Handler {
	h.insecureAnonymousPeer = insecure
	return h
}

// maxTraceIDLen — предел длины корреляционного идентификатора В ЛОГЕ.
//
// Длина приходит от вызывающего КАКАЯ УГОДНО: механизма, ограничивающего её на
// пути запроса, в этом дереве нет — ни интерсептора, ни проверки контракта.
// Прежде предел объявляло расширение контракта, но исполнителя у него не было ни
// одного, и семейство снято целиком (kacho#1255). Писать значение в лог как есть
// значит отдать вызывающему право на объём наших логов. Обрезка живёт в коде,
// рядом с записью, и здесь она ЕДИНСТВЕННАЯ.
const maxTraceIDLen = 64

// traceAttr — корреляционный идентификатор вызывающего как атрибут записи лога.
//
// Поле `trace_id` объявлено на проверках доступа как «Correlation id for downstream
// logs / traces», и до этой правки его не читал никто: вызывающий присылал
// идентификатор и не находил его ни в одной записи. Атрибут добавляется на путях,
// где запись вообще делается (недоступность бэкенда, внутренняя ошибка). На успешном
// пути записи нет и не будет: authz-Check стоит на КАЖДОМ RPC платформы, и лог на
// каждый успешный Check утопил бы ту самую корреляцию, ради которой поле существует.
//
// Пустой идентификатор даёт пустой атрибут (slog его печатает как пустую строку) —
// это дешевле ветвления на каждом вызове и не искажает запись. Лок:
// trace_id_test.go.
func traceAttr(traceID string) slog.Attr {
	if len(traceID) > maxTraceIDLen {
		traceID = traceID[:maxTraceIDLen]
	}
	return slog.String("trace_id", traceID)
}

// Check — see iamv1.AuthorizeServiceServer.
func (h *Handler) Check(ctx context.Context, req *iamv1.AuthorizeCheckRequest) (*iamv1.AuthorizeCheckResponse, error) {
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument subject: required")
	}
	if req.GetResource() == nil {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument resource: required")
	}
	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument action: required")
	}
	// Inner defense-in-depth: a tenant principal may only Check about itself, a
	// resource it administers, or as a cluster-admin (caller_authority.go).
	if err := h.authorizeCaller(ctx, req.GetSubject(), req.GetResource()); err != nil {
		return nil, err
	}
	res, err := h.svc.Check(ctx, service.CheckRequest{
		Subject: req.GetSubject(),
		Resource: service.ResourceRef{
			Type: req.GetResource().GetType(),
			ID:   req.GetResource().GetId(),
		},
		Action:           req.GetAction(),
		RequiredRelation: req.GetRequiredRelation(),
		Context:          structToMap(req.GetContext()),
	})
	if err != nil {
		// Validation errors → InvalidArgument (verbatim, safe); backend errors →
		// Unavailable/Internal with a fixed, redacted message (no raw pgx/FGA leak).
		// Backend-unavailable is classified by the typed iamerr.ErrUnavailable
		// sentinel (robust to error-text rewording), NOT an error-string prefix.
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if stderrors.Is(err, iamerr.ErrUnavailable) {
			slog.ErrorContext(ctx, "authorize backend unavailable", "op", "Check",
				"err", err.Error(), traceAttr(req.GetTraceId()))
			return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
		}
		slog.ErrorContext(ctx, "authorize internal error", "op", "Check",
			"err", err.Error(), traceAttr(req.GetTraceId()))
		return nil, status.Error(codes.Internal, msgAuthzInternal)
	}
	return &iamv1.AuthorizeCheckResponse{
		Allowed:     res.Allowed,
		DenyReasons: res.DenyReasons,
		CheckedAt:   shared.TimestampProto(res.CheckedAt),
	}, nil
}

// BatchCheck — see iamv1.AuthorizeServiceServer.
func (h *Handler) BatchCheck(ctx context.Context, req *iamv1.BatchAuthorizeCheckRequest) (*iamv1.BatchAuthorizeCheckResponse, error) {
	if len(req.GetChecks()) > 100 {
		return nil, status.Errorf(codes.InvalidArgument, "Illegal argument checks: batch size %d > 100", len(req.GetChecks()))
	}
	// Inner defense-in-depth: gate every item's subject/resource before fanning
	// out — a single unauthorized item denies the whole batch (caller_authority.go).
	for _, c := range req.GetChecks() {
		if err := h.authorizeCaller(ctx, c.GetSubject(), c.GetResource()); err != nil {
			return nil, err
		}
	}
	reqs := make([]service.CheckRequest, 0, len(req.GetChecks()))
	for _, c := range req.GetChecks() {
		reqs = append(reqs, service.CheckRequest{
			Subject: c.GetSubject(),
			Resource: service.ResourceRef{
				Type: c.GetResource().GetType(),
				ID:   c.GetResource().GetId(),
			},
			Action:           c.GetAction(),
			RequiredRelation: c.GetRequiredRelation(),
			Context:          structToMap(c.GetContext()),
		})
	}
	results, err := h.svc.BatchCheck(ctx, reqs)
	if err != nil {
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		// Backend-unavailable fails the whole batch (mirror Check): surface a
		// retryable Unavailable with the fixed redacted text, never the raw FGA
		// transport error (endpoint/store id leak).
		if stderrors.Is(err, iamerr.ErrUnavailable) {
			slog.ErrorContext(ctx, "authorize backend unavailable", "op", "BatchCheck",
				"err", err.Error(), traceAttr(req.GetTraceId()))
			return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
		}
		slog.ErrorContext(ctx, "authorize internal error", "op", "BatchCheck",
			"err", err.Error(), traceAttr(req.GetTraceId()))
		return nil, status.Error(codes.Internal, msgAuthzInternal)
	}
	out := &iamv1.BatchAuthorizeCheckResponse{
		Responses: make([]*iamv1.AuthorizeCheckResponse, len(results)),
	}
	for i, r := range results {
		out.Responses[i] = &iamv1.AuthorizeCheckResponse{
			Allowed:     r.Allowed,
			DenyReasons: r.DenyReasons,
			CheckedAt:   shared.TimestampProto(r.CheckedAt),
		}
	}
	return out, nil
}

// ListSubjects — see iamv1.AuthorizeServiceServer.
func (h *Handler) ListSubjects(ctx context.Context, req *iamv1.ListSubjectsRequest) (*iamv1.ListSubjectsResponse, error) {
	if req.GetResource() == nil {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument resource: required")
	}
	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument action: required")
	}
	// Inner defense-in-depth: ListSubjects enumerates WHO can act on a resource,
	// so a tenant caller must administer that resource or be a cluster-admin
	// (caller_authority.go) — otherwise it leaks the resource's authz graph.
	if err := h.authorizeCaller(ctx, "", req.GetResource()); err != nil {
		return nil, err
	}
	res, err := h.svc.ListSubjects(ctx, service.ListSubjectsRequest{
		ResourceType:      req.GetResource().GetType(),
		ResourceID:        req.GetResource().GetId(),
		Action:            req.GetAction(),
		PageSize:          int(req.GetPageSize()),
		PageToken:         req.GetPageToken(),
		SubjectTypeFilter: req.GetSubjectTypeFilter(),
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		slog.ErrorContext(ctx, "authorize backend unavailable", "op", "ListSubjects", "err", err.Error())
		return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
	}
	return &iamv1.ListSubjectsResponse{
		Subjects:      res.Subjects,
		NextPageToken: res.NextPageToken,
	}, nil
}

// ExpandRelations — see iamv1.AuthorizeServiceServer.
func (h *Handler) ExpandRelations(ctx context.Context, req *iamv1.ExpandRelationsRequest) (*iamv1.ExpandRelationsResponse, error) {
	if req.GetResource() == nil {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument resource: required")
	}
	if req.GetRelation() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument relation: required")
	}
	// Пара (тип ресурса, отношение) приходит от вызывающего ЦЕЛИКОМ, а разбирает
	// её компиляция плана по набору КОНКРЕТНОГО типа. Пара, которой тип не
	// объявляет, плана не даёт никогда — и до этой проверки уезжала в форму,
	// возвращаясь `UNAVAILABLE`, то есть «повтори позже» на ввод, который годным
	// не станет ни при каком повторе (#1290, соседний по классу с
	// AccessBindingService.ExpandAccess).
	//
	// Предикат тот же, на котором стоит компиляция (`authzmodel.Declares`), —
	// поэтому приём и разбор здесь судят один набор by construction. Поверхность
	// НЕ сужается: это интроспекция графа прав, и машинерия модели (переносчики
	// охвата, резолверы) остаётся законным вопросом, если тип её объявляет.
	if plans, perr := authzmodel.Shared(); perr != nil {
		slog.ErrorContext(ctx, "authz model unparsed", "op", "ExpandRelations", "err", perr.Error())
		return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
	} else if !plans.DeclaresType(req.GetResource().GetType()) {
		return nil, status.Errorf(codes.InvalidArgument,
			"Illegal argument resource.type %q", req.GetResource().GetType())
	} else if !plans.Declares(req.GetResource().GetType(), req.GetRelation()) {
		return nil, status.Errorf(codes.InvalidArgument,
			"Illegal argument relation %q (not declared on resource type %q)",
			req.GetRelation(), req.GetResource().GetType())
	}
	// Inner defense-in-depth: ExpandRelations discloses the full userset tree of
	// a resource, so a tenant caller must administer that resource or be a
	// cluster-admin (caller_authority.go).
	if err := h.authorizeCaller(ctx, "", req.GetResource()); err != nil {
		return nil, err
	}
	res, err := h.svc.ExpandRelations(ctx, service.ExpandRequest{
		ResourceType: req.GetResource().GetType(),
		ResourceID:   req.GetResource().GetId(),
		Relation:     req.GetRelation(),
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		slog.ErrorContext(ctx, "authorize backend unavailable", "op", "ExpandRelations", "err", err.Error())
		return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
	}
	return &iamv1.ExpandRelationsResponse{
		Resource: &iamv1.ResourceRef{Type: res.Resource.Type, Id: res.Resource.ID},
		Relation: res.Relation,
		Tree:     treeToProto(res.Tree),
	}, nil
}

// treeToProto — основания права → iamv1.UsersetTree.
//
// Перечень ОДНОУРОВНЕВЫЙ, и это свойство источника, а не упрощение переходника.
// Основание в реляционной форме — плоская запись (факт · выдача · членство); у
// него не бывает глубины, которой неоткуда взяться. Рёбра графа сняты с контракта
// вместе с движком, который их производил: заполнять их было бы нечем, а поле,
// которое никогда не заполняется, обещает возможность, которой нет.
func treeToProto(t *authztypes.ExpandTree) *iamv1.UsersetTree {
	if t == nil {
		return nil
	}
	return &iamv1.UsersetTree{
		Leaves:    append([]string(nil), t.Leaves...),
		Truncated: t.Truncated,
	}
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// WhoAmI — see iamv1.AuthorizeServiceServer. Marshals the WhoAmI
// use-case result into the proto response shape. The use-case is the
// authoritative gate (anonymous → Unauthenticated); the handler is the
// thin transport wrapper.
func (h *Handler) WhoAmI(ctx context.Context, _ *iamv1.WhoAmIRequest) (*iamv1.WhoAmIResponse, error) {
	res, err := h.whoAmI.Execute(ctx)
	if err != nil {
		// use-case already returns status.Error for terminal cases
		// (Unauthenticated, Unavailable, NotFound). Anything else is
		// shaped through shared.MapRepoErr inside the use-case.
		return nil, err
	}
	accounts := make([]*iamv1.AccountMembership, 0, len(res.Accounts))
	for _, a := range res.Accounts {
		accounts = append(accounts, &iamv1.AccountMembership{
			AccountId:   string(a.AccountID),
			AccountName: a.AccountName,
			Roles:       append([]string(nil), a.Roles...),
		})
	}
	return &iamv1.WhoAmIResponse{
		Subject:       res.Subject,
		UserId:        string(res.UserID),
		Email:         res.Email,
		DisplayName:   res.DisplayName,
		SystemAdmin:   res.SystemAdmin,
		ClusterViewer: res.ClusterViewer,
		Accounts:      accounts,
		CheckedAt:     shared.TimestampProto(res.CheckedAt),
	}, nil
}
