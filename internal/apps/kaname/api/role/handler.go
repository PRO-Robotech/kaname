// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package role — RoleService.
package role

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/safeconv"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	reporole "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

type Handler struct {
	iamv1.UnimplementedRoleServiceServer

	create *CreateRoleUseCase
	update *UpdateRoleUseCase
	delete *DeleteRoleUseCase
	get    *GetRoleUseCase
	list   *ListRolesUseCase
	listOp *shared.ListOperationsUseCase
}

func NewHandler(c *CreateRoleUseCase, u *UpdateRoleUseCase, d *DeleteRoleUseCase,
	g *GetRoleUseCase, l *ListRolesUseCase) *Handler {
	return &Handler{create: c, update: u, delete: d, get: g, list: l}
}

// WithListOperations wires the per-resource operation-listing use-case.
func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

func (h *Handler) Create(ctx context.Context, req *iamv1.CreateRoleRequest) (*operationpb.Operation, error) {
	// A-02: permissions is INTERNAL compiled/output-only — reject any client-sent
	// value as the first statement (before the use-case), so no role is created.
	// Intentionally reads the deprecated field precisely to reject client input.
	if len(req.GetPermissions()) > 0 { //nolint:staticcheck // A-02: deprecated field read solely to reject it
		return nil, shared.InvalidArg("permissions", "Illegal argument permissions (compiled/output-only)")
	}
	if err := refuseNestedRulesOnInput(req.GetRules()); err != nil {
		return nil, err
	}
	r, err := roleFromCreateReq(req)
	if err != nil {
		return nil, err
	}
	op, err := h.create.Execute(ctx, r)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateRoleRequest) (*operationpb.Operation, error) {
	if err := refuseNestedRulesOnInput(req.GetRules()); err != nil {
		return nil, err
	}
	in := UpdateRoleInput{
		ID:              domain.RoleID(req.GetRoleId()),
		ResourceVersion: req.GetResourceVersion(),
	}
	if name := req.GetName(); name != "" {
		n := domain.RoleName(name)
		in.Name = &n
	}
	if desc := req.GetDescription(); desc != "" {
		d := domain.Description(desc)
		in.Description = &d
	}
	if rules := req.GetRules(); rules != nil {
		in.Rules = rulesFromProto(rules)
	}
	// labels — own-resource метки (T3.3); НЕ путать с Rule.MatchLabels.
	if labels := req.GetLabels(); labels != nil {
		in.Labels = labelsFromProto(labels)
	}
	if mask := req.GetUpdateMask(); mask != nil {
		in.UpdateMask = append([]string{}, mask.GetPaths()...)
	}
	op, err := h.update.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteRoleRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.RoleID(req.GetRoleId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetRoleRequest) (*iamv1.Role, error) {
	r, err := h.get.Execute(ctx, domain.RoleID(req.GetRoleId()))
	if err != nil {
		return nil, err
	}
	pb, err := roleToPb(r)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return pb, nil
}

func (h *Handler) List(ctx context.Context, req *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	// Форма страницы судится ЗДЕСЬ, на транспортной границе, и первым
	// стейтментом — как у остальных шести списочных поверхностей сервиса
	// (kacho#660). Прежде роли судили величину здесь, а форму токена — первым
	// стейтментом use-case: порядок «формат до замыкания по личности»
	// соблюдался, но форма была одна из семи, и следующий, кто заведёт
	// восьмую поверхность, скопировал бы ту, на которую посмотрел.
	//
	// Оба предмета — величина и форма токена — теперь у одного вызова:
	// два места об одном вопросе расходятся при первой же правке одного.
	if err := shared.ValidateRawVisiblePagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	filter := reporole.ListFilter{
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
		// kacho-iam#185: scope the catalog to a single Account (system + that Account's
		// custom roles). Empty → unscoped (subject to per-object visibility).
		AccountID: domain.AccountID(req.GetAccountId()),
	}
	rows, next, err := h.list.Execute(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Role, 0, len(rows))
	for _, r := range rows {
		pb, err := roleToPb(r)
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		out = append(out, pb)
	}
	return &iamv1.ListRolesResponse{Roles: out, NextPageToken: next}, nil
}

func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListRoleOperationsRequest) (*iamv1.ListRoleOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetRoleId(), domain.PrefixRole, "role"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetRoleId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListRoleOperationsResponse{Operations: out, NextPageToken: next}, nil
}

// ----- helpers -----

// roleFromCreateReq maps a CreateRoleRequest into the domain.Role for the
// use-case. BOTH scope columns are mapped (account_id XOR project_id, kacho-iam#212) —
// the use-case enforces the XOR. IsSystem is always false (system roles are
// seeded by migration, never via this RPC).
func roleFromCreateReq(req *iamv1.CreateRoleRequest) (domain.Role, error) {
	r := domain.Role{
		AccountID:   domain.AccountID(req.GetAccountId()),
		ProjectID:   domain.ProjectID(req.GetProjectId()),
		Name:        domain.RoleName(req.GetName()),
		Description: domain.Description(req.GetDescription()),
		Rules:       rulesFromProto(req.GetRules()),
		// labels — own-resource метки самого ресурса Role (T3.3); НЕ путать с
		// Rule.MatchLabels (object-selector внутри правила).
		Labels:   labelsFromProto(req.GetLabels()),
		IsSystem: false,
	}
	// redesign-2026 F4: definitionTier is the canonical scope input; when set it
	// supersedes the legacy account_id/project_id pair. Pre-Phase-0 tierType is
	// REQUIRED (prefix-derivation is B3-gated); iam.cluster is rejected (system
	// roles are seeded by migration, never created via this RPC).
	if dt := req.GetDefinitionTier(); dt != nil && (dt.GetTierType() != "" || dt.GetTierId() != "") {
		acc, prj, ok := domain.CustomDefinitionTierToScope(dt.GetTierType(), dt.GetTierId())
		if !ok {
			return domain.Role{}, shared.InvalidArg("definitionTier", "Illegal argument definitionTier")
		}
		r.AccountID = domain.AccountID(acc)
		r.ProjectID = domain.ProjectID(prj)
	}
	return r, nil
}

// rulesFromProto maps the authored proto rules into domain.Rule, preserving the
// selector arm (resource_names XOR match_labels). Empty input → empty slice.
func rulesFromProto(in []*iamv1.Rule) domain.Rules {
	out := make(domain.Rules, 0, len(in))
	for _, r := range in {
		out = append(out, domain.Rule{
			Module:        r.GetModule(),
			Resources:     append([]string(nil), r.GetResources()...),
			Verbs:         append([]string(nil), r.GetVerbs()...),
			ResourceNames: append([]string(nil), r.GetResourceNames()...),
			MatchLabels:   r.GetMatchLabels(),
		})
	}
	return out
}

// roleToPb — роль в ответе ЧТЕНИЯ (`Get`, `List`).
//
// Вычисленное состояние — целость, состояния правил (и вложенных, kaname#874),
// жизненное состояние, ведомости — сюда приложил `attachIntegrity` ЭТОГО же
// чтения, и оно едет в ответ. Проекция ответа ОПЕРАЦИИ (`marshalRole`,
// `domain.Role.WithoutComputedState`) его обнуляет намеренно — у мутации оно
// посчитано не на том снимке, — и прежде она стояла и здесь: `declaredSegments`,
// `health` и `ruleStates` на чтении были нулевыми всегда, то есть «не
// вычислено» там, где вычислено.
func roleToPb(r domain.Role) (*iamv1.Role, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(r, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer Role: %w", err)
	}
	return dst, nil
}

// textNestedRulesNotOnInput — отказ входа с вложенными правилами (kaname#874,
// ND-04 (ж)). Контракт тона — дословно приёмочный.
const textNestedRulesNotOnInput = "Illegal argument children (nested rules are declared by a module manifest)"

// refuseNestedRulesOnInput — в этой фазе вложенное правило объявляет только
// манифест модуля (приёмка `nested-rule-reaches-descendants-of-a-named-container.md`,
// Р4): непустое `children` на входе `Create` и `Update` — синхронный
// INVALID_ARGUMENT с полем `rules[<i>].children`, а не молчаливый пропуск. Поле
// контракта на входе то же, что `permissions` (вывод) — отказ стоит рядом и в
// той же форме, до заведения операции.
func refuseNestedRulesOnInput(rules []*iamv1.Rule) error {
	for i, r := range rules {
		if len(r.GetChildren()) > 0 {
			return shared.InvalidArg(fmt.Sprintf("rules[%d].children", i), textNestedRulesNotOnInput)
		}
		// Селектор создателя (kaname#1003, Р2 п.4) — тем же отказом и в той же
		// форме: объявляет его только манифест модуля, а роль аккаунта, несущая
		// его, вела бы «созданное субъектом» по правилу, которое автор аккаунта мог
		// не понять (§8 В6).
		if r.GetCreatedBySubject() {
			return shared.InvalidArg(fmt.Sprintf("rules[%d].createdBySubject", i), textCreatorRulesNotOnInput)
		}
	}
	return nil
}

// textCreatorRulesNotOnInput — отказ входа с селектором создателя (kaname#1003,
// Р6). Контракт тона — дословно приёмочный.
const textCreatorRulesNotOnInput = "Illegal argument createdBySubject (creator-scoped rules are declared by a module manifest)"
