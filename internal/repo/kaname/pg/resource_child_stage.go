// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Снимок RR готовит источники для серверной проверки. Повтор для занятого
// ключа подтверждает только квитанция создания. При отсутствии родителя
// остаётся кандидат на отказ без области записи.
type resourceChildStage struct {
	authorization    *resourceChildAuthorization
	catalog          resourceCatalogRow
	parents          *resourceParentCapture
	source           *resourceSourceCapture
	output           *resourceOutputCapture
	hierarchies      []domain.ParentHierarchy
	oldScopes        []domain.ContainerScope
	newScopes        []domain.ContainerScope
	footprint        *resourceFenceFootprint
	parentRegistered bool
	childRegistered  bool
}

// Источники читаются на снимке предварительной авторизации с общим бюджетом.
// Состояние родителя, квоты и квитанции входят в закрытое чтение владельца.
// Окончательный компилятор дополняет и сверяет зависимости записи.
func (r *ResourceDecisionRunner) stageUserChildRegistration(ctx context.Context, tx pgx.Tx, lifetime *resourceAttemptLifetime,
	input kaname.UserChildRegistrationInput, principal operations.Principal, budget *relverdict.AdministrativeReadBudget,
) (*resourceChildStage, error) {
	authorization, err := r.captureUserChildAuthorization(ctx, tx, lifetime, input, principal, budget)
	if err != nil {
		return nil, err
	}
	source, err := newResourceSourceCapture(tx, budget, lifetime)
	if err != nil {
		return nil, err
	}
	parents, err := newResourceParentCapture(tx, source)
	if err != nil {
		return nil, err
	}
	captured, err := parents.catalog(ctx, input.ResourceType)
	if err != nil {
		return nil, err
	}
	selected, known := captured.selected()
	if !known || !selected.live {
		return nil, domain.ErrUserChildRegistrationRefused
	}
	policy, enabled := r.bundle.ChildRegistration(input.ResourceType)
	if !enabled || selected.identity.Dotted != input.ResourceType || selected.identity.ObjectType != policy.Path.ChildType {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := confirmResourceChildPolicy(selected, policy); err != nil {
		return nil, err
	}
	parentType, parentID, _ := strings.Cut(authorization.target.ParentObject, ":")
	parentDotted, enabled := r.bundle.ChildRegistrationParentDotted(parentType, authorization.target.ParentAction)
	if !enabled {
		return nil, kaname.ErrSourceUnconfirmed
	}
	parentCatalog, err := parents.catalog(ctx, parentType)
	if err != nil {
		return nil, err
	}
	parent, known := parentCatalog.selected()
	if !known || !parent.live {
		return nil, domain.ErrUserChildRegistrationRefused
	}
	if parent.identity.Dotted != parentDotted || parent.identity.ObjectType != parentType || parent.identity.Module != selected.identity.Module {
		return nil, kaname.ErrSourceUnconfirmed
	}

	out := &resourceChildStage{authorization: authorization, catalog: selected, parents: parents, source: source}
	_, out.parentRegistered, err = parents.mirror(ctx, parentType, parentID)
	if err != nil || !out.parentRegistered {
		return out, err
	}
	// Передаём компилятору полные снимки предикатов, включая прочитанные
	// пустые результаты для нового ключа.
	if err := captureResourceDirectSources(ctx, parents, selected, input.ResourceID, kaname.ResourceDecisionRegister); err != nil {
		return nil, err
	}
	_, out.childRegistered, err = parents.mirror(ctx, selected.identity.ObjectType, input.ResourceID)
	if err != nil {
		return nil, err
	}
	out.output, err = captureResourceOutput(ctx, parents, selected, input.ResourceID)
	if err != nil {
		return nil, err
	}
	// Пустое утверждение сохраняет все ветви канонического графа родителя.
	out.hierarchies, out.newScopes, err = parents.derive(ctx, authorization.target.ParentObject, "parent",
		authorization.target.ChildObject, selected.policy, domain.ParentClaim{})
	if err != nil {
		return nil, err
	}
	if len(out.hierarchies) == 0 || len(out.newScopes) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	for _, branch := range out.hierarchies {
		if len(branch.Links) == 0 || branch.Links[0] != authorization.target.ParentObject ||
			(selected.policy.PermanentProject && branch.ProjectID == "") {
			return nil, kaname.ErrSourceUnconfirmed
		}
	}
	out.oldScopes, err = parents.savedScopes(ctx, selected.identity.ObjectType, input.ResourceID)
	if err != nil {
		return nil, err
	}
	if out.childRegistered && len(out.oldScopes) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	parentScopes, err := parents.savedScopes(ctx, parentType, parentID)
	if err != nil {
		return nil, err
	}
	footprint := newResourceFootprint()
	if err := footprint.addRegistrationScopes(parentScopes); err != nil {
		return nil, err
	}
	if err := footprint.addRegistrationScopes(out.newScopes); err != nil {
		return nil, err
	}
	if len(out.oldScopes) != 0 {
		if err := footprint.addRegistrationScopes(out.oldScopes); err != nil {
			return nil, err
		}
	}
	if err := out.output.addFootprint(ctx, parents, footprint); err != nil {
		return nil, err
	}
	broad, err := source.requiresGlobalPredicate()
	if err != nil {
		return nil, err
	}
	for account := range authorization.native.boundary.accounts {
		if err := footprint.addMutationAccount(domain.AccountID(account)); err != nil {
			return nil, err
		}
	}
	footprint.global = footprint.global || broad || authorization.native.boundary.global()
	classified, err := footprint.classified()
	if err != nil {
		return nil, err
	}
	classified.sourceWrite = true
	out.footprint = &classified
	return out, nil
}

type resourceChildRegistrationIntent struct {
	Kind         string `json:"kind"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Actor        string `json:"actor"`
	AuditID      string `json:"audit_id"`
}

// Запрос компилятору использует личность и координату из захваченного
// допуска. Источники и версии проверяет сервер под ограждением.
func (s *resourceChildStage) proposal() (*resourceDecisionProposal, error) {
	if s == nil || s.footprint == nil || !s.parentRegistered || s.authorization == nil ||
		s.source == nil || s.source.lifetime != s.authorization.native.lifetime ||
		len(s.authorization.native.guards) == 0 || len(s.authorization.native.epochs) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	actor, ok := strings.CutPrefix(s.authorization.subject, "user:")
	_, childID, named := strings.Cut(s.authorization.target.ChildObject, ":")
	if !ok || !nativeQuestionToken(actor) || !named || !nativeQuestionToken(childID) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	intent, err := json.Marshal(resourceChildRegistrationIntent{
		Kind: "child_registration", ResourceType: s.catalog.identity.Dotted, ResourceID: childID, Actor: actor, AuditID: newAuditEventID(),
	})
	if err != nil {
		return nil, err
	}
	envelope, catalogs, err := makeResourceProposalEnvelope(intent, s.parents, *s.footprint)
	if err != nil {
		return nil, err
	}
	envelope.Actor = actor
	envelope.NativeGuards = slices.Clone(s.authorization.native.guards)
	envelope.NativeEpochs = slices.Clone(s.authorization.native.epochs)
	return finishResourceDecisionProposal(envelope, s.source.lifetime, catalogs)
}

// Общий читатель сохраняет строку каталога целиком. Из неё сверяем
// child_registration с принятой политикой и проверяем указатель parent.
func confirmResourceChildPolicy(row resourceCatalogRow, policy catalog.ChildRegistrationPolicy) error {
	var state []json.RawMessage
	if json.Unmarshal([]byte(row.state), &state) != nil || len(state) != 3 {
		return kaname.ErrSourceUnconfirmed
	}
	var physical struct {
		Dotted     string                         `json:"dotted"`
		ObjectType string                         `json:"object_type"`
		Live       bool                           `json:"live"`
		Rule       *catalog.ChildRegistrationRule `json:"child_registration"`
	}
	if json.Unmarshal(state[2], &physical) != nil || !physical.Live || physical.Dotted != row.identity.Dotted ||
		physical.ObjectType != row.identity.ObjectType || physical.Rule == nil {
		return kaname.ErrSourceUnconfirmed
	}
	expected := catalog.ChildRegistrationRule{Verb: policy.Verb, ParentSegments: int32(policy.Path.ParentSegments),
		MaxChildren: policy.MaxChildren, MaxCreates: policy.MaxCreates, WindowSeconds: policy.WindowSeconds}
	if *physical.Rule != expected {
		return kaname.ErrSourceUnconfirmed
	}
	pointer, ok := row.policy.Pointer("parent")
	if !ok || pointer.Type != policy.Path.ParentType {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}
