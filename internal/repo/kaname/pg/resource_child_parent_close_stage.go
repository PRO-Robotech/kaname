// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type resourceChildParentCloseStage struct {
	input         kaname.ChildParentCloseInput
	module        resourceModuleIdentity
	catalog       resourceCatalogRow
	parents       *resourceParentCapture
	source        *resourceSourceCapture
	footprint     resourceFenceFootprint
	authorization *resourceRegistrationStage
}

// RR собирает только доступные runtime источники. Закрытость и повторное
// закрытие той же инкарнации устанавливает сервер под общим ограждением;
// этот снимок не читает закрытую таблицу состояния родителя.
func (r *ResourceDecisionRunner) stageChildParentClose(ctx context.Context, tx pgx.Tx, lifetime *resourceAttemptLifetime,
	module resourceModuleIdentity, input kaname.ChildParentCloseInput, budget *relverdict.AdministrativeReadBudget,
) (*resourceChildParentCloseStage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.bundle == nil || r.facts == nil || lifetime == nil || lifetime.bundle != r.bundle || !module.valid() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if !nativeQuestionToken(input.ResourceType) {
		return nil, &kaname.ResourceDecisionFieldError{Field: "resource_type", Description: "a live dotted parent resource type is required"}
	}
	modelType, admitted := r.facts.FGAObjectType(input.ResourceType)
	if !admitted {
		return nil, &kaname.ResourceDecisionFieldError{Field: "resource_type", Description: "parent resource type is not a live dotted catalog entry"}
	}
	if !nativeQuestionToken(input.ResourceID) {
		return nil, &kaname.ResourceDecisionFieldError{Field: "resource_id", Description: "an exact parent resource ID is required"}
	}
	input.SourceVersion = input.SourceVersion.UTC()
	if input.SourceVersion.IsZero() || input.SourceVersion.Year() < 1 || input.SourceVersion.Year() > 9999 {
		return nil, &kaname.ResourceDecisionFieldError{Field: "source_version", Description: "a finite nonzero parent registration version is required"}
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
	parent, known := captured.selected()
	if !known || !parent.live {
		return nil, &kaname.ResourceDecisionFieldError{Field: "resource_type", Description: "parent resource type is not live"}
	}
	if parent.identity.Module != module.catalogModule {
		return nil, authzguard.PermissionDenied()
	}
	if parent.identity.Dotted != input.ResourceType || parent.identity.ObjectType != modelType {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := r.confirmChildParentCloseCatalog(ctx, parents, parent); err != nil {
		return nil, err
	}
	rows, err := source.read(ctx, tx, resourceSourceKey{kind: resourceSourceMirror, typ: input.ResourceType, id: input.ResourceID})
	if err != nil {
		return nil, err
	}
	// Полное физическое состояние сохранено capture; декодер извлекает лишь
	// точную координату и версию, которых нет в общем parent mirror reader.
	type mirror struct {
		ObjectType    string    `json:"object_type"`
		ObjectID      string    `json:"object_id"`
		SourceVersion time.Time `json:"source_version"`
	}
	mirrors, err := resourceDecodeRows[mirror](rows)
	if err != nil {
		return nil, err
	}
	if len(mirrors) == 0 {
		return nil, authzguard.PermissionDenied()
	}
	if len(mirrors) != 1 || mirrors[0].ObjectType != input.ResourceType || mirrors[0].ObjectID != input.ResourceID {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if !mirrors[0].SourceVersion.Equal(input.SourceVersion) {
		return nil, authzguard.PermissionDenied()
	}
	// Включаем и пустые прямые предикаты: ветвление savedScopes не должно
	// превращать непрочитанный источник в доказательство его отсутствия.
	for _, kind := range []resourceSourceKind{resourceSourceParentEdges, resourceSourceRegistrationScopes, resourceSourceProjectBinding, resourceSourcePointerFacts} {
		if _, err := source.read(ctx, tx, resourceSourceKey{kind: kind, typ: modelType, id: input.ResourceID}); err != nil {
			return nil, err
		}
	}
	scopes, err := parents.savedScopes(ctx, modelType, input.ResourceID)
	if err != nil {
		return nil, err
	}
	footprint := newResourceFootprint()
	if err := footprint.addObject(domain.ResourceRef{Type: input.ResourceType, ID: input.ResourceID}); err != nil {
		return nil, err
	}
	if err := footprint.addRegistrationScopes(scopes); err != nil {
		return nil, err
	}
	footprint.global, err = source.requiresGlobalPredicate()
	if err != nil {
		return nil, err
	}
	classified, err := footprint.classified()
	if err != nil {
		return nil, err
	}
	classified.sourceWrite = true
	authorization := &resourceRegistrationStage{source: source, footprint: classified}
	authorization.installation, err = captureResourceInstallation(ctx, tx, lifetime, module, classified.registration, budget)
	if err != nil {
		return nil, err
	}
	authorization.native, err = r.captureRegistrationNative(ctx, tx, lifetime, module, classified.registration, budget)
	if err != nil {
		return nil, err
	}
	return &resourceChildParentCloseStage{input: input, module: module, catalog: parent, parents: parents,
		source: source, footprint: classified, authorization: authorization}, nil
}

// Имя родителя само по себе не включает закрытие. Хотя бы одна политика
// принятого bundle должна явно называть этот тип; каждую такую политику
// сверяем с физическим RR каталогом и включаем в последующий recheck.
func (r *ResourceDecisionRunner) confirmChildParentCloseCatalog(ctx context.Context, parents *resourceParentCapture, parent resourceCatalogRow) error {
	enabled := false
	for _, resource := range r.facts.Resources() {
		dotted := resource.Module + "." + resource.Resource
		policy, ok := r.bundle.ChildRegistration(dotted)
		if !ok || policy.Path.ParentType != parent.identity.ObjectType {
			continue
		}
		parentDotted, ok := r.bundle.ChildRegistrationParentDotted(policy.Path.ParentType, policy.Path.ParentAction)
		if !ok || parentDotted != parent.identity.Dotted || resource.Module != parent.identity.Module {
			return kaname.ErrSourceUnconfirmed
		}
		captured, err := parents.catalog(ctx, dotted)
		if err != nil {
			return err
		}
		child, known := captured.selected()
		if !known || !child.live || child.identity.Dotted != dotted || child.identity.Module != parent.identity.Module || child.identity.ObjectType != policy.Path.ChildType {
			return kaname.ErrSourceUnconfirmed
		}
		if err := confirmResourceChildPolicy(child, policy); err != nil {
			return err
		}
		enabled = true
	}
	if !enabled {
		return &kaname.ResourceDecisionFieldError{Field: "resource_type", Description: "resource type is not an enabled child-registration parent"}
	}
	return ctx.Err()
}

type resourceChildParentCloseIntent struct {
	Kind          string    `json:"kind"`
	ResourceType  string    `json:"resource_type"`
	ResourceID    string    `json:"resource_id"`
	SourceVersion time.Time `json:"source_version"`
	Actor         string    `json:"actor"`
	AuditID       string    `json:"audit_id"`
}

// Отдельный kind исключает трактовку close как Unregister старым dispatcher.
// Общий authorizer получает те же источники и окончательное время, что у
// module registration; отдельного callback или нового права тут нет.
func (s *resourceChildParentCloseStage) proposal() (*resourceDecisionProposal, error) {
	if s == nil || s.source == nil || s.parents == nil || s.parents.source != s.source || s.authorization == nil ||
		s.authorization.source != s.source || !s.module.valid() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	authorization := s.authorization
	if authorization.installation == nil || authorization.native == nil || authorization.installation.lifetime != s.source.lifetime ||
		authorization.native.lifetime != s.source.lifetime || authorization.installation.serviceName != s.module.serviceName ||
		authorization.installation.actor != s.module.actor || len(authorization.native.guards) == 0 || len(authorization.native.epochs) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	intent, err := json.Marshal(resourceChildParentCloseIntent{
		Kind: "child_parent_close", ResourceType: s.input.ResourceType, ResourceID: s.input.ResourceID,
		SourceVersion: s.input.SourceVersion, Actor: s.module.actor, AuditID: newAuditEventID(),
	})
	if err != nil {
		return nil, err
	}
	envelope, catalogs, err := makeResourceProposalEnvelope(intent, s.parents, s.footprint)
	if err != nil {
		return nil, err
	}
	envelope.Service, envelope.Actor = s.module.serviceName, s.module.actor
	envelope.NativeGuards = slices.Clone(authorization.native.guards)
	envelope.NativeEpochs = slices.Clone(authorization.native.epochs)
	for _, account := range authorization.installation.accounts {
		for _, witness := range authorization.installation.sources[account] {
			envelope.Installation = append(envelope.Installation, resourceProposalInstallation{Account: account, Assignment: witness.assignment, Binding: witness.binding, State: witness.state})
		}
	}
	return finishResourceDecisionProposal(envelope, s.source.lifetime, catalogs)
}
