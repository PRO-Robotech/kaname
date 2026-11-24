// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// ErrPublicationOperatorDenied означает отказ в допуске оператора регистрации.
var ErrPublicationOperatorDenied = errors.New("modulecatalog: catalog registration requires a confirmed human system administrator")

// ErrPublicationDocument обозначает отказ разбора декларации от оператора.
var ErrPublicationDocument = errors.New("modulecatalog: invalid catalog publication document")

// PublishedModel — запись головной редакции модели из журнала.
type PublishedModel struct {
	Revision  int64
	Digest    string
	CatalogID string
	Text      string
}

// CatalogPublicationWriter работает после повторного допуска оператора.
// Каталог, журнал частей и журнал модели принадлежат одной транзакции.
type CatalogPublicationWriter interface {
	CatalogWriter
	LatestPublishedModel(context.Context) (PublishedModel, error)
	LatestPublishedParts(context.Context) ([]LatestPart, error)
	ReprojectCatalogExtension(context.Context, string, catalog.Halves, catalog.Halves) error
	AppendPublishedPart(context.Context, PublishedPart) error
	AppendPublishedModel(context.Context, PublishedModel) (PublishedModel, error)
}

// CatalogPublicationTxRunner открывает операцию под оградой и замком каталога.
type CatalogPublicationTxRunner interface {
	RunInCatalogPublicationTx(context.Context, func(context.Context, CatalogPublicationWriter) error) error
}

// CatalogPublicationPlan связывает подтверждаемые координаты с результатом
// проверки всей модели и каталога. Номер модели в плане ещё не записан.
type CatalogPublicationPlan struct {
	StateToken      string
	Revision        RevisionReport
	Model           PublishedModel
	declared        Declared
	prior           catalog.Halves
	catalogPrevious *Edition
}

// PlanCatalogPublication разбирает документ после допуска и вычисляет результат
// на том же снимке, который понадобится применителю для повторной сверки.
func PlanCatalogPublication(ctx context.Context, tx CatalogPublicationTxRunner, module string, document []byte, maxBytes int) (CatalogPublicationPlan, error) {
	var plan CatalogPublicationPlan
	err := tx.RunInCatalogPublicationTx(ctx, func(ctx context.Context, writer CatalogPublicationWriter) error {
		m, err := ParseCatalogPublicationDocument(module, document, maxBytes)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPublicationDocument, err)
		}
		plan, err = planCatalogPublicationLocked(ctx, writer, m, document)
		return err
	})
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	return plan, nil
}

// ApplyCatalogPublication повторяет допуск и план, затем фиксирует каталог,
// редакции и аудит одной транзакцией. Повтор принятой декларации возвращает
// подтверждённую редакцию без новой записи.
func ApplyCatalogPublication(ctx context.Context, tx CatalogPublicationTxRunner, module string, document []byte, maxBytes int, expectedState string) (PublishedModel, error) {
	if expectedState == "" {
		return PublishedModel{}, ErrExpectedStateRequired
	}
	principal, verified := operations.PrincipalFromContextOK(ctx)
	who, err := actorOf(laneVerbChecksAnchor, principal, verified)
	if err != nil {
		return PublishedModel{}, err
	}
	var model PublishedModel
	err = tx.RunInCatalogPublicationTx(ctx, func(ctx context.Context, writer CatalogPublicationWriter) error {
		m, err := ParseCatalogPublicationDocument(module, document, maxBytes)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPublicationDocument, err)
		}
		plan, err := planCatalogPublicationLocked(ctx, writer, m, document)
		if err != nil {
			return err
		}
		if plan.Revision.Outcome == RevisionRepeat {
			model = plan.Model
			return nil
		}
		if plan.StateToken != expectedState {
			return ErrStateMoved
		}
		model, err = plan.applyLocked(ctx, writer, who, document)
		return err
	})
	if err != nil {
		return PublishedModel{}, err
	}
	return model, nil
}

func (p CatalogPublicationPlan) applyLocked(ctx context.Context, writer CatalogPublicationWriter, who actor, document []byte) (PublishedModel, error) {
	module := p.declared.Module
	advanced, err := writer.AdvanceRevision(ctx, module, p.Revision.Declared)
	if err != nil {
		return PublishedModel{}, fmt.Errorf("записать редакцию каталога модуля %q: %w", module, err)
	}
	samePrevious := advanced.Previous == nil && p.catalogPrevious == nil ||
		advanced.Previous != nil && p.catalogPrevious != nil && *advanced.Previous == *p.catalogPrevious
	if !advanced.Written || !samePrevious {
		return PublishedModel{}, ErrStateMoved
	}
	report := Report{
		Module:            module,
		ModuleWritten:     advanced.RowCreated,
		DeclaredResources: len(p.declared.Resources),
		DeclaredVerbs:     len(p.declared.Verbs),
		Revision:          p.Revision,
	}
	changes, err := prepareCatalogChangesLocked(ctx, writer, p.declared)
	if err != nil {
		return PublishedModel{}, err
	}
	if len(changes.staleResources) != 0 || len(changes.staleVerbs) != 0 {
		return PublishedModel{}, ErrStateMoved
	}
	if err := applyCatalogChanges(ctx, writer, changes, who, &report); err != nil {
		return PublishedModel{}, err
	}
	state, err := writer.ReadCatalog(ctx)
	if err != nil {
		return PublishedModel{}, err
	}
	installed := catalog.Halves{Live: state.live, Retired: state.retired}
	actual, err := catalog.CanonicalJSON(installed)
	if err != nil {
		return PublishedModel{}, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(actual)) != p.Model.CatalogID {
		return PublishedModel{}, fmt.Errorf("%w: записанный каталог отличается от допущенного", ErrStateMoved)
	}
	if report.WrittenResources != 0 || report.WrittenVerbs != 0 {
		if err := writer.ReprojectCatalogExtension(ctx, module, p.prior, installed); err != nil {
			return PublishedModel{}, fmt.Errorf("расширить проекции ролей модуля %q: %w", module, err)
		}
	}
	if err := writer.AppendPublishedPart(ctx, PublishedPart{Module: module, Edition: *p.Revision.Declared, Document: document}); err != nil {
		return PublishedModel{}, err
	}
	model, err := writer.AppendPublishedModel(ctx, p.Model)
	if err != nil {
		return PublishedModel{}, err
	}
	if model != p.Model {
		return PublishedModel{}, ErrStateMoved
	}
	event := appliedEventOf(who, report, &confirmation{expectedState: p.StateToken})
	event.partEdition = p.Revision.Declared
	event.modelEdition = &Edition{Revision: model.Revision, Digest: model.Digest}
	if err := writer.EmitApplied(ctx, event); err != nil {
		return PublishedModel{}, fmt.Errorf("аудит публикации модуля %q: %w", module, err)
	}
	return model, nil
}

func planCatalogPublicationLocked(ctx context.Context, writer CatalogPublicationWriter, m *manifest.Manifest, document []byte) (CatalogPublicationPlan, error) {
	declared, err := RowsOf(m)
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	current, err := writer.ReadCatalog(ctx)
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	head, err := writer.LatestPublishedModel(ctx)
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	parts, err := writer.LatestPublishedParts(ctx)
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	var previous *Edition
	var catalogPrevious *Edition
	partIndex := -1
	for i := range parts {
		if parts[i].Module != m.Module {
			continue
		}
		if parts[i].Withdrawn || partIndex >= 0 {
			return CatalogPublicationPlan{}, ErrBeyondAnchor
		}
		partIndex = i
		edition := parts[i].Edition
		previous = &edition
		catalogPrevious, err = parts[i].DeclaredEdition()
		if err != nil {
			return CatalogPublicationPlan{}, err
		}
	}
	if namesModule(current.live.Modules, m.Module) != (partIndex >= 0) {
		return CatalogPublicationPlan{}, fmt.Errorf("%w: живой каталог и журнал модуля %q расходятся", ErrBeyondAnchor, m.Module)
	}
	edition := DeclaredEdition(m)
	if edition == nil {
		return CatalogPublicationPlan{}, ErrBeyondAnchor
	}
	outcome := JudgeRevision(previous, edition)
	report := RevisionReport{Outcome: outcome, Declared: edition, Previous: previous}
	if err := refusalOf(m.Module, report); err != nil {
		return CatalogPublicationPlan{}, err
	}
	if err := requireCatalogExtension(current, declared); err != nil {
		return CatalogPublicationPlan{}, err
	}
	prior := catalog.Halves{Live: current.live, Retired: current.retired}
	canonical, err := catalog.CanonicalJSON(prior)
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(canonical)) != head.CatalogID {
		return CatalogPublicationPlan{}, fmt.Errorf("%w: каталог не совпал с журналом активной редакции", ErrStateMoved)
	}
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%d\n%s\n%s\n", head.Revision, head.Digest, edition.Digest)
	_, _ = digest.Write(canonical)
	plan := CatalogPublicationPlan{
		StateToken:      fmt.Sprintf("sha256:%x", digest.Sum(nil)),
		Revision:        report,
		Model:           head,
		declared:        declared,
		prior:           prior,
		catalogPrevious: catalogPrevious,
	}
	if outcome == RevisionRepeat {
		after := current.AfterApplying(declared)
		repeated, err := catalog.CanonicalJSON(catalog.Halves{Live: after.live, Retired: after.retired})
		if err != nil {
			return CatalogPublicationPlan{}, err
		}
		if !bytes.Equal(repeated, canonical) {
			return CatalogPublicationPlan{}, fmt.Errorf("%w: живой каталог модуля %q не соответствует опубликованной редакции", ErrStateMoved, m.Module)
		}
		return plan, nil
	}
	if head.Revision <= 0 || head.Revision == math.MaxInt64 {
		return CatalogPublicationPlan{}, ErrStateMoved
	}
	part := LatestPart{PublishedPart: PublishedPart{Module: m.Module, Edition: *edition, Document: document}}
	if partIndex >= 0 {
		parts[partIndex] = part
	} else {
		parts = append(parts, part)
	}
	text, terms, err := ReconstructPublishedModel(parts)
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	after := current.AfterApplying(declared)
	bundle, err := granteffect.NewBundle(ctx, text, catalog.Halves{Live: after.live, Retired: after.retired},
		granteffect.ProjectorVersion, terms...)
	if err != nil {
		return CatalogPublicationPlan{}, err
	}
	identity := bundle.Identity()
	plan.Model = PublishedModel{
		Revision:  head.Revision + 1,
		Digest:    "sha256:" + identity.ModelID,
		CatalogID: identity.CatalogID,
		Text:      text,
	}
	return plan, nil
}

func requireCatalogExtension(state CatalogState, proposed Declared) error {
	const explanation = "регистрация каталога допускает только добавление типов и действий"
	if namesModule(state.retired.Modules, proposed.Module) {
		return fmt.Errorf("%w: %s: модуль %q снят", ErrBeyondAnchor, explanation, proposed.Module)
	}
	resources := make(map[string]catalog.ResourceRow, len(proposed.Resources))
	types := make(map[string]string, len(proposed.Resources))
	for _, row := range proposed.Resources {
		key := resourcePair(row)
		if owner, exists := types[row.ObjectType]; exists && owner != key {
			return fmt.Errorf("%w: тип %s указан у ресурсов %s и %s", ErrBeyondAnchor, row.ObjectType, owner, key)
		}
		resources[key] = row
		types[row.ObjectType] = key
	}
	verbs := make(map[string]catalog.VerbRow, len(proposed.Verbs))
	for _, row := range proposed.Verbs {
		verbs[verbTriple(row)] = row
	}
	for _, row := range state.live.Resources {
		key := resourcePair(row)
		if owner, exists := types[row.ObjectType]; exists && owner != key {
			return fmt.Errorf("%w: тип %s уже принадлежит %s", ErrBeyondAnchor, row.ObjectType, key)
		}
		if row.Module == proposed.Module {
			next, exists := resources[key]
			if !exists || !next.SameForm(row) {
				return fmt.Errorf("%w: %s: ресурс %s", ErrBeyondAnchor, explanation, key)
			}
		}
	}
	for _, row := range state.live.Verbs {
		if row.Module == proposed.Module {
			key := verbTriple(row)
			next, exists := verbs[key]
			if !exists || !next.SameForm(row) {
				return fmt.Errorf("%w: %s: действие %s", ErrBeyondAnchor, explanation, key)
			}
		}
	}
	for _, row := range state.retired.Resources {
		_, named := resources[resourcePair(row)]
		_, reused := types[row.ObjectType]
		if named || reused {
			return fmt.Errorf("%w: %s: снятый ресурс %s", ErrBeyondAnchor, explanation, resourcePair(row))
		}
	}
	for _, row := range state.retired.Verbs {
		if _, reused := verbs[verbTriple(row)]; reused {
			return fmt.Errorf("%w: %s: снятое действие %s", ErrBeyondAnchor, explanation, verbTriple(row))
		}
	}
	return nil
}
