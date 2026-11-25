// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// resourceDecisionProposal — сериализованный запрос закрытого compiler, а не аттестация.
// Сервер обязан вывести область из текущих строк и самого намерения, проверить
// полноту и получить все waits. Нельзя принять список caller keys как proof.
type resourceDecisionProposal struct {
	intent   json.RawMessage
	payload  json.RawMessage
	lifetime *resourceAttemptLifetime
	prepared *authorityWriteTx
	catalogs []string
}

type resourceProposalSource struct {
	Kind       resourceSourceKind `json:"kind"`
	Type       string             `json:"type"`
	ID         string             `json:"id"`
	Projection string             `json:"projection"`
	States     []string           `json:"states"`
}

func resourceSourceProposal(key resourceSourceKey, rows []resourceSourceRow) resourceProposalSource {
	item := resourceProposalSource{Kind: key.kind, Type: key.typ, ID: key.id, Projection: key.projection, States: make([]string, 0, len(rows))}
	for _, row := range rows {
		item.States = append(item.States, row.state)
	}
	slices.Sort(item.States)
	return item
}

type resourceProposalCatalog struct {
	Input  string   `json:"input"`
	States []string `json:"states"`
}
type resourceProposalInstallation struct {
	Account    domain.AccountID `json:"account"`
	Assignment string           `json:"assignment"`
	Binding    string           `json:"binding"`
	State      string           `json:"state"`
}
type resourceProposalEnvelope struct {
	RefusalEffects      *resourceRefusalEffectProposal      `json:"refusal_effects,omitempty"`
	RegistrationEffects *resourceRegistrationEffectProposal `json:"registration_effects,omitempty"`
	ObjectEffects       *resourceObjectEffectProposal       `json:"object_effects,omitempty"`
	SourceEffects       []resourceSourceEffect              `json:"source_effects"`
	ABI                 int                                 `json:"abi"`
	Intent              json.RawMessage                     `json:"intent"`
	Owners              []kaname.AuthorityOwnerRef          `json:"owners"`
	Objects             []domain.ResourceRef                `json:"objects"`
	Registration        []domain.AccountID                  `json:"registration_accounts"`
	Sources             []resourceProposalSource            `json:"sources"`
	Catalogs            []resourceProposalCatalog           `json:"catalogs"`
	Service             string                              `json:"service"`
	Actor               string                              `json:"actor"`
	Installation        []resourceProposalInstallation      `json:"installation"`
	NativeGuards        []string                            `json:"native_guards"`
	NativeEpochs        json.RawMessage                     `json:"native_epochs"`
	PredicateGuards     []resourcePredicateProtection       `json:"predicate_guards"`
}

func makeResourceRegistrationProposal(in kaname.ResourceDecisionIntent, parents *resourceParentCapture, footprint resourceFenceFootprint, stage *resourceRegistrationStage) (*resourceDecisionProposal, error) {
	if in.Action == kaname.ResourceDecisionRecordRefusal || stage == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	intent, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	envelope, catalogs, err := makeResourceProposalEnvelope(intent, parents, footprint)
	if err != nil {
		return nil, err
	}
	if stage != nil {
		if stage.source != parents.source || stage.installation == nil || stage.native == nil || stage.native.lifetime != parents.source.lifetime || stage.installation.lifetime != parents.source.lifetime {
			return nil, kaname.ErrSourceUnconfirmed
		}
		envelope.RegistrationEffects, err = makeResourceRegistrationEffectProposal(stage)
		if err != nil {
			return nil, err
		}
		envelope.Service, envelope.Actor = stage.installation.serviceName, stage.installation.actor
		envelope.NativeGuards = slices.Clone(stage.native.guards)
		envelope.NativeEpochs = slices.Clone(stage.native.epochs)
		for _, account := range stage.installation.accounts {
			for _, witness := range stage.installation.sources[account] {
				envelope.Installation = append(envelope.Installation, resourceProposalInstallation{Account: account, Assignment: witness.assignment, Binding: witness.binding, State: witness.state})
			}
		}
	}
	return finishResourceDecisionProposal(envelope, parents.source.lifetime, catalogs)
}

// Общая оболочка переносит только server-captured данные. И registration, и
// object route проходят один prewait/recheck/finalize; JSON не становится proof.
func makeResourceProposalEnvelope(intent json.RawMessage, parents *resourceParentCapture, footprint resourceFenceFootprint) (resourceProposalEnvelope, []string, error) {
	if parents == nil || parents.source == nil || parents.source.sealed || parents.source.lifetime == nil || parents.source.lifetime.prepared != nil || !json.Valid(intent) {
		return resourceProposalEnvelope{}, nil, kaname.ErrSourceUnconfirmed
	}
	envelope := resourceProposalEnvelope{SourceEffects: slices.Clone(footprint.sourceEffects), ABI: 2, Intent: intent, Owners: slices.Clone(footprint.owners), Objects: slices.Clone(footprint.objects), Registration: slices.Clone(footprint.registration), NativeEpochs: json.RawMessage("{}")}
	for key, rows := range parents.source.entries {
		envelope.Sources = append(envelope.Sources, resourceSourceProposal(key, rows))
		if key.kind == resourceSourceSelectorObjects || key.kind == resourceSourceNestedDescendants {
			protection, err := classifyResourcePredicate(key)
			if err != nil {
				return resourceProposalEnvelope{}, nil, err
			}
			if protection.Global && footprint.plan.Mode != kaname.AuthorityFenceGlobal {
				return resourceProposalEnvelope{}, nil, kaname.ErrSourceUnconfirmed
			}
			envelope.PredicateGuards = append(envelope.PredicateGuards, protection)
		}
	}
	slices.SortFunc(envelope.Sources, func(a, b resourceProposalSource) int {
		if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return cmp.Compare(a.Projection, b.Projection)
	})
	slices.SortFunc(envelope.PredicateGuards, func(a, b resourcePredicateProtection) int { return cmp.Compare(a.Source, b.Source) })
	catalogs := make([]string, 0, len(parents.catalogs))
	for key := range parents.catalogs {
		catalogs = append(catalogs, key)
	}
	slices.Sort(catalogs)
	for _, key := range catalogs {
		captured := parents.catalogs[key]
		if captured == nil || captured.input != key {
			return resourceProposalEnvelope{}, nil, kaname.ErrSourceUnconfirmed
		}
		item := resourceProposalCatalog{Input: key, States: make([]string, 0, len(captured.rows))}
		for _, row := range captured.rows {
			item.States = append(item.States, row.state)
		}
		envelope.Catalogs = append(envelope.Catalogs, item)
	}
	return envelope, catalogs, nil
}

func finishResourceDecisionProposal(envelope resourceProposalEnvelope, lifetime *resourceAttemptLifetime, catalogs []string) (*resourceDecisionProposal, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return &resourceDecisionProposal{intent: envelope.Intent, payload: payload, lifetime: lifetime, catalogs: catalogs}, nil
}

// Единственный блокирующий SQL этап после coordinator. Счётчики внутри SQL
// имеют переданные остатки; overbound завершается ошибкой и rollback, а не
// частичным manifest. Returned rows/reads списываются с общей RR+RC попытки.
func (p *resourceDecisionProposal) prewait(ctx context.Context, w *authorityWriteTx, budget *relverdict.AdministrativeReadBudget) error {
	if p == nil || p.prepared != nil || !p.lifetime.beforeDecision(w) || budget == nil || len(p.payload) == 0 {
		return kaname.ErrSourceUnconfirmed
	}
	if budget.RemainingReads() == 0 || budget.RemainingRows() == 0 {
		return kaname.ErrSourceReadLimit
	}
	if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return err
	}
	var rows, reads int
	if err := w.tx.QueryRow(ctx, `SELECT logical_rows,logical_reads FROM kaname.authority_resource_prewait_v2($1::jsonb,$2,$3)`, p.payload, budget.RemainingRows(), budget.RemainingReads()).Scan(&rows, &reads); err != nil {
		return err
	}
	if err := chargeNativePolicyBudget(budget, rows, reads); err != nil {
		return err
	}
	p.prepared = w
	return ctx.Err()
}

func (p *resourceDecisionProposal) recheckCatalogs(ctx context.Context, w *authorityWriteTx, parents *resourceParentCapture) error {
	if p == nil || p.prepared != w || !p.lifetime.beforeDecision(w) || parents == nil || parents.source == nil || parents.source.lifetime != p.lifetime || !parents.source.sealed || len(parents.catalogs) != len(p.catalogs) {
		return kaname.ErrSourceUnconfirmed
	}
	for _, key := range p.catalogs {
		captured := parents.catalogs[key]
		if captured == nil {
			return kaname.ErrSourceUnconfirmed
		}
		if err := captured.recheck(ctx, w.tx, parents.source.budget); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Эта функция не получает locks. SQL проверяет ранее удержанный private
// manifest, сравнивает ожидаемые epochs и выставляет единственный final clock.
// Последующие native/installation reads используют этот момент без обновления.
func (p *resourceDecisionProposal) finalize(ctx context.Context, w *authorityWriteTx, lifetime *resourceAttemptLifetime, budget *relverdict.AdministrativeReadBudget) error {
	if p == nil || p.prepared != w || p.lifetime != lifetime || !lifetime.beforeDecision(w) || budget == nil {
		return kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return err
	}
	var at time.Time
	var rows, reads int
	if err := w.tx.QueryRow(ctx, `SELECT decision_at,logical_rows,logical_reads FROM kaname.authority_resource_finalize_v2($1::jsonb,$2,$3)`, p.intent, budget.RemainingRows(), budget.RemainingReads()).Scan(&at, &rows, &reads); err != nil {
		return err
	}
	if err := chargeNativePolicyBudget(budget, rows, reads); err != nil {
		return err
	}
	if at.IsZero() {
		return kaname.ErrSourceUnconfirmed
	}
	w.fence.decisionAt = at.UTC()
	if err := lifetime.bind(w); err != nil {
		return err
	}
	return ctx.Err()
}
