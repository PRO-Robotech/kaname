// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Граница касается materialized leaf, а не имени всего вопроса. Пустой leaf
// обычного grant-arm уже проверен native SQL на final DecisionAt. Структурные
// subject/member/parent отношения не становятся выдачами из-за этого списка.
func mutationSourceRelation(relation string) bool {
	if administrativeRelation(relation) {
		return true
	}
	switch relation {
	case "editor", "viewer", "system_viewer", domain.PublicReaderRelation:
		return true
	}
	// Префикс определяет форму глагольного leaf, а не его наличие в каталоге.
	// Даже снятый или неизвестный v_* обязан пройти проверку живого источника:
	// отсутствие строки каталога не превращает его в структурное отношение.
	return strings.HasPrefix(relation, "v_")
}

// Дополнительные глагольные и контейнерные leaf задаёт immutable каталог:
// имя вроде service_account_creator не является структурной связью.
// Это только классификация, не live proof.
func mutationCatalogRelations(halves catalog.Halves) map[[2]string]bool {
	out := make(map[[2]string]bool)
	types := make(map[[2]string]string)
	for _, resource := range halves.Live.Resources {
		types[[2]string{resource.Module, resource.Resource}] = resource.ObjectType
	}
	for _, verb := range halves.Live.Verbs {
		if typ := types[[2]string{verb.Module, verb.Resource}]; typ != "" && verb.PerObject {
			out[[2]string{typ, "v_" + verb.Verb}] = true
		}
		if verb.ContainerParent != "" && verb.ContainerRelation != "" {
			out[[2]string{verb.ContainerParent, verb.ContainerRelation}] = true
		}
	}
	return out
}

// Receipt выбирает только точный tuple. Его active/версии/retirement/catalog
// и живые scopes проверяет общий канонический reader на той же транзакции.
// Неактивный известный источник даёт DENY; отсутствие происхождения — UNKNOWN.
// Никакого actor-wide обхода или сохранения proof между Check здесь нет.
func (s *nativeAdministrativeSources) producerFact(ctx context.Context, fact relverdict.AdministrativeFact, budget *relverdict.AdministrativeReadBudget) (bool, bool, error) {
	if err := budget.Charge(1, 1); err != nil {
		return false, false, err
	}
	var known bool
	err := s.transaction().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.producer_source_receipt WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject_type||':'||subject_id=$4 AND kind IN ('registration_owner','publication'))`, fact.ObjectType, fact.ObjectID, fact.Relation, fact.Subject).Scan(&known)
	if err != nil || !known {
		return false, known, err
	}
	typ, id, ok := strings.Cut(fact.QuestionSubject, ":")
	actor := domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}
	if !ok || actor.Validate() != nil || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return false, known, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	proof := &semanticAuthorityWriteTx{authorityWriteTx: s.w, bundle: s.bundle}
	cursor := ""
	var unconfirmed bool
	for {
		if err = ctx.Err(); err != nil {
			return false, known, err
		}
		if err = budget.Charge(0, 1); err != nil {
			return false, known, err
		}
		page, next, e := proof.producerSourcesQueryForFact(ctx, kaname.CanonicalSourceFilter{Actor: actor, After: cursor, Limit: 1}, nil, &fact)
		if e != nil {
			return false, known, e
		}
		if e = budget.Charge(page.Cost.Rows, page.Cost.Reads-1); e != nil {
			return false, known, e
		}
		for _, source := range page.Sources {
			r := source.Receipt
			if source.Identity != s.bundle.Identity() || r.Validate() != nil || r.ObjectType != fact.ObjectType || r.ObjectID != fact.ObjectID || r.Relation != fact.Relation || domain.FGASubjectRef(string(r.Subject.Type), string(r.Subject.ID)) != fact.Subject {
				return false, known, relverdict.ErrAdministrativeSourceUnconfirmed
			}
			if source.Issue == "" {
				return true, known, nil
			}
			unconfirmed = true
		}
		if next == "" {
			break
		}
		if next == cursor {
			return false, known, relverdict.ErrAdministrativeSourceUnconfirmed
		}
		cursor = next
	}
	if unconfirmed {
		return false, known, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	return false, known, nil
}
