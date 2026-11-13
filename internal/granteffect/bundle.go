// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

// ProjectorVersion обозначает семантику Compile/CompileDirect и нормализации
// селекторов этого пакета. При изменении смысла проекции версия меняется явно;
// это не версия carrier и не признак готовности миграции/роли.
const ProjectorVersion = "granteffect/v1"

var ErrInvalidBundle = errors.New("invalid semantic bundle")

// Bundle закрепляет допущенный текст, Plans и Facts одного построения. У него
// нет методов изменения и доступа к Model(), Compiler или mutable Facts.
// Нулевое значение непригодно. Identity само по себе не удостоверяет БД.
type Bundle struct {
	compiler         *Compiler
	modelSource      string
	canonicalCatalog []byte
}

func NewBundle(ctx context.Context, modelSource string, halves catalog.Halves, version string, keyTerms ...authzmodel.KeyTerm) (*Bundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if version != ProjectorVersion || modelSource == "" || len(modelSource) > MaxInputBytes {
		return nil, ErrInvalidBundle
	}
	input, err := json.Marshal(halves)
	if err != nil || len(input) > MaxInputBytes {
		return nil, ErrInvalidBundle
	}
	raw, err := catalog.CanonicalJSON(halves)
	if err != nil {
		return nil, fmt.Errorf("%w: catalog: %v", ErrInvalidBundle, err)
	}
	if len(raw) > MaxInputBytes {
		return nil, ErrInvalidBundle
	}
	// И допуск, и компиляция получают один текст, без глобального Shared.
	admission, err := authzmodel.Admit(modelSource, keyTerms...)
	if err != nil {
		return nil, fmt.Errorf("%w: admission: %v", ErrInvalidBundle, err)
	}
	if !admission.Judged || len(admission.Findings) != 0 ||
		(!admission.Admitted() && !(admission.NothingToJudge && modelSource == authzmodel.DSL)) {
		return nil, fmt.Errorf("%w: admission %s", ErrInvalidBundle, admission.Census())
	}
	var pinned catalog.Halves
	if err = json.Unmarshal(raw, &pinned); err != nil {
		return nil, err
	}
	c, err := New(modelSource, pinned)
	if err != nil {
		return nil, fmt.Errorf("%w: compiler: %v", ErrInvalidBundle, err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return &Bundle{compiler: c, modelSource: modelSource, canonicalCatalog: raw}, nil
}

// Validate проверяет построение, а не актуальность модели в БД.
func (b *Bundle) Validate() error {
	if b == nil || b.compiler == nil || b.modelSource == "" || len(b.canonicalCatalog) == 0 ||
		b.compiler.identity.ProjectorVersion != ProjectorVersion {
		return ErrInvalidBundle
	}
	return nil
}
func (b *Bundle) Identity() grantcoverage.Identity {
	if b.Validate() != nil {
		return grantcoverage.Identity{}
	}
	return b.compiler.identity
}
func (b *Bundle) ModelSource() string {
	if b.Validate() != nil {
		return ""
	}
	return b.modelSource
}
func (b *Bundle) CanonicalCatalog() []byte {
	if b.Validate() != nil {
		return nil
	}
	return slices.Clone(b.canonicalCatalog)
}
func (b *Bundle) Compile(in Binding) Set {
	if b.Validate() != nil {
		return Set{}
	}
	return b.compiler.Compile(in)
}
func (b *Bundle) CompileDirect(in Direct) Set {
	if b.Validate() != nil {
		return Set{}
	}
	return b.compiler.CompileDirect(in)
}

// Plan возвращает независимые срезы: кэш Plans не становится изменяемым через
// native checker или через его вызывающего.
func (b *Bundle) Plan(typ, relation string) (authzplan.Plan, error) {
	if err := b.Validate(); err != nil {
		return authzplan.Plan{}, err
	}
	p, err := b.compiler.plans.Plan(typ, relation)
	if err != nil {
		return authzplan.Plan{}, err
	}
	p.Atoms = slices.Clone(p.Atoms)
	p.Conditioned = slices.Clone(p.Conditioned)
	p.Unclassified = slices.Clone(p.Unclassified)
	return p, nil
}
func (b *Bundle) GrantCapabilityPlan(typ, relation string) error {
	if err := b.Validate(); err != nil {
		return err
	}
	return b.compiler.plans.GrantCapabilityPlan(typ, relation)
}

// GrantSelectors — проекция ordinary rules на тех же Facts, что у Compile.
// Это не proof полноты: wildcard producer и capability split судит Compile.
// Копия на входе разрывает ссылки на авторские карты/срезы правил.
func (b *Bundle) GrantSelectors(rules domain.Rules, policy domain.RulePolicy, scope domain.ScopeAnchor) ([]domain.RuleSelector, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if !domain.IsScopeAnchorKind(scope.Type) || domain.DeriveFromResourceType(scope.Type).ValidateAgainst(scope.Type, scope.ID) != nil {
		return nil, fmt.Errorf("invalid selector scope")
	}
	raw, err := json.Marshal(rules)
	if err != nil || len(raw) > MaxInputBytes {
		return nil, fmt.Errorf("invalid selector input")
	}
	var copy domain.Rules
	if err = json.Unmarshal(raw, &copy); err != nil {
		return nil, err
	}
	if err = copy.Validate(policy, b.compiler.facts); err != nil {
		return nil, err
	}
	return b.compiler.facts.GrantSelectors(copy.MaterializingSelectorsInScope(domain.DeriveFromResourceType(scope.Type)), policy), nil
}
