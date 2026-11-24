// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifestoracle"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
)

// PublishedPart содержит исходный документ и проверяемую редакцию журнала.
type PublishedPart struct {
	Module   string
	Edition  Edition
	Document []byte
}

// LatestPart связывает последнюю редакцию с состоянием модуля в том же снимке.
type LatestPart struct {
	PublishedPart
	Withdrawn bool
}

// NewBaselinePublishedPart сохраняет исходный документ установленного модуля.
// У старого манифеста без revision номер 1 служит порядком в журнале.
func NewBaselinePublishedPart(module string, document []byte) (PublishedPart, error) {
	m, err := loadCatalogPublicationManifest(module, document)
	if err != nil {
		return PublishedPart{}, err
	}
	return PublishedPart{Module: module, Edition: archivedEdition(m), Document: bytes.Clone(document)}, nil
}

// DeclaredEdition сверяет документ с журналом и возвращает координаты,
// которые должны быть в установленном каталоге. У старого документа это nil.
func (p PublishedPart) DeclaredEdition() (*Edition, error) {
	m, err := p.parse()
	if err != nil {
		return nil, err
	}
	return DeclaredEdition(m), nil
}

func archivedEdition(m *manifest.Manifest) Edition {
	if edition := DeclaredEdition(m); edition != nil {
		return *edition
	}
	return Edition{Revision: 1, Digest: m.Digest()}
}

func (p PublishedPart) parse() (*manifest.Manifest, error) {
	m, err := loadCatalogPublicationManifest(p.Module, p.Document)
	if err != nil {
		return nil, fmt.Errorf("разобрать опубликованный документ модуля %q: %w", p.Module, err)
	}
	if archivedEdition(m) != p.Edition {
		return nil, fmt.Errorf("документ модуля %q не совпал с редакцией %d", p.Module, p.Edition.Revision)
	}
	return m, nil
}

// ReconstructPublishedModel восстанавливает текст и исключения допуска из
// документов с подтверждёнными отпечатками. Снятые части сохраняются в журнале.
func ReconstructPublishedModel(parts []LatestPart) (string, []authzmodel.KeyTerm, error) {
	seen := make(map[string]struct{}, len(parts))
	active := make([]*manifest.Manifest, 0, len(parts))
	for _, part := range parts {
		if _, duplicate := seen[part.Module]; duplicate {
			return "", nil, fmt.Errorf("повторная опубликованная часть %q", part.Module)
		}
		seen[part.Module] = struct{}{}
		if part.Withdrawn {
			continue
		}
		m, err := part.parse()
		if err != nil {
			return "", nil, err
		}
		active = append(active, m)
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Module < active[j].Module })
	model, report, err := modelcompose.Compose(authzmodel.DSL, active)
	if err != nil {
		return "", nil, err
	}
	plans, err := authzmodel.New(model)
	if err != nil {
		return "", nil, err
	}
	oracle := manifestoracle.FromPlans(plans)
	for _, part := range parts {
		if part.Withdrawn {
			continue
		}
		if _, err := manifest.Load(part.Document, manifest.WithRelationOracle(oracle)); err != nil {
			return "", nil, fmt.Errorf("модуль %q в восстановленной модели: %w", part.Module, err)
		}
	}
	return model, report.KeyTerms, nil
}
