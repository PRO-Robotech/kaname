// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// ParseCatalogPublicationDocument разбирает декларацию типов и действий.
// module задаёт уже авторизованную цель запроса, а не берётся из документа.
// Пространство типов выводится на сервере; пользователь не задаёт свой префикс.
// Сравнение с живой редакцией, запрет сужения и коллизии с другими владельцами
// проверяются отдельно, под замком каталога, до записи.
func ParseCatalogPublicationDocument(module string, document []byte, maxBytes int) (*manifest.Manifest, error) {
	if !domain.IsWellFormedModuleName(module) || module == "iam" {
		return nil, errors.New("module: требуется допустимое имя бизнес-модуля")
	}
	if maxBytes <= 0 {
		return nil, errors.New("catalog publication: требуется положительный предел размера документа")
	}
	if len(document) == 0 || len(document) > maxBytes {
		return nil, fmt.Errorf("document: требуется непустой документ размером не более %d байт", maxBytes)
	}
	m, err := loadCatalogPublicationManifest(module, document)
	if err != nil {
		return nil, fmt.Errorf("декларация каталога: %w", err)
	}
	if DeclaredEdition(m) == nil {
		return nil, errors.New("revision: обязательна для публикации")
	}
	if len(m.Resources) == 0 {
		return nil, errors.New("resources: требуется непустой перечень типов; пустой документ не снимает модуль")
	}
	switch {
	case m.RolesDeclared():
		return nil, errors.New("roles: регистрация каталога принимает только типы и действия")
	case m.Seed != nil:
		return nil, errors.New("seed: посев применяется отдельной операцией")
	case len(m.DeprecatedVerbs) != 0:
		return nil, errors.New("deprecatedVerbs: регистрация каталога добавляет действия")
	}

	prefix := strings.ReplaceAll(module, "-", "_") + "_"
	own := make(map[string]struct{}, len(m.Resources))
	for i, resource := range m.Resources {
		if !strings.HasPrefix(resource.ObjectType, prefix) {
			return nil, fmt.Errorf("resources[%d].objectType: требуется пространство типов модуля %q с префиксом %q", i, module, prefix)
		}
		own[resource.ObjectType] = struct{}{}
	}
	for i, resource := range m.Resources {
		for j, parent := range resource.Parents {
			if parent.Type == "project" || parent.Type == "cluster" {
				continue
			}
			if _, declared := own[parent.Type]; !declared {
				return nil, fmt.Errorf("resources[%d].parents[%d]: допустимы свои объявленные типы, project и cluster", i, j)
			}
		}
	}
	return m, nil
}

// Части читаются для композиции до проверки их отношений в итоговой модели.
func loadCatalogPublicationManifest(module string, document []byte) (*manifest.Manifest, error) {
	m, err := manifest.Load(document)
	if err != nil {
		return nil, err
	}
	if m.Module != module {
		return nil, fmt.Errorf("module: документ объявляет %q, запрошен %q", m.Module, module)
	}
	return m, nil
}
