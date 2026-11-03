// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

// EvidenceDirectory не подставляет необработанную идентичность подтеста Go в путь
// оболочки. Хеширование ПОЛНОЙ идентичности также различает a/b и a-b в отличие
// от замены разделителей или удаления пунктуации. Вызывающий записывает исходную
// идентичность отдельно данными JSON, а не исполняемым синтаксисом оболочки.
func EvidenceDirectory(root, identity string) (string, error) {
	if err := validateStandPath(root); err != nil {
		return "", err
	}
	if identity == "" {
		return "", fmt.Errorf("evidence requires a nonempty test identity")
	}
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(root, fmt.Sprintf("case-%x", digest)), nil
}

// Существующий построитель окружения стенда вычисляет фиксированные имена переменных.
// Поэтому переданные пути PKI/запуска/поставки должны использовать этот ограниченный алфавит ASCII
// до ЛЮБОГО подготовительного подпроцесса или изменения файловой системы. Это
// ограничение тестовой оркестрации, без изменения производственной конфигурации.
func validateStandPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("native stand path must be absolute and canonical")
	}
	for _, c := range path {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '_' || c == '-' {
			continue
		}
		return fmt.Errorf("native stand path contains characters outside its safe path alphabet")
	}
	return nil
}
