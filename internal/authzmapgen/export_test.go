// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// export_test.go — полоса СИНТЕТИЧЕСКОГО дерева, доступная пробам этого каталога.
//
// Пробы порождения собирают дерево во временном каталоге: индекса у него нет by
// construction, и перечень путей там берётся с диска. Прод-вызывающего у полосы
// нет, поэтому её объявление живёт в пробах — в поставке символа не возникает
// (`architecture.md` §LEAN).
//
// Отдельная полоса нужна не ради удобства: состав индекса читается ОДИН раз за
// прогон и кешируется по корню (pkg/treecorpus), а синтетическое дерево пробы
// МЕНЯЕТСЯ между двумя обходами — приманка подкладывается, манифест дописывается.
// Прогнав синтетику через индексную полосу, проба получила бы на второй обход
// перечень первого и объявила бы «приманку не увидели» свойством продукта.
package authzmapgen

import "github.com/PRO-Robotech/kacho-iam/internal/manifest"

// CollectSynthetic — [Collect] по дереву, репозиторием не являющемуся.
func CollectSynthetic(root string) (Tables, error) {
	return collectReport(root, manifest.CheckSyntheticTreeForGeneration(root))
}

// CheckFreshSynthetic — [CheckFresh] по тому же дереву.
func CheckFreshSynthetic(root string) (Census, error) {
	tables, err := CollectSynthetic(root)
	if err != nil {
		return tables.Census, err
	}
	return compareRendered(root, tables)
}
