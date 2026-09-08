// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rightsfixture — ПРОИЗВОДИТЕЛЬ ПРАВИЛ роли для проб (kacho#1998).
//
// # Зачем отдельный пакет, а не по копии в каждой пробе
//
// Применитель ролей модуля берёт правила у экспортёра, а тому нужны две
// величины: каталожный факт и записи каталога прав. Собираются они всегда
// одинаково — тем же способом, каким их собирает команда обхода дерева
// (`tools/modulemanifestcheck`), — и нужны пробам ТРЁХ пакетов сразу. Копия в
// каждом была бы тремя местами об одном предмете; разойдясь, они дали бы пробы,
// зелёные по разным каталогам.
//
// # Почему фикстура НЕ снисходительнее продукта
//
// Она не подставляет производителя, отвечающего «сведено» без проверки: строит
// НАСТОЯЩИЙ `moduleroles.NewRightsExport` над `seed.LiteralRows()` и над
// встроенным каталогом прав — ровно теми, что читает исполнитель обхода дерева.
// Дублёр, принимающий больше настоящего, сделал бы невидимым тот самый дефект,
// ради которого его подставляют.
package rightsfixture

import (
	"context"
	"log/slog"
	"os"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
)

// Export — производитель правил роли над посеянным каталогом.
//
// Паникует на невозможном — пустом каталожном факте или пустой привязке
// действий: и то и другое означает сломанный производитель посева, и проба на
// такой фикстуре считала бы полноту перечня по НУЛЮ классов, ничего об этом не
// сказав.
func Export() moduleroles.RightsExport {
	facts, err := catalog.NewFacts(seed.LiteralRows())
	if err != nil {
		panic("rightsfixture: каталожный факт не собран: " + err.Error())
	}
	reg, rerr := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if rerr != nil {
		panic("rightsfixture: каталог прав не прочитан: " + rerr.Error())
	}
	rows := reg.All()
	entries := make([]roleexport.CatalogEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, roleexport.CatalogEntry{
			FQN:              r.FQN,
			RequiredRelation: r.RequiredRelation,
			ScopeObjectType:  r.ScopeExtractor.ObjectType,
		})
	}
	actions, _ := roleexport.Attribute(entries)
	x, xerr := moduleroles.NewRightsExport(facts, actions)
	if xerr != nil {
		panic("rightsfixture: производитель правил не собран: " + xerr.Error())
	}
	return x
}
