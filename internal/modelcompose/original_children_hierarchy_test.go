// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	"github.com/stretchr/testify/require"
)

// Исходная фикстура проходит startup-композицию целиком: проект не заменяется
// аккаунтом, publicReadToChildren не удаляется. Отдельные KeyTerms берутся из
// настоящего отчёта Compose; ручного разрешения public_reader здесь нет.
func TestOriginalChildrenManifestAdmitsFiveHopClusterAuthority(t *testing.T) {
	raw, err := publicreadfixture.Read(publicreadfixture.ChildrenProbemodFile)
	require.NoError(t, err)
	require.Contains(t, string(raw), "    parents: [project]")
	require.Contains(t, string(raw), "    publicReadToChildren: true")
	delivered, err := manifest.Load(raw)
	require.NoError(t, err)
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{delivered})
	require.NoError(t, err)
	require.Contains(t, report.KeyTerms, authzmodel.KeyTerm{Type: "probemod_box", Relation: "public_reader"})
	require.Contains(t, report.KeyTerms, authzmodel.KeyTerm{Type: "probemod_item", Relation: "v_get", Pointer: "box"})
	admitted, err := authzmodel.Admit(composed, report.KeyTerms...)
	require.NoError(t, err)
	require.Empty(t, admitted.Findings, "%s", admitted.Census())
	require.True(t, admitted.Admitted())
	plans, err := authzmodel.New(composed)
	require.NoError(t, err)
	tag, err := plans.Plan("probemod_tag", "v_get")
	require.NoError(t, err)
	require.True(t, tag.Expressible())
	cluster := false
	for _, atom := range tag.Atoms {
		if atom.Kind == authzplan.AtomFact && atom.ParentType == "cluster" && atom.Relation == "system_admin" {
			cluster = true
		}
	}
	require.True(t, cluster, "глубокий источник cluster.system_admin потерян")
	// У project есть также короткий pointer cluster. Одного atom недостаточно:
	// проверяем именно полный пятишаговый путь через account, не короткий alias.
	derivations, err := plans.EffectDerivations("probemod_tag", "v_get")
	require.NoError(t, err)
	var paths [][]authzmodel.EffectHop
	for _, source := range derivations {
		if source.Kind == authzplan.AtomFact && source.SourceType == "cluster" && source.SourceRelation == "system_admin" {
			paths = append(paths, source.Path)
		}
	}
	require.Contains(t, paths, []authzmodel.EffectHop{
		{From: "probemod_tag", Pointer: "item", To: "probemod_item"},
		{From: "probemod_item", Pointer: "box", To: "probemod_box"},
		{From: "probemod_box", Pointer: "project", To: "project"},
		{From: "project", Pointer: "account", To: "account"},
		{From: "account", Pointer: "cluster", To: "cluster"},
	})
	item, err := plans.Plan("probemod_item", "v_get")
	require.NoError(t, err)
	publicReader := false
	for _, atom := range item.Atoms {
		if atom.Kind == authzplan.AtomFact && atom.ParentType == "probemod_box" && atom.Relation == "public_reader" {
			publicReader = true
		}
	}
	require.True(t, publicReader, "исходный эффект publicReadToChildren должен сохраниться вместе с глубокой иерархией")
}
