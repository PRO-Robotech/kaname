// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/stretchr/testify/require"
)

type participationHandoffProbe struct {
	called int
	model  string
	keys   []authzmodel.KeyTerm
	err    error
	bundle *granteffect.Bundle
}

func (p *participationHandoffProbe) LoadAuthorityBundle(_ context.Context, m string, k ...authzmodel.KeyTerm) (*granteffect.Bundle, error) {
	p.called++
	p.model = m
	p.keys = append([]authzmodel.KeyTerm(nil), k...)
	return p.bundle, p.err
}
func TestGroupParticipationHandoffNeverFallsBack(t *testing.T) {
	p := &participationHandoffProbe{err: errors.New("transition")}
	m := preparedModel{text: "composed source"}
	b, err := loadGroupParticipationBundle(context.Background(), config.AuthorityProtocolConfig{Participation: "legacy"}, p, m)
	require.NoError(t, err)
	require.Nil(t, b)
	require.Zero(t, p.called)
	b, err = loadGroupParticipationBundle(context.Background(), config.AuthorityProtocolConfig{Participation: "participant"}, p, m)
	require.Error(t, err)
	require.Nil(t, b)
	require.Equal(t, 1, p.called)
	require.Equal(t, m.text, p.model)
	p.err = nil
	b, err = loadGroupParticipationBundle(context.Background(), config.AuthorityProtocolConfig{Participation: "participant"}, p, m)
	require.Error(t, err)
	require.Nil(t, b)
	b, err = loadGroupParticipationBundle(context.Background(), config.AuthorityProtocolConfig{Participation: "typo"}, p, m)
	require.Error(t, err)
	require.Nil(t, b)
	require.Equal(t, 2, p.called)
}

func TestGroupParticipationHandoffAcceptsActualAdmittedBundle(t *testing.T) {
	model, err := prepareComposedModel(quietLogger(), nil)
	require.NoError(t, err)
	rows := catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "account", ObjectType: "account"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "account", Verb: "get", PerObject: true}}}}
	b, err := granteffect.NewBundle(context.Background(), model.text, rows, granteffect.ProjectorVersion, model.report.KeyTerms...)
	require.NoError(t, err)
	p := &participationHandoffProbe{bundle: b}
	got, err := loadGroupParticipationBundle(context.Background(), config.AuthorityProtocolConfig{Participation: "participant"}, p, model)
	require.NoError(t, err)
	require.Same(t, b, got)
	require.Equal(t, model.text, p.model)
	require.Equal(t, model.report.KeyTerms, p.keys)
}
