// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProducerReceiptTypedSourceAndUnconditionalBoundary(t *testing.T) {
	r := ProducerReceipt{Kind: RegistrationOwnerReceipt, Module: "probe", CatalogType: "probe.item", ObjectType: "probe_item", ObjectID: "i", Relation: "owner", Subject: Subject{Type: SubjectTypeUser, ID: "same"}, Scopes: []ContainerScope{{Registered: true, AccountID: "a", ProjectID: "p"}}}
	require.NoError(t, r.Validate())
	r.Subject.Type = SubjectTypeServiceAccount
	require.NoError(t, r.Validate())
	for _, change := range []func(*ProducerReceipt){func(r *ProducerReceipt) { r.Module = "foreign" }, func(r *ProducerReceipt) { r.Subject.Type = SubjectTypeGroup }, func(r *ProducerReceipt) { r.ConditionName = "mfa" }, func(r *ProducerReceipt) { r.Scopes = nil }, func(r *ProducerReceipt) { r.Subject.ID = "*" }, func(r *ProducerReceipt) { r.Scopes = append(r.Scopes, r.Scopes[0]) }} {
		c := r
		change(&c)
		require.ErrorIs(t, c.Validate(), ErrProducerReceipt)
	}
	r.Kind = PublicationReceipt
	r.Relation = PublicationRelation
	r.Subject = Subject{Type: SubjectTypeSystemClass, ID: "anonymous"}
	require.NoError(t, r.Validate())
	r.Subject.Type = SubjectTypeUser
	require.Error(t, r.Validate())
}
