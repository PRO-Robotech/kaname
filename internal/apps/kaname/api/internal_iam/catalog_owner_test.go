// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

// Намеренно конечный каталог: ни префикс типа, ни вызывающий не задают
// владельца. Транзакция и чтения отслеживаются независимо от полномочий.
type ownerCatalog struct {
	typ, owner                 string
	live, known                bool
	policyReads, identityReads int
	tx                         service.Tx
	pointers                   []domain.ParentPointer
}

func (c *ownerCatalog) WritePolicyTx(_ context.Context, tx service.Tx, typ string) (string, domain.WritePolicy, bool, error) {
	c.policyReads++
	c.tx = tx
	if typ != c.typ || !c.live || !c.known {
		return "", domain.WritePolicy{}, false, nil
	}
	pointers := c.pointers
	if pointers == nil {
		pointers = []domain.ParentPointer{{Name: "project", Type: "project"}}
	}
	return c.owner + ".resource", domain.WritePolicy{Module: c.owner, ObjectType: c.typ, Pointers: pointers}, true, nil
}
func (c *ownerCatalog) CatalogTypeTx(_ context.Context, tx service.Tx, typ string) (domain.CatalogTypeIdentity, bool, error) {
	c.identityReads++
	c.tx = tx
	if typ != c.typ || !c.known {
		return domain.CatalogTypeIdentity{}, false, nil
	}
	return domain.CatalogTypeIdentity{Dotted: c.owner + ".resource", Module: c.owner, ObjectType: c.typ}, true, nil
}

type ownerScopes struct {
	sceneScopes
	reads int
	tx    service.Tx
}

func (s *ownerScopes) ProjectAccountTx(ctx context.Context, tx service.Tx, id string) (string, bool, error) {
	s.reads++
	s.tx = tx
	return s.sceneScopes.ProjectAccountTx(ctx, tx, id)
}

func TestRegistrationCatalogOwnerBeforeHierarchyAndWrites(t *testing.T) {
	for _, c := range []struct {
		name, actor, typ, owner string
		live                    bool
		want                    codes.Code
	}{
		{"dynamic-owner", "probemod", "probemod_box", "probemod", true, codes.OK},
		{"standard-owner", "vpc", "vpc_network", "vpc", true, codes.OK},
		{"service-alias", "nlb", "nlb_listener", "loadbalancer", true, codes.OK},
		{"catalog-owner-not-prefix", "probemod", "registry_forged", "probemod", true, codes.OK},
		{"forged-prefix", "registry", "registry_forged", "probemod", true, codes.PermissionDenied},
		{"foreign-known-module", "registry", "probemod_box", "probemod", true, codes.PermissionDenied},
		{"missing-canonical-owner", "probemod", "probemod_box", "", true, codes.PermissionDenied},
		{"wildcard-actor", "*", "probemod_box", "probemod", true, codes.PermissionDenied},
		{"empty-actor", "", "probemod_box", "probemod", true, codes.PermissionDenied},
		{"unknown-catalog-type", "probemod", "probemod_unknown", "probemod", false, codes.InvalidArgument},
	} {
		t.Run(c.name, func(t *testing.T) {
			catalog := &ownerCatalog{typ: c.typ, owner: c.owner, live: c.live, known: c.live}
			scopes := &ownerScopes{sceneScopes: unitScopes()}
			txb := &smTxBeginner{}
			mirror := newMirrorSpy()
			authority := registrationwriterfixture.Authority{Module: c.actor}
			if c.actor == "nlb" {
				authority.CatalogModule = "loadbalancer"
			}
			uc := NewRegisterResourceUseCase(smEmitter{}, mirror, txb, catalog, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, scopes).
				WithRegistrationAuthority(authority)
			err := uc.Register(context.Background(), &regReq{subject: "project:" + unitProject, relation: "project", object: c.typ + ":one"})
			require.Equal(t, c.want, status.Code(err))
			if c.want == codes.OK {
				require.Equal(t, 1, catalog.policyReads, "owner and policy must use one read")
				require.Zero(t, catalog.identityReads, "registration must not reread ownership")
				require.Same(t, txb.tx, catalog.tx)
				require.Same(t, txb.tx, scopes.tx)
				require.True(t, txb.tx.committed)
				require.Equal(t, 1, mirror.upserts)
			} else {
				require.Zero(t, scopes.reads, "owner refusal must precede hierarchy reads")
				require.Zero(t, mirror.upserts)
				require.Zero(t, mirror.deletes)
				if txb.tx != nil {
					require.False(t, txb.tx.committed)
				}
				if c.actor == "" || c.actor == "*" {
					require.Nil(t, txb.tx)
					require.Zero(t, catalog.policyReads)
				}
				if c.want == codes.PermissionDenied {
					require.Equal(t, "permission denied", status.Convert(err).Message())
					require.Empty(t, status.Convert(err).Details())
				}
			}
		})
	}
}

func TestRegistrationShapeRetainsClosedGuardsForDynamicActor(t *testing.T) {
	for _, c := range []struct{ name, subject, relation, object string }{
		{"iam-type", "user:u", "owner", "account:a"},
		{"privilege", "user:u", "editor", "probemod_box:b"},
		{"hierarchy-class", "system_class:anonymous", "owner", "probemod_box:b"},
		{"dynamic-publication", "system_class:anonymous", "v_get", "probemod_box:b"},
	} {
		t.Run(c.name, func(t *testing.T) {
			txb := &smTxBeginner{}
			uc := NewRegisterResourceUseCase(smEmitter{}, newMirrorSpy(), txb, &ownerCatalog{}, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, unitScopes()).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"})
			err := uc.Register(context.Background(), &regReq{subject: c.subject, relation: c.relation, object: c.object})
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.Nil(t, txb.tx)
		})
	}
}

func TestCleanupCatalogOwnerRetiredAndUnknown(t *testing.T) {
	for _, c := range []struct {
		name, actor, owner, typ, subject, relation string
		known                                      bool
		want                                       codes.Code
	}{
		{"retired-own", "probemod", "probemod", "probemod_box", "project:p", "project", true, codes.OK},
		{"retired-foreign", "registry", "probemod", "probemod_box", "project:p", "project", true, codes.PermissionDenied},
		// Внутренний порт уже получил каталоговое имя из доверенного перечня.
		{"retired-alias", "loadbalancer", "loadbalancer", "nlb_listener", "project:p", "project", true, codes.OK},
		{"unknown-type", "probemod", "probemod", "probemod_box", "project:p", "project", false, codes.PermissionDenied},
		{"retired-publication-own", "registry", "registry", "registry_repository", "system_class:anonymous", "v_get", true, codes.OK},
		{"retired-publication-foreign", "registry", "probemod", "registry_repository", "system_class:anonymous", "v_get", true, codes.PermissionDenied},
	} {
		t.Run(c.name, func(t *testing.T) {
			catalog := &ownerCatalog{typ: c.typ, owner: c.owner, known: c.known, live: false}
			uc := &RegisterResourceUseCase{catalogTypes: catalog}
			tx := &smTx{}
			dotted, err := uc.authorizeCatalogType(context.Background(), tx, c.actor, tupleIntent{subject: c.subject, relation: c.relation, object: c.typ + ":one"})
			require.Equal(t, c.want, status.Code(err))
			require.Equal(t, 1, catalog.identityReads)
			require.Zero(t, catalog.policyReads, "cleanup/publication must not consult current writes or require live type")
			require.Same(t, tx, catalog.tx)
			if c.want == codes.OK {
				require.Equal(t, c.owner+".resource", dotted)
			} else {
				require.Empty(t, dotted)
			}
		})
	}
}

func TestRegistrationPrincipalPointerRefusedBeforeCatalogAndWrites(t *testing.T) {
	for _, subject := range []string{"user:u", "service_account:s", "group:g", "system_class:anonymous", "probemod_box:*", "*:id"} {
		for _, live := range []bool{false, true} {
			name := subject + "/unknown"
			if live {
				name = subject + "/live"
			}
			t.Run(name, func(t *testing.T) {
				catalog := &ownerCatalog{typ: "probemod_item", owner: "probemod", live: live, known: live}
				txb := &smTxBeginner{}
				mirror := newMirrorSpy()
				emitter := &countingEmitter{}
				uc := NewRegisterResourceUseCase(emitter, mirror, txb, catalog, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, unitScopes()).
					WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"})
				err := uc.Register(context.Background(), &regReq{subject: subject, relation: "box", object: "probemod_item:i"})
				require.Equal(t, codes.PermissionDenied, status.Code(err))
				require.Equal(t, "permission denied", status.Convert(err).Message())
				require.Empty(t, status.Convert(err).Details())
				require.Nil(t, txb.tx)
				require.Zero(t, catalog.policyReads)
				require.Zero(t, catalog.identityReads)
				require.Zero(t, mirror.upserts)
				require.Zero(t, mirror.deletes)
				require.Zero(t, emitter.writes)
				require.Zero(t, emitter.deletes)
			})
		}
	}
}

func TestRegistrationAuthenticatedCatalogIdentityUsesCurrentOwnerEveryRequest(t *testing.T) {
	for _, tc := range []struct{ service, module, typ string }{
		{"probemod", "probemod", "probemod_box"},
		{"nlb", "loadbalancer", "nlb_listener"},
	} {
		t.Run(tc.service, func(t *testing.T) {
			roster, err := moduleidentity.Parse([]string{"modules/kacho-" + tc.service + "=module-writer"})
			require.NoError(t, err)
			ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kaname.test"),
				"spiffe://kaname.test/ns/modules/sa/kacho-"+tc.service, true)
			gate := authzguard.NewRelationWriteGate(nil).WithModuleRoster(roster)
			catalog := &ownerCatalog{typ: tc.typ, owner: tc.module, live: true, known: true}
			txb := &smTxBeginner{}
			mirror := newMirrorSpy()
			uc := NewRegisterResourceUseCase(smEmitter{}, mirror, txb, catalog, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, unitScopes()).
				WithRegistrationAuthority(gate)
			tuple := tupleIntent{subject: "project:" + unitProject, relation: "project", object: tc.typ + ":one"}
			module, err := uc.authorizeIntent(ctx, tuple)
			require.NoError(t, err)
			require.Equal(t, tc.module, module)
			tx := &smTx{}
			row := service.ResourceMirrorRow{ObjectType: tc.typ, ObjectID: "one"}
			_, err = uc.admitRegistration(ctx, tx, module, tuple, row)
			require.NoError(t, err)
			catalog.owner = "foreign"
			_, err = uc.admitRegistration(ctx, tx, module, tuple, row)
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.Equal(t, 2, catalog.policyReads)
			require.Zero(t, mirror.upserts)
			// Тип запроса может назвать чужой ресурс, но не сменить личность.
			tuple.object = "foreign_box:one"
			module, err = uc.authorizeIntent(ctx, tuple)
			require.NoError(t, err)
			require.Equal(t, tc.module, module)
			catalog.live = false
			catalog.owner = tc.module
			tuple.object = tc.typ + ":one"
			_, err = uc.authorizeCatalogType(ctx, tx, module, tuple)
			require.NoError(t, err, "снятый собственный тип допускает очистку")
			catalog.owner = "foreign"
			_, err = uc.authorizeCatalogType(ctx, tx, module, tuple)
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.Equal(t, 2, catalog.identityReads)
		})
	}
}
