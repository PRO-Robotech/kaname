// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_issuer_probe_test.go — признание модуля по листу привязано к
// выпустившему его удостоверяющему центру (kaname#988).
//
// Пробы DoD:
//
//  1. лист с допустимой формой SAN, выпущенный НЕ ТЕМ доверенным центром, —
//     отказ, вызов не исполняется;
//  2. законный близнец: тот же SAN в листе своего центра — вызов исполняется;
//  3. SAN вне перечня своего центра — отказ.
//
// Привязка судится на каждом пути признания тем же набором форм: обе политики
// вызывающего, посредник записи отношений, пол системного читателя, допуск
// анонимной самопроверки и признак края на HTTP-слушателях.
package authzguard

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// issuerWorld — два доверенных центра установки и перечень, привязывающий
// край к центру края, а модуль-владелец — к внутреннему центру.
type issuerWorld struct {
	edge, internal *moduleroster.CA
	roster         moduleidentity.Roster
}

func newIssuerWorld(t *testing.T) issuerWorld {
	t.Helper()
	w := issuerWorld{edge: moduleroster.NewCA(t, "edge-ca"), internal: moduleroster.NewCA(t, "internal-ca")}
	r, err := moduleidentity.ParseWithIssuers(moduleroster.NameForm(), []string{
		"kacho/kacho-api-gateway=edge@edge",
		"kacho/kacho-vpc=module-writer@internal",
	}, moduleidentity.IssuerSet{
		"edge":     {w.edge.Cert()},
		"internal": {w.internal.Cert()},
	})
	if err != nil {
		t.Fatalf("перечень проб не разобрался: %v", err)
	}
	w.roster = r
	return w
}

// TestModuleIssuer_LeafOfTheOtherTrustedCAIsRefused — DoD пп. 1–2: SAN края в
// листе внутреннего центра — не край ни на gRPC, ни на HTTP; тот же SAN в
// листе центра края — край.
func TestModuleIssuer_LeafOfTheOtherTrustedCAIsRefused(t *testing.T) {
	w := newIssuerWorld(t)
	p := NewCallerPolicy(true, GatewayFrontedInternalRPCs()).WithModuleRoster(w.roster)
	d := moduleroster.Domain()

	requireDenied(t, p.allow(w.internal.PeerContext(t, rosterGatewaySAN), gatewayOnlyMethod),
		"gRPC: SAN края в листе внутреннего центра")
	if PeerIsGateway(w.roster, d, w.internal.ConnectionState(t, rosterGatewaySAN)) {
		t.Fatal("HTTP: SAN края в листе внутреннего центра признан краем")
	}

	if err := p.allow(w.edge.PeerContext(t, rosterGatewaySAN), gatewayOnlyMethod); err != nil {
		t.Fatalf("близнец gRPC: SAN края в листе центра края отвергнут: %v", err)
	}
	if !PeerIsGateway(w.roster, d, w.edge.ConnectionState(t, rosterGatewaySAN)) {
		t.Fatal("близнец HTTP: SAN края в листе центра края не признан краем")
	}
}

// TestModuleIssuer_SANOutsideItsCAListIsRefused — DoD п. 3: SAN модуля-владельца
// в листе центра края — вне перечня этого центра, отказ; близнец — лист
// внутреннего центра.
func TestModuleIssuer_SANOutsideItsCAListIsRefused(t *testing.T) {
	w := newIssuerWorld(t)
	p := NewCallerPolicy(true, GatewayFrontedInternalRPCs()).WithModuleRoster(w.roster)

	requireDenied(t, p.allow(w.edge.PeerContext(t, moduleroster.DeclaredVPC), internalRegisterResourceMethod),
		"SAN модуля в листе центра края")
	if err := p.allow(w.internal.PeerContext(t, moduleroster.DeclaredVPC), internalRegisterResourceMethod); err != nil {
		t.Fatalf("близнец: SAN модуля в листе своего центра отвергнут: %v", err)
	}
}

// TestModuleIssuer_EveryCallerCheckPathBindsTheIssuer — привязка одним разбором
// на всех путях: решение каждого пути о модуле `vpc` совпадает с ожиданием на
// листах обоих центров и на контексте без проверенной цепочки.
func TestModuleIssuer_EveryCallerCheckPathBindsTheIssuer(t *testing.T) {
	w := newIssuerWorld(t)
	internal := NewCallerPolicy(true, GatewayFrontedInternalRPCs()).WithModuleRoster(w.roster)
	public := NewPublicCallerPolicy(true, PublicPeerCallableRPCs(), nil, nil).WithModuleRoster(w.roster)
	writer := NewRelationWriteGate(&allowingChecker{}).WithProductionMode(true).WithModuleRoster(w.roster)
	floor := NewSystemViewerFloor(&allowingChecker{}, ReadFloorRPCs()).WithProductionMode(true).WithModuleRoster(w.roster)
	anonymousShape := &iamv1.AuthorizeCheckRequest{
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "net1"},
		Action:   "get",
	}
	paths := map[string]func(ctx context.Context) bool{
		"политика внутреннего слушателя": func(ctx context.Context) bool {
			return internal.allow(ctx, internalRegisterResourceMethod) == nil
		},
		"политика публичного слушателя": func(ctx context.Context) bool {
			return public.allow(ctx, publicProjectGetMethod) == nil
		},
		"посредник записи отношений": func(ctx context.Context) bool {
			domain, err := writer.Authorize(ctx)
			return err == nil && domain == "vpc"
		},
		"пол системного читателя": func(ctx context.Context) bool {
			return floor.allow(ctx, internalLookupSubjectMethod) == nil
		},
		"допуск анонимной самопроверки": func(ctx context.Context) bool {
			return !IsAnonymousSelfCheck(ctx, anonymousShape, w.roster)
		},
	}
	forms := []struct {
		name   string
		ctx    context.Context
		module bool
	}{
		{"лист своего центра", w.internal.PeerContext(t, moduleroster.DeclaredVPC), true},
		{"лист чужого доверенного центра", w.edge.PeerContext(t, moduleroster.DeclaredVPC), false},
		{"идентификатор без проверенной цепочки", moduleroster.IdentityContext(moduleroster.DeclaredVPC), false},
	}
	decisions := 0
	for _, f := range forms {
		for name, decide := range paths {
			decisions++
			if got := decide(f.ctx); got != f.module {
				t.Errorf("форма %q: путь %q признал модулем = %v, ожидалось %v", f.name, name, got, f.module)
			}
		}
	}
	t.Logf("перепись: форм %d · путей %d · решений %d", len(forms), len(paths), decisions)
}
