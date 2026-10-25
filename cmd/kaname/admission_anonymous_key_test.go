// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/restfront"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Пробы ключа и класса публичного ограничителя допуска (kaname#991).
//
// Ограничитель собирается ТЕМИ ЖЕ частями, что в композиционном корне:
// publicAdmissionSubject и publicAdmissionOptions. Своя копия ключа в пробе
// судила бы копию, а не провязку.

const (
	testFrontHop    = "spiffe://kaname.test/ns/kaname/sa/kaname"
	testMutatingRPC = "/kaname.cloud.iam.v1.AccountService/Create"
)

// tightLimits — величины, при которых второй вызов того же класса уже отказ.
func tightLimits(read, mutation float64) grpcsrv.AdmissionLimits {
	return grpcsrv.AdmissionLimits{ReadPerSec: read, MutationPerSec: mutation, BurstFactor: 1, InFlight: 64}
}

func newTestPublicAdmission(t *testing.T, limits grpcsrv.AdmissionLimits) *grpcsrv.Admission {
	t.Helper()
	a, err := grpcsrv.NewAdmission("public", limits, publicAdmissionSubject(testFrontHop), publicAdmissionOptions()...)
	require.NoError(t, err)
	return a
}

// fromPeer — контекст вызова, пришедшего по соединению с адреса addr.
func fromPeer(addr string) context.Context {
	ap := netip.MustParseAddrPort(addr)
	return peer.NewContext(context.Background(), &peer.Peer{Addr: net.TCPAddrFromAddrPort(ap)})
}

// viaFront — вызов, пришедший через собственный REST-фронт от клиента client.
func viaFront(client string) context.Context {
	ctx := fromPeer("127.0.0.1:41000")
	ctx = grpcsrv.WithCertIdentityIn(ctx, grpcsrv.TrustDomain{}, testFrontHop, true)
	return metadata.NewIncomingContext(ctx, metadata.Pairs(restfront.MetadataClientAddr, client))
}

// admit — исход одного вызова: nil либо код отказа.
func admit(t *testing.T, a *grpcsrv.Admission, ctx context.Context, method string) error {
	t.Helper()
	release, err := a.Admit(ctx, method)
	if err == nil {
		release()
	}
	return err
}

func requireRateRefusal(t *testing.T, err error, msg string) {
	t.Helper()
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.ResourceExhausted, st.Code())
	require.Equal(t, msg, st.Message())
}

// Анонимные вызовы двух клиентов по прямому соединению — РАЗНЫЕ вёдра: первый
// доведён до отказа, второй принят.
func TestPublicAdmission_AnonymousDirectClientsDoNotShareABucket(t *testing.T) {
	a := newTestPublicAdmission(t, tightLimits(1, 1))
	clientA := fromPeer("198.51.100.7:50001")
	clientB := fromPeer("198.51.100.8:50001")

	require.NoError(t, admit(t, a, clientA, testMutatingRPC))
	requireRateRefusal(t, admit(t, a, clientA, testMutatingRPC), grpcsrv.MsgMutationRateExceeded)
	require.NoError(t, admit(t, a, clientB, testMutatingRPC),
		"анонимный клиент B не обязан платить за поток клиента A")
}

// Новое соединение того же клиента — тот же ключ: ключ — адрес, а не пара
// «адрес, порт», иначе каждое переподключение покупало бы свежее ведро.
func TestPublicAdmission_AnonymousKeyIgnoresThePort(t *testing.T) {
	a := newTestPublicAdmission(t, tightLimits(1, 1))
	require.NoError(t, admit(t, a, fromPeer("198.51.100.7:50001"), testMutatingRPC))
	requireRateRefusal(t, admit(t, a, fromPeer("198.51.100.7:50002"), testMutatingRPC), grpcsrv.MsgMutationRateExceeded)
}

// Анонимные вызовы через собственный REST-фронт — по адресу клиента фронта, а
// не по адресу самого фронта.
func TestPublicAdmission_AnonymousViaOwnFrontKeyedByClientAddress(t *testing.T) {
	a := newTestPublicAdmission(t, tightLimits(1, 1))
	require.NoError(t, admit(t, a, viaFront("203.0.113.10"), testMutatingRPC))
	requireRateRefusal(t, admit(t, a, viaFront("203.0.113.10"), testMutatingRPC), grpcsrv.MsgMutationRateExceeded)
	require.NoError(t, admit(t, a, viaFront("203.0.113.11"), testMutatingRPC),
		"клиент B за фронтом не обязан платить за поток клиента A")
}

// Адрес клиента в метаданных от пира, который НЕ собственный фронт, не
// читается: иначе ключ сменял бы всякий, кто его подставил.
func TestPublicAdmission_ClientAddressFromForeignPeerIsIgnored(t *testing.T) {
	a := newTestPublicAdmission(t, tightLimits(1, 1))
	spoof := func(claimed string) context.Context {
		ctx := fromPeer("198.51.100.9:50001")
		ctx = grpcsrv.WithCertIdentityIn(ctx, grpcsrv.TrustDomain{}, "spiffe://kaname.test/ns/x/sa/other", true)
		return metadata.NewIncomingContext(ctx, metadata.Pairs(restfront.MetadataClientAddr, claimed))
	}
	require.NoError(t, admit(t, a, spoof("203.0.113.20"), testMutatingRPC))
	requireRateRefusal(t, admit(t, a, spoof("203.0.113.21"), testMutatingRPC), grpcsrv.MsgMutationRateExceeded)

	// Непроверенный сертификат с именем фронта — тоже не фронт.
	unverified := func(claimed string) context.Context {
		ctx := fromPeer("198.51.100.10:50001")
		ctx = grpcsrv.WithCertIdentityIn(ctx, grpcsrv.TrustDomain{}, testFrontHop, false)
		return metadata.NewIncomingContext(ctx, metadata.Pairs(restfront.MetadataClientAddr, claimed))
	}
	require.NoError(t, admit(t, a, unverified("203.0.113.30"), testMutatingRPC))
	requireRateRefusal(t, admit(t, a, unverified("203.0.113.31"), testMutatingRPC), grpcsrv.MsgMutationRateExceeded)
}

// Фронт без годного адреса клиента нового ключа не получает: негодное
// значение не дробит ведро фронта на произвольное число вёдер.
func TestPublicAdmission_FrontWithoutAddressKeepsItsOwnKey(t *testing.T) {
	a := newTestPublicAdmission(t, tightLimits(1, 1))
	require.NoError(t, admit(t, a, viaFront("not-an-address"), testMutatingRPC))
	requireRateRefusal(t, admit(t, a, viaFront("also, garbage"), testMutatingRPC), grpcsrv.MsgMutationRateExceeded)
}

// Законный близнец: вошедший ключуется личностью, как прежде, — с какого
// адреса бы он ни пришёл.
func TestPublicAdmission_AuthenticatedCallerKeyedByPrincipalAsBefore(t *testing.T) {
	a := newTestPublicAdmission(t, tightLimits(1, 1))
	who := operations.Principal{Type: "userAccount", ID: "u-1"}
	require.NoError(t, admit(t, a, operations.WithPrincipal(fromPeer("198.51.100.7:1"), who), testMutatingRPC))
	requireRateRefusal(t,
		admit(t, a, operations.WithPrincipal(fromPeer("198.51.100.8:1"), who), testMutatingRPC),
		grpcsrv.MsgMutationRateExceeded)
	other := operations.Principal{Type: "userAccount", ID: "u-2"}
	require.NoError(t, admit(t, a, operations.WithPrincipal(fromPeer("198.51.100.7:1"), other), testMutatingRPC))
}

// Check — чтение: поток Check в пределах потолка чтений не получает отказа по
// потолку мутаций, сверх потолка чтений — отказ о чтениях.
func TestPublicAdmission_CheckIsChargedToTheReadBudget(t *testing.T) {
	a := newTestPublicAdmission(t, tightLimits(3, 1))
	caller := operations.WithPrincipal(fromPeer("198.51.100.7:1"), operations.Principal{Type: "userAccount", ID: "u-1"})
	for i := 0; i < 3; i++ {
		require.NoError(t, admit(t, a, caller, iamv1.AuthorizeService_Check_FullMethodName),
			"Check №%d в пределах потолка чтений", i+1)
	}
	requireRateRefusal(t, admit(t, a, caller, iamv1.AuthorizeService_Check_FullMethodName), grpcsrv.MsgReadRateExceeded)

	// Близнец: мутация того же вызывающего платит своим потолком, как прежде.
	require.NoError(t, admit(t, a, caller, testMutatingRPC))
	requireRateRefusal(t, admit(t, a, caller, testMutatingRPC), grpcsrv.MsgMutationRateExceeded)
}

// Классификатор сужает только Check: прочие имена — по конвенции продукта.
func TestPublicCallClass_OnlyCheckIsReclassified(t *testing.T) {
	require.Equal(t, grpcsrv.ClassRead, publicCallClass(iamv1.AuthorizeService_Check_FullMethodName))
	for _, m := range []string{
		iamv1.AuthorizeService_BatchCheck_FullMethodName,
		testMutatingRPC,
		"/kaname.cloud.iam.v1.AccountService/Get",
		"/kaname.cloud.iam.v1.AccountService/List",
	} {
		require.Equal(t, grpcsrv.ClassifyByKachoConvention(m), publicCallClass(m), m)
	}
}
