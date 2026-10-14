// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// edge_credential_chain_test.go — РАЗМЕЩЕНИЕ читателя переданного краем
// удостоверения (kaname#677) на той цепочке, что уезжает в публичный
// слушатель: цепочка собирается боевым сборщиком `publicIdentityUnary`, а не
// перечислением звеньев. Что читатель принимает и что отбрасывает — матрица
// односфактных отрицаний у самого читателя (`internal/edgecredential`); здесь —
// что он стоит на публичной полосе, ЗА решением о личности, и что полоса
// предъявленного его не подменяет.

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/corelib/principalwire"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/edgecredential"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
)

const edgeSessionRecord = "hss-0000000000000000e"

// edgeSeen — носители текущей сессии, которые увидел бы обработчик.
type edgeSeen struct {
	session, credential string
	hasSession          bool
}

func runEdgeChain(t *testing.T, chain grpc.UnaryServerInterceptor, ctx context.Context) edgeSeen {
	t.Helper()
	var got edgeSeen
	_, err := chain(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AccessKeyService/Revoke"},
		func(c context.Context, _ any) (any, error) {
			got.session, got.hasSession = callerorigin.SessionIDFrom(c)
			got.credential, _ = callerorigin.CredentialIDFrom(c)
			return nil, nil
		})
	if err != nil {
		t.Fatalf("цепочка отвергла запрос: %v", err)
	}
	return got
}

// edgeForwardedMD — то, что ставит край за человека chainSubject.
func edgeForwardedMD(extra ...string) metadata.MD {
	return metadata.Pairs(append([]string{
		principalwire.MetaPrincipalType, "user",
		principalwire.MetaPrincipalID, chainSubject,
		edgecredential.MetaSessionID, edgeSessionRecord,
	}, extra...)...)
}

// TestKN677_PublicChainCarriesTheForwardedSessionToTheHandler — публичная
// цепочка, собранная боевым сборщиком, доносит номер записи от края до
// обработчика; внутренняя — нет: глагола, читающего его, там не смонтировано,
// и решение поставить читатель на обе полосы никто не принимал.
func TestKN677_PublicChainCarriesTheForwardedSessionToTheHandler(t *testing.T) {
	reader, _ := chainReader(t)
	ctx := metadata.NewIncomingContext(context.Background(), edgeForwardedMD())

	got := runEdgeChain(t, publicChainWithReader(reader), ctx)
	if !got.hasSession || got.session != edgeSessionRecord {
		t.Fatalf("публичная цепочка не донесла номер записи от края: %+v — читатель "+
			"переданного краем стоит мимо боевого сборщика", got)
	}

	internal := runEdgeChain(t, internalChainNoReader(), ctx)
	if internal.hasSession {
		t.Errorf("внутренняя цепочка прочитала номер записи: %+v", internal)
	}
}

// TestKN677_PresentedLaneIgnoresForwardedMetadata — предъявленный токен и
// метаданные края в одном запросе: личность названа предъявленным, номер
// записи из метаданных не читается, выпуск — проверенный читателем
// предъявленного (`tok-chain`), а не присланный рядом.
func TestKN677_PresentedLaneIgnoresForwardedMetadata(t *testing.T) {
	reader, raw := chainReader(t)
	md := edgeForwardedMD(principalwire.MetaTokenJti, "jti-forged")
	md.Set(presentedcred.MetadataKey, "Bearer "+raw)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	got := runEdgeChain(t, publicChainWithReader(reader), ctx)
	if got.hasSession {
		t.Errorf("номер записи прочитан на полосе предъявленного: %+v", got)
	}
	if got.credential != "tok-chain" {
		t.Errorf("выпуск предъявленного подменён: %q, ожидался tok-chain", got.credential)
	}
}
