// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// own_rest_front_hop_test.go — сертификат СОБСТВЕННОГО REST-фронта называет ХОП,
// а не вызывающего (задача продукта #2319).
//
// # Предмет
//
// Задача #2103 решила ТОН отказа безымянному: «назовись», а не «не пускают», — и
// завела ветвь, которая это отвечает. Ветвь верна и её проба зелена. Неверен её
// ВХОД: проба подаёт `context.Background()`, то есть мир БЕЗ сертификата вовсе,
// а развёрнутая посадка такого мира не производит ни на одном запросе.
//
// Собственный REST-фронт службы — обычный клиент своего же gRPC-слушателя, и
// дозванивается он под КЛИЕНТСКИМ листом службы. Значит на каждом запросе,
// пришедшем через фронт, `verified` истинно, конъюнкция трёх «нет» ложна by
// construction, и ветвь «назовись» не срабатывает НИ РАЗУ на той полосе, ради
// которой заведена. Арендатор чужого облака, не приложивший удостоверения,
// получает «тебя знают и не пускают» — при том что его никто не знает.
//
// # Почему это НЕ решение о тоне заново
//
// Тон решён #2103 и здесь не пересматривается. Пересматривается ПРЕДПОСЫЛКА
// ветви: «сертификат есть ⇒ вызывающий назвался». Для соседнего модуля это
// верно — лист называет ЕГО. Для собственного фронта ложно: лист называет нас
// самих, и о вызывающем не говорит ничего.
//
// # Почему это не оракул
//
// Различаются два состояния ЗАПРОСА, известные вызывающему до ответа: он либо
// приложил удостоверение, либо нет. Отказ ПРЕДЪЯВИВШЕМУ негодное не меняется —
// он остаётся единственным побайтово равным.

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
)

// ownRESTFrontSAN — SPIFFE-имя КЛИЕНТСКОГО листа самой службы.
//
// Строка взята из чарта, который этот сертификат выдаёт
// (deploy/helm/umbrella/charts/kaname: spiffe.trustDomain/namespace/saName), а не
// написана по образцу соседей: сегмент учётной записи у службы СВОЙ и префикса
// платформенных модулей не несёт — ровно поэтому её лист и не разбирается в имя
// модуля.
const ownRESTFrontSAN = "spiffe://kacho.cloud/ns/kacho/sa/kaname"

// newOwnRESTFrontCtx — мир РАЗВЁРНУТОЙ посадки: запрос пришёл через собственный
// REST-фронт, и фронт назвался своим клиентским листом. Удостоверения вызывающий
// не прикладывал, личность за него никто не передавал.
func newOwnRESTFrontCtx() context.Context {
	return grpcsrv.WithCertIdentityIn(
		context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), ownRESTFrontSAN, true)
}

// TestOwnRESTFrontHop_UnnamedCallerIsStillToldToIdentifyItself — несущее
// утверждение. Тот же вызывающий, что и в TestUnnamedCaller_IsToldToIdentifyItself,
// но пришедший ТЕМ ПУТЁМ, которым он приходит на посадке.
func TestOwnRESTFrontHop_UnnamedCallerIsStillToldToIdentifyItself(t *testing.T) {
	st := runPolicy(t, newOwnRESTFrontCtx(), projectGetMethod)
	if st == nil {
		t.Fatalf("безымянный вызывающий прошёл политику через собственный фронт — отказа нет вовсе")
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("код отказа безымянному ЧЕРЕЗ СОБСТВЕННЫЙ ФРОНТ = %v (%q), ожидался %v: "+
			"сертификат фронта называет хоп, а не вызывающего, и «назовись» остаётся "+
			"единственным отказом, восстанавливающим следующий шаг",
			st.Code(), st.Message(), codes.Unauthenticated)
	}
	if st.Message() != UnnamedCallerMessage {
		t.Fatalf("текст отказа = %q, ожидался %q", st.Message(), UnnamedCallerMessage)
	}
}

// TestOwnRESTFrontHop_NeighbourModuleStaysPermissionDenied — ЗАКОННЫЙ БЛИЗНЕЦ,
// и он несущий: без него утверждение выше зеленело бы на политике, отвечающей
// «назовись» всякому, кого не пустили.
//
// Сосед назвался СВОИМ листом, и лист называет именно его. Предлагать ему
// назваться значило бы послать чинить не то.
func TestOwnRESTFrontHop_NeighbourModuleStaysPermissionDenied(t *testing.T) {
	st := runPolicy(t, newStorageCtx(), userTokenIssueMethod)
	if st == nil {
		t.Fatalf("сосед допущен к чеканке личного токена — политика не сработала")
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("код отказа НАЗВАВШЕМУСЯ соседу = %v, ожидался %v", st.Code(), codes.PermissionDenied)
	}
	if st.Message() != "permission denied" {
		t.Fatalf("текст отказа соседу = %q, ожидался прежний %q", st.Message(), "permission denied")
	}
}

// TestOwnRESTFrontHop_PresentedCredentialThroughTheFrontPassesThrough — второй
// законный близнец: арендатор, приложивший удостоверение и проверенный
// читателем, проходит ТЕМ ЖЕ путём. Без него поправка могла бы отвергать всех,
// кто пришёл через фронт, и первое утверждение этого не показало бы.
func TestOwnRESTFrontHop_PresentedCredentialThroughTheFrontPassesThrough(t *testing.T) {
	ctx := callerorigin.With(newOwnRESTFrontCtx(), callerorigin.PresentedCredential)
	if st := runPolicy(t, ctx, projectGetMethod); st != nil {
		t.Fatalf("арендатор с проверенным удостоверением отвергнут на пути через фронт: %v %q",
			st.Code(), st.Message())
	}
}

// TestOwnRESTFrontHop_DevPostureStillPassesTheUnnamedCallerThrough — ГРАНИЦА
// поправки, названная числом, а не обещанная прочь.
//
// Поправка выше действует в БОЕВОЙ посадке. В dev-посадке политика вырождается
// целиком (`if !p.prodMode { return nil }`), и безымянный вызывающий проходит её
// насквозь — отказ ему выносит уже дверь, прежним `PermissionDenied`.
//
// # Зачем это утверждается, а не умалчивается
//
// Шард сквозных проб поднимает службу именно в dev-посадке
// (deploy/helm/umbrella/values.dev.yaml, `kaname: authMode: dev`), поэтому
// стендовая половина предиката #2319 — «безымянному отвечают 401 с подсказкой» —
// ЭТОЙ поправкой не закрывается, и множество принимаемых отказов в кейсе
// IAM-OWNREST-NEG-ANONYMOUS остаётся двузначным. Снять его можно не правкой
// тона, а подъёмом шарда в боевую посадку (ban #16: production-mode ВЕЗДЕ) —
// и это отдельный предмет со своей ценой.
//
// Проба существует затем, чтобы следующий, увидев поправку посаженной, не сузил
// множество в кейсе, не подняв стенд: она называет ровно ту причину, по которой
// сужать сегодня нельзя.
func TestOwnRESTFrontHop_DevPostureStillPassesTheUnnamedCallerThrough(t *testing.T) {
	dev := NewPublicCallerPolicy(false, PublicPeerCallableRPCs(), nil, bearerPresent)
	_, err := dev.Unary()(newOwnRESTFrontCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: projectGetMethod},
		func(context.Context, any) (any, error) { return nil, nil })
	if err != nil {
		t.Fatalf("dev-посадка отвергла безымянного на уровне политики (%v) — "+
			"если это намеренная перемена, стендовая половина #2319 закрывается "+
			"вместе с ней, и множество в IAM-OWNREST-NEG-ANONYMOUS пора сужать", err)
	}
}
