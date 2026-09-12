// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// presented_credential_chain_test.go — сценарии KAN-WIRE-02, KAN-VER-01,
// KAN-DUP-01 и KAN-FWD-01 приёмки KAN-AUTHN-1 на ТОЙ ЖЕ цепочке, что собирает
// боевой корень (задача продукта #2077).
//
// # Ловушка, ради которой файл написан
//
// До этого перехода харнессы обеих цепочек собирались ОДНИМ вызовом и потому
// были тождественны по телу. Читатель, добавленный в публичную цепочку мимо
// боевого сборщика, оказался бы вне харнесса — и все поведенческие пробы стали
// бы ВАКУУМНЫМИ, оставаясь зелёными. Поэтому цепочка здесь строится
// `publicIdentityUnary`, то есть тем же сборщиком, что уезжает в слушатель.
//
// # Что здесь НЕ утверждается
//
// Матрица односфактных отрицаний живёт у читателя (internal/presentedcred): её
// предмет — что читатель отвергает. Предмет ЭТОГО файла — РАЗМЕЩЕНИЕ: что
// читатель стоит на публичной полосе, не стоит на внутренней, и что назначенная
// им личность доживает до обработчика.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

const (
	chainIssuer   = "https://kaname.chain.test"
	chainAudience = "kaname-public"
	chainSubject  = "usr-01hchainchainchain"
	chainKID      = "kaname-chain-a"
	chainRPC      = "/kaname.cloud.iam.v1.ProjectService/Get"
)

// chainKeys / chainRevocations — подставные зависимости читателя. Своей логики
// они не несут: предмет файла — размещение, а не проверки.
type chainKeys struct{ keys []domain.PublishedKey }

func (k chainKeys) PublishedSet(context.Context) ([]domain.PublishedKey, error) { return k.keys, nil }

type chainRevocations struct{}

func (chainRevocations) RevokedBefore(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

// chainReader строит читателя и годный токен к нему.
func chainReader(t *testing.T) (*presentedcred.Reader, string) {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	if err != nil {
		t.Fatalf("порождение ключа: %v", err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(mat.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("разбор ключа: %v", err)
	}
	now := time.Now().UTC()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": chainIssuer, "sub": chainSubject, "aud": []string{chainAudience},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"jti":                        "tok-chain",
		domain.ClaimPrincipalType:    "user",
		domain.ClaimPrincipalID:      chainSubject,
		domain.ClaimPrincipalDisplay: "alice@chain.test",
	})
	tok.Header["kid"] = chainKID
	tok.Header["typ"] = tokenpolicy.TokenTypeAccess
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}
	r, err := presentedcred.New(presentedcred.Config{
		Issuer:            chainIssuer,
		Audience:          chainAudience,
		AllowedAlgorithms: []string{tokenpolicy.AlgES256},
		Keys: chainKeys{keys: []domain.PublishedKey{{
			KID: domain.KeyID(chainKID), Algorithm: domain.SigningAlgES256, PublicKeyPEM: mat.PublicKeyPEM,
		}}},
		Revocations:        chainRevocations{},
		RevocationCacheTTL: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("построение читателя: %v", err)
	}
	return r, raw
}

// publicChainWithReader / internalChainNoReader — ТЕ ЖЕ сборщики, что уезжают в
// слушатели. Перечислять звенья здесь нельзя: перечисление и есть тот дрейф,
// из-за которого проводка меняется, а замки не замечают.
func publicChainWithReader(r *presentedcred.Reader) grpc.UnaryServerInterceptor {
	return chainUnaryServer(publicIdentityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN), r)...)
}

func internalChainNoReader() grpc.UnaryServerInterceptor {
	return chainUnaryServer(identityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN))...)
}

func presenting(raw string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(presentedcred.MetadataKey, "Bearer "+raw))
}

// runChain прогоняет запрос и возвращает личность, которую увидел бы обработчик.
func runChain(t *testing.T, chain grpc.UnaryServerInterceptor, ctx context.Context) (operations.Principal, bool, error) {
	t.Helper()
	var (
		seen    operations.Principal
		present bool
	)
	_, err := chain(ctx, nil, &grpc.UnaryServerInfo{FullMethod: chainRPC},
		func(c context.Context, _ any) (any, error) {
			seen, present = operations.PrincipalFromContextOK(c)
			return nil, nil
		})
	return seen, present, err
}

// TestKAN_WIRE_02_PublicAndInternalChainsStopBeingIdentical — харнесс собирает
// цепочку БОЕВЫМ сборщиком и потому видит читателя; внутренняя цепочка,
// собранная своим сборщиком, предъявленного не читает.
//
// Обе половины обязательны: «публичная читает» без «внутренняя не читает»
// зеленело бы на читателе, поставленном на ОБЕ полосы, — а это другое решение,
// которого никто не принимал.
func TestKAN_WIRE_02_PublicAndInternalChainsStopBeingIdentical(t *testing.T) {
	reader, raw := chainReader(t)

	p, present, err := runChain(t, publicChainWithReader(reader), presenting(raw))
	if err != nil {
		t.Fatalf("публичная цепочка отвергла годное предъявление: %v", err)
	}
	if !present || p.ID != chainSubject {
		t.Fatalf("публичная цепочка не назвала вызывающего: %+v (носитель=%v) — читатель "+
			"добавлен мимо боевого сборщика, и все поведенческие пробы вакуумны", p, present)
	}

	_, internalPresent, err := runChain(t, internalChainNoReader(), presenting(raw))
	if err != nil {
		t.Fatalf("внутренняя цепочка вернула отказ на предъявленном: %v", err)
	}
	if internalPresent {
		t.Error("внутренняя цепочка прочитала предъявленное удостоверение — читатель стоит " +
			"на обеих полосах, и решение об этом никто не принимал")
	}
}

// TestKAN_VER_01_IdentityNamedByTheReaderSurvivesToTheHandler — личность,
// назначенная читателем, ДОЖИВАЕТ до обработчика.
//
// Это утверждение о ПОРЯДКЕ, и держится оно исходом, а не позицией строк в
// исходнике: пара извлечения личности на двух ветках из трёх ЗАТИРАЕТ носитель,
// поэтому читатель, поставленный перед ней, увидел бы, как назначенного им
// вызывающего стирают — молча.
func TestKAN_VER_01_IdentityNamedByTheReaderSurvivesToTheHandler(t *testing.T) {
	reader, raw := chainReader(t)

	p, present, err := runChain(t, publicChainWithReader(reader), presenting(raw))
	if err != nil {
		t.Fatalf("годное предъявление отвергнуто цепочкой: %v", err)
	}
	if !present {
		t.Fatal("носитель личности пуст: читатель стоит ДО пары извлечения, и она стёрла " +
			"назначенного им вызывающего")
	}
	// Сравнение с САМИМ идентификатором, а не с запасным значением: запасное —
	// общее наблюдаемое двух разных состояний, и утверждать им о носителе
	// нельзя. Вычищенность носителя утверждает признак наличия выше.
	if p.ID != chainSubject {
		t.Errorf("вызывающим назван %q, ожидается субъект токена %q — если это запасная "+
			"личность, ею владеет каждая системно записанная операция", p.ID, chainSubject)
	}
}

// TestKAN_FWD_01_ForwardedIdentityStillPassesTheRealChain — прежний путь не
// отозван: проверенный пир из круга разрешённых отправителей по-прежнему
// называет конечного пользователя на ТОЙ ЖЕ боевой цепочке.
//
// # Здесь стояло отрицание «обе формы разом — отказ». Оно СНЯТО ВМЕСТЕ С ПРЕДМЕТОМ
//
// Приёмка KAN-AUTHN-1 редакцией 2 отозвала решение, которое эта ветка
// реализовывала: полосы взаимоисключающи ПОСТРОЕНИЕМ — край снимает
// арендаторское удостоверение перед пересылкой за себя. Сочетания двух форм в
// одном запросе больше не производит никто, и утверждение о нём стало бы
// зелёным вердиктом о снятом предмете.
//
// Положительный близнец того отрицания выражал требование ЖИВОЕ (ось 7 решения:
// прежний путь не отзывается) и потому остался — под своим именем.
func TestKAN_FWD_01_ForwardedIdentityStillPassesTheRealChain(t *testing.T) {
	reader, _ := chainReader(t)
	chain := publicChainWithReader(reader)

	fwdOnly := forwardedIdentity(verifiedCertPeer(t, fwdGatewaySAN), "usr-alice")
	p, present, err := runChain(t, chain, fwdOnly)
	if err != nil {
		t.Fatalf("прежний путь отозван: переданная личность от разрешённого отправителя "+
			"отвергнута: %v", err)
	}
	if !present || p.ID != "usr-alice" {
		t.Fatalf("прежний путь сломан: %+v (носитель=%v)", p, present)
	}
}

// TestKAN_VER_01_CallerNamedByAPresentedCredentialIsALegitimatePublicCaller —
// звено политики вызывающего признаёт того, кого назвал читатель.
//
// Без этого утверждения объём приёмки закрыт наполовину: читатель называет
// вызывающего, а следующее звено отвергает его за отсутствие МОДУЛЬНОГО
// сертификата — которого у арендатора чужого облака нет и быть не может. Тогда
// «вызов доходит до обработчика» недостижимо ни при каком токене, а десять
// односфактных отрицаний зеленеют по неверной причине: отказ приходит не от той
// проверки, которую они описывают.
//
// Положительный контроль соседней ветки — тут же: тот же боевой режим БЕЗ
// предъявленного удостоверения по-прежнему отвергается. Без него «политика
// признаёт названного читателем» зеленело бы на политике, снятой целиком.
func TestKAN_VER_01_CallerNamedByAPresentedCredentialIsALegitimatePublicCaller(t *testing.T) {
	reader, raw := chainReader(t)
	policy := authzguard.NewPublicCallerPolicy(true, authzguard.PublicPeerCallableRPCs(), noFloorCatalog{}, presentedcred.Presented)
	chain := chainUnaryServer(append(
		publicIdentityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN), reader),
		policy.Unary())...)

	if _, _, err := runChain(t, chain, presenting(raw)); err != nil {
		t.Fatalf("вызывающий, названный предъявленным удостоверением, отвергнут политикой: %v — "+
			"у арендатора чужого облака модульного сертификата нет и быть не может", err)
	}

	// Положительный контроль: без предъявленного удостоверения тот же вызывающий
	// в боевом режиме по-прежнему отвергается.
	if _, _, err := runChain(t, chain, context.Background()); err == nil {
		t.Fatal("политика вызывающего пропустила запрос БЕЗ всякой личности — она снята, " +
			"а не расширена")
	}
}

// mergeIncoming — метаданные контекста плюс добавленные.
func mergeIncoming(ctx context.Context, add metadata.MD) metadata.MD {
	base, _ := metadata.FromIncomingContext(ctx)
	out := base.Copy()
	if out == nil {
		out = metadata.MD{}
	}
	for k, vs := range add {
		for _, v := range vs {
			out.Append(k, v)
		}
	}
	return out
}

// noFloorCatalog / floorCatalog — каталог порогов доверия для проб.
//
// Подставной намеренно: предмет здесь — ВЕТВЬ политики, а не состав боевого
// каталога. Состав боевого каталога утверждает отдельная проба ниже — без неё
// обе ветви были бы верны о мире, в котором порогов не объявляет никто.
type noFloorCatalog struct{}

func (noFloorCatalog) RequiredACRMin(string) string { return "" }

type floorCatalog struct{ min string }

func (c floorCatalog) RequiredACRMin(string) string { return c.min }

// TestKAN_VER_01_PresentedLaneDoesNotBypassTheAssuranceFloor — полоса
// предъявленного НЕ снимает порог доверия, объявленный каталогом.
//
// # Что здесь охраняется
//
// Порог на публичном пути производит КРАЙ. До этого перехода край стоял на пути
// всякого публичного вызывающего by construction: без модульного сертификата
// дальше не пускали. Полоса предъявленного идёт МИМО края — значит вместе с ним
// исчезает единственный производитель порога, а каталог продолжает его
// объявлять. Это ровно тот класс, где два правила об одном запросе делают
// объявленное требование непроверяемым для целого класса вызывающих.
//
// Утверждение двустороннее, иначе вакуумно: глагол БЕЗ порога полоса пропускает.
func TestKAN_VER_01_PresentedLaneDoesNotBypassTheAssuranceFloor(t *testing.T) {
	reader, raw := chainReader(t)

	chainWith := func(catalog authzguard.ACRRequirementLookup) grpc.UnaryServerInterceptor {
		policy := authzguard.NewPublicCallerPolicy(true, authzguard.PublicPeerCallableRPCs(), catalog, presentedcred.Presented)
		return chainUnaryServer(append(
			publicIdentityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN), reader),
			policy.Unary())...)
	}

	// Положительный близнец: порога нет — вызов проходит.
	if _, _, err := runChain(t, chainWith(noFloorCatalog{}), presenting(raw)); err != nil {
		t.Fatalf("глагол без объявленного порога обязан проходить, иначе отрицание ниже "+
			"вакуумно: %v", err)
	}

	// Отрицание: отличие ровно одно — каталог объявил порог.
	_, _, err := runChain(t, chainWith(floorCatalog{min: "2"}), presenting(raw))
	if err == nil {
		t.Fatal("глагол с объявленным порогом доверия пропущен по предъявленному " +
			"удостоверению — порог объявлен каталогом и не проверяется никем")
	}
	if st := status.Convert(err); st.Code() != codes.PermissionDenied {
		t.Errorf("код отказа %s, ожидается %s — отказ обязан быть тем же, что у соседних "+
			"ветвей политики: «сертификата нет» и «доверия недостаточно» суть один ответ",
			st.Code(), codes.PermissionDenied)
	}
}

// TestKAN_VER_01_TheAssuranceFloorHasProducersInTheRealCatalog — проверка
// ПРЕДПОСЫЛКИ пробы выше.
//
// Ветвь охраняет порог, объявленный БОЕВЫМ каталогом. Если ни один публичный
// глагол порога не объявляет, ветвь стережёт то, чего не бывает, а проба выше
// верна о выдуманном мире. Перепись печатается: «ноль объявивших» обязано быть
// отличимо от «ноль прочитанного».
func TestKAN_VER_01_TheAssuranceFloorHasProducersInTheRealCatalog(t *testing.T) {
	registry, err := seed.LoadPermissionRegistry(context.Background(), slog.Default())
	if err != nil {
		t.Fatalf("боевой каталог прав не прочитан: %v", err)
	}
	entries := registry.All()
	if len(entries) == 0 {
		t.Fatal("обход пуст: каталог прав не несёт ни одной записи — предпосылка не проверена")
	}
	withFloor := 0
	for _, e := range entries {
		if e.RequiredACRMin != "" {
			withFloor++
		}
	}
	t.Logf("перепись: записей каталога %d · объявляют порог доверия %d", len(entries), withFloor)
	if withFloor == 0 {
		t.Fatal("ни одна запись каталога не объявляет порога доверия — ветвь политики стережёт " +
			"то, чего не бывает, и проба выше верна о выдуманном мире")
	}
}
