// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// trusted_forwarders_test.go — замки на измерение «кому разрешено передавать
// личность конечного пользователя» в kaname.
//
// Что было не так. Оба листенера строили доверенную пару CertIdentityExtract →
// TrustedPrincipalExtract, но с ПУСТЫМ списком отправителей. По контракту corelib
// (pkg/grpcsrv principalIsTrusted) это означает не «никому», а «любому пиру,
// прошедшему проверку сертификата». Оба gRPC-порта — обычные Service внутри
// пространства имён, клиентский сертификат всем соседям выдаёт один и тот же
// внутренний центр, а единственная сетевая политика, выбирающая под iam,
// покрывает внутренний порт и вне боевого профиля выключена.
//
// Цена именно здесь выше, чем у соседей: на :9090 iam СОЗНАТЕЛЬНО не
// перепроверяет права конечного пользователя (единственная парадная дверь —
// api-gateway). Значит сосед, приславший заголовки личности жертвы, получал её
// полномочия на всей тенантской поверхности — вплоть до чеканки личных токенов и
// ключей служебных учёток.
//
// Замки утверждают НАБЛЮДАЕМОЕ: какую личность увидит обработчик за цепочкой,
// которую собирает боевая проводка, со списком из боевой конфигурации. Что эту
// цепочку получают ОБА листенера — предмет trusted_forwarders_wiring_test.go.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	// fwdGatewaySAN — парадная дверь: единственный отправитель, который передаёт
	// личность на ВСЕЙ поверхности обоих листенеров.
	fwdGatewaySAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	// fwdVPCSAN — сосед, который передаёт личность ЗАКОННО, но на одном
	// read-ребре (ProjectService.Get на пути запроса своего Create). Он в списке
	// отправителей — сужает его пер-RPC политика, не этот слой.
	fwdVPCSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
	// fwdOutsiderSAN — пир с законным сертификатом внутреннего центра, которому
	// передавать чужую личность НЕ разрешено вовсе. Взят НЕ выдуманный: у
	// bootstrap-оператора есть собственный клиентский сертификат того же центра
	// (umbrella templates/bootstrap-operator-certificate.yaml), он ходит в iam на
	// :9091 и по форме своего SAN проходит модульный пол — но роли отправителя
	// чужой личности у него нет. То есть «держит валидный сертификат модуля» и
	// «вправе говорить за пользователя» — РАЗНЫЕ вещи, и именно это здесь
	// проверяется.
	fwdOutsiderSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-operator"

	fwdVictimUserID = "usr-victim"
)

// fwdCfg — конфигурация, с которой процесс поднимается в боевом режиме; тесты
// меняют РОВНО ОДНО — список отправителей.
func fwdCfg(forwarders ...string) config.Config {
	return config.Config{
		AuthN: config.AuthNConfig{
			Mode:                 config.ModeProductionStrict,
			TrustedForwarderSANs: forwarders,
			// Домен доверия — величина установки: по необъявленному не опознаётся
			// ни один предъявитель, и проба судила бы отказ домена вместо своего
			// предмета — круга отправителей.
			TrustDomainName: "kacho.cloud",
		},
	}
}

// seenIdentity прогоняет запрос через цепочку и возвращает личность, которую
// увидел бы обработчик, признак доверия и наличие носителя. Это и есть
// наблюдаемое: субъект решения о правах собирается ровно отсюда
// (operations.PrincipalFromContext / authzguard.PrincipalSubject).
func seenIdentity(t *testing.T, ctx context.Context, forwarders ...string) (id string, trusted, present bool) {
	t.Helper()
	final := func(c context.Context, _ any) (any, error) {
		p, ok := operations.PrincipalFromContextOK(c)
		id, present = p.ID, ok
		_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
		return nil, nil
	}
	chain := chainUnaryServer(identityUnary(fwdCfg(forwarders...))...)
	if _, err := chain(ctx, nil, nil, final); err != nil {
		t.Fatalf("chain returned error: %v", err)
	}
	return id, trusted, present
}

// TestListener_NeighbourWithValidCertCannotActAsSomeoneElse — главный замок.
//
// Сосед предъявляет ЗАКОННЫЙ сертификат внутреннего центра и присылает заголовки
// личности жертвы. Он обязан остаться собой: переданная личность снимается,
// носитель вычищается, и решение о правах не может выполниться от имени жертвы.
//
// RED до правки: список отправителей пуст, corelib доверяет любому проверенному
// пиру — личность жертвы доходит до обработчика.
func TestListener_NeighbourWithValidCertCannotActAsSomeoneElse(t *testing.T) {
	id, trusted, present := seenIdentity(t,
		forwardedIdentity(verifiedCertPeer(t, fwdOutsiderSAN), fwdVictimUserID), fwdGatewaySAN, fwdVPCSAN)

	if id == fwdVictimUserID {
		t.Fatalf("a neighbour (%s) presented itself as %q — iam does NOT re-ReBAC the end user on "+
			"its own listeners, so the whole tenant surface would answer in the victim's name: "+
			"accounts, projects, groups, roles, grants, and the minting of personal tokens and "+
			"service-account keys", fwdOutsiderSAN, fwdVictimUserID)
	}
	if trusted {
		t.Fatalf("the forwarded identity from %s was marked trusted", fwdOutsiderSAN)
	}
	if present {
		t.Fatalf("the identity carrier survived for an untrusted sender: got %q "+
			"(it must be scrubbed, otherwise use-cases downstream see a forged actor in "+
			"granted_by / created_by / audit)", id)
	}
}

// TestListener_PinnedSendersKeepWorking — НЕ замок на дыру (с пустым списком он
// тоже зелёный: там доверены все). Его предмет — обратная ошибка: сузить так, что
// перестанет работать рабочий путь. Без gateway встают ВСЕ пользовательские
// запросы; без consumer-модулей встаёт проверка проекта на пути запроса Create в
// пяти сервисах.
func TestListener_PinnedSendersKeepWorking(t *testing.T) {
	for _, san := range []string{fwdGatewaySAN, fwdVPCSAN} {
		id, trusted, present := seenIdentity(t,
			forwardedIdentity(verifiedCertPeer(t, san), "usr-alice"), fwdGatewaySAN, fwdVPCSAN)
		if !trusted || !present {
			t.Fatalf("%s was refused (trusted=%v present=%v) — the change denies service instead "+
				"of narrowing it", san, trusted, present)
		}
		if id != "usr-alice" {
			t.Fatalf("%s: forwarded identity not honoured: got %q, want %q", san, id, "usr-alice")
		}
	}
}

// TestListener_UnverifiedPeerCannotForward — НЕ замок на дыру: после правки эта
// ветка срабатывает независимо от списка. Держит нижний слой инварианта, чтобы
// правка списка не увела внимание от него.
func TestListener_UnverifiedPeerCannotForward(t *testing.T) {
	id, trusted, _ := seenIdentity(t,
		forwardedIdentity(unverifiedTLSPeerCtx(), fwdVictimUserID), fwdGatewaySAN)

	if trusted || id == fwdVictimUserID {
		t.Fatalf("a peer without a verified client certificate forwarded an identity: id=%q trusted=%v", id, trusted)
	}
}

// TestListener_BlankOnlyAllowListIsNotANarrowing — честный отчёт о вырождении:
// список из одних пустых записей corelib отбрасывает, поэтому круг НЕ сужен и
// сосед снова становится жертвой. Стража старта обязана такую конфигурацию не
// пустить (config.Validate) — здесь фиксируется, ПОЧЕМУ она обязана.
func TestListener_BlankOnlyAllowListIsNotANarrowing(t *testing.T) {
	id, trusted, _ := seenIdentity(t,
		forwardedIdentity(verifiedCertPeer(t, fwdOutsiderSAN), fwdVictimUserID), "", " ")

	if !trusted || id != fwdVictimUserID {
		t.Fatalf("blank entries unexpectedly narrowed the circle (id=%q trusted=%v) — if corelib "+
			"ever starts honouring them, the boot guard's reason to reject them changes and this "+
			"lock must be revisited together with it", id, trusted)
	}
}

// ── самоотчёт о посадке ─────────────────────────────────────────────────────

// TestBootPosture_ReportsWhetherTheCircleIsNarrowed — самоотчёт живого процесса
// обязан нести это измерение: гейт посадки читает строку процесса, а не хранимые
// настройки, поэтому неотчитанное измерение для него не существует.
//
// Значение берётся из той же config.AuthN.TrustedForwarders, что уходит в
// проводку, — отчёт не может разойтись с посадкой.
func TestBootPosture_ReportsWhetherTheCircleIsNarrowed(t *testing.T) {
	posture := func(sans ...string) bool {
		cfg := fwdCfg(sans...)
		// Дескриптор посадки строится на ПРИНИМАЕМОМ круге: центральный
		// конструктор не пропускает несужённый круг на боевой посадке (О1), и
		// это его работа. Предмет пробы другой — что САМООТЧЁТ описывает исход,
		// а не намерение, — поэтому измеряемый круг подаётся в `bootPosture`
		// отдельно, ровно тем значением, которое проба и проверяет.
		accepted := fwdCfg(fwdGatewaySAN)
		accepted.Repository.Postgres.URL = "postgres://u:p@pg-iam:5432/kaname"
		accepted.Repository.Postgres.SSLMode = "require"
		return bootPosture(acceptedPosture(t, accepted), cfg, config.MTLSConfig{}, true).TrustedForwarders
	}
	t.Run("pinned", func(t *testing.T) {
		if !posture(fwdGatewaySAN) {
			t.Fatal("a pinned allow-list must be reported as a narrowing")
		}
	})
	t.Run("empty_is_reported_honestly", func(t *testing.T) {
		if posture() {
			t.Fatal("an empty allow-list reported as a narrowing — the report describes intent, not outcome")
		}
	})
	t.Run("blank_entries_are_not_a_narrowing", func(t *testing.T) {
		if posture("", " ") {
			t.Fatal("blank entries reported as a narrowing: corelib drops them, so the circle stays open")
		}
	})
}

// ── helpers ─────────────────────────────────────────────────────────────────

// forwardedIdentity кладёт во входящие метаданные заголовки личности, которые
// отправитель передаёт за пользователя.
func forwardedIdentity(ctx context.Context, userID string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs(
		grpcsrv.MDKeyPrincipalType, "user",
		grpcsrv.MDKeyPrincipalID, userID,
		grpcsrv.MDKeyPrincipalDisplay, userID,
	))
}

// verifiedCertPeer — пир, прошедший проверку клиентского сертификата, с
// указанной личностью сертификата.
func verifiedCertPeer(t *testing.T, san string) context.Context {
	t.Helper()
	leaf := &x509.Certificate{URIs: mustParseURIs(t, san)}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}},
	}})
}

// unverifiedTLSPeerCtx — TLS есть, подтверждённого клиентского сертификата нет.
func unverifiedTLSPeerCtx() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	})
}

// TestConfigRefusal_NamesTheEnvOverride — отказ старта обязан назвать переменную
// окружения, которой оператор заполняет список: без имени сообщение
// «настройте что-нибудь» бесполезно на боевом кластере.
func TestConfigRefusal_NamesTheEnvOverride(t *testing.T) {
	cfg := fwdCfg()
	cfg.APIServer = config.APIServerConfig{
		Endpoint:         "tcp://0.0.0.0:9090",
		InternalEndpoint: "tcp://0.0.0.0:9091",
	}
	cfg.Repository.Postgres.URL = "postgres://u:p@db:5432/kaname"
	cfg.Repository.Postgres.SSLMode = "require"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("production Validate() accepted an empty trusted-forwarder allow-list")
	}
	if !strings.Contains(err.Error(), "KANAME_AUTHN__TRUSTED_FORWARDER_SANS") {
		t.Fatalf("the refusal must name the env override an operator sets, got: %v", err)
	}
}
