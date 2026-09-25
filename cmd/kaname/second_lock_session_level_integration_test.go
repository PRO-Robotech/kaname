// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// second_lock_session_level_integration_test.go — Ф11-20, ПОЛОВИНА НА ГРАНИЦЕ
// СЛУЖБЫ (задача PRO-Robotech/kacho#1280; приёмка
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`
// ред. 5, Ф11-20; §8 строка «Ф11-20»; П2, П3, П10).
//
// # Что утверждается
//
// Дано: сессия в согласованном состоянии «2» в хранилище службы (§3.0а) у
// личности, держащей `system_admin` на кластере по посеву бутстрапа
// (`seed.RunBootstrapAdmin`). Уровень, который край пересылает второму замку, —
// уровень из ответа службы краю о сессии (`Resolve`); он обязан быть РАВЕН
// уровню нашей сессии, и с ним пол второго замка на глаголе внутреннего
// слушателя с полом «2» (`InternalClusterService/GrantAdmin`, П10) пройден. Тот
// же вызов с пересланным «1» в обход первого замка отвергается
// `PERMISSION_DENIED` с нарушением вида `authz.step_up`, требующим «2»: второй
// замок держит пол сам и решает по тому же значению и той же функцией
// (`grpcsrv.EvaluateStepUp`), что первый.
//
// Половина края — пересылка уровня нашей сессии в `x-kacho-token-acr` — дом
// платформы (`gateway/internal/middleware/own_session_assurance_test.go`,
// `TestOwnSessionAssurance_F11_20_ForwardedLevelEqualsTheSessionLevel`).
//
// # Как проба зовёт второй замок — так, как зовёт край
//
// По mTLS: настоящий TLS-слушатель, клиентский сертификат с SAN края,
// метаданные личности и уровня. Цепочка — внутреннего слушателя `serve.go` в
// боевом режиме, собранная ТЕМИ ЖЕ конструкторами: сборщик личности
// `identityUnary` (круг отправителей — край), политика вызывающего, пол уровня
// над встроенным каталогом прав, звено причины отказа. Против цепочки
// `serve.go` не собраны три звена, и ни одно не решает судьбу этого вызова:
// измеритель задержки (только считает), `UnaryPanicRecovery` (действует лишь
// на панике) и пол `system_viewer` (стоит только на читающих глаголах,
// `ReadFloorRPCs`, а `GrantAdmin` — мутация). У политики вызывающего не
// заданы два уточнения боевой сборки: `WithSANAllowlist` — рукав с перечнем
// сертификатов, он стоит только на чеканке токена начальной загрузки, — и
// `WithOwnFrontHop` — допуск хопа собственного фронта, а вызывающий пробы —
// край, не фронт.
// Обработчик — дублёр, отмечающий, что до него дошли: предмет пробы — пол, а не
// выдача прав (её держат пробы `internal/apps/kaname/api/cluster`).
//
// # Чего `system_admin` здесь НЕ делает — сказано прямо
//
// Второй замок это отношение не читает: без него отказ даёт проверка прав КРАЯ
// до пересылки (§3.0). Факт заведён потому, что он — часть «Дано», и мир пробы
// обязан совпадать с миром сценария; наличие выдачи проверяется до предмета.
//
// # Способность падать (инъекцией, откат, зелёное)
//
//   - `acr_floor.go`: пол не спрашивает каталог (`if true || acrlevel.Rank(required)
//     == 0`) → красное «второй замок пропустил пересланное «1»»;
//   - `resolve.go`, `sessionProto`: ответ краю называет «1» вместо уровня
//     записи → красное «пересылаемое значение не равно уровню нашей сессии».
//
// Run: `go test ./cmd/kaname/ -run F11_20 -count=1` (Docker). Skipped under -short.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/ids"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// TestSecondLockIntegration_F11_20_ForwardedSessionLevelPassesAndABypassingOneIsRefused — Ф11-20.
func TestSecondLockIntegration_F11_20_ForwardedSessionLevelPassesAndABypassingOneIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	logger := slog.New(slog.DiscardHandler)

	// Дано 1 — личность, заведённая регистрацией (Ф4), и `system_admin` на
	// кластере посевом бутстрапа по её адресу.
	user := registerSecondLockPerson(t, ctx, pool, logger)
	boot, err := seed.RunBootstrapAdmin(ctx, pool, logger, seed.BootstrapAdminInput{Email: string(user.Email)})
	require.NoError(t, err)
	require.False(t, boot.Skipped, "Дано: посев бутстрапа выдал права (причина пропуска: %q)", boot.SkipReason)
	require.Equal(t, string(user.ID), boot.UserID, "Дано: посев выдал права ЭТОЙ личности")
	var grants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, string(user.ID)).Scan(&grants))
	require.Equal(t, 1, grants, "Дано: выдача system_admin на кластере записана")

	// Дано 2 — сессия в согласованном состоянии «2»: производитель выдачи
	// продукта с множеством, которое даёт вход паролем и кодом (Ф11-02);
	// уровень выводит правило, а не проба (§3.0а).
	sessions := kanamepg.NewHumanSessionRepo(pool)
	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	issued, bearer, err := humansession.IssueSession(ctx, w, humansession.IssueInput{
		User: user, Presented: []assurance.Presentation{assurance.PasswordPresented(), assurance.TOTPPresented()},
		At: time.Now().UTC(), TTL: 24 * time.Hour, EmitAudit: true,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, "2", issued.AssuranceLevel, "Дано: согласованное состояние «2» при {password, totp}")

	// Значение, которое край пересылает, — уровень из ответа службы краю о сессии.
	resolveUC, err := humansession.NewResolveUseCase(sessions, humansession.NopObserver{}, time.Now)
	require.NoError(t, err)
	answer, err := humansession.NewHandler(resolveUC).Resolve(ctx, &iamv1.ResolveHumanSessionRequest{Bearer: bearer.CookieValue()})
	require.NoError(t, err)
	require.True(t, answer.GetFound(), "ответ краю о живой сессии — «найдена»")
	forwarded := answer.GetSession().GetAssuranceLevel()
	require.Equal(t, issued.AssuranceLevel, forwarded,
		"пересылаемое значение не равно уровню нашей сессии: ответ краю называет %q, запись сессии — %q", forwarded, issued.AssuranceLevel)

	reg, err := seed.LoadPermissionRegistry(ctx, nil)
	require.NoError(t, err)
	required := reg.RequiredACRMin(strings.TrimPrefix(grantAdminFQN, "/"))
	require.Equal(t, "2", required, "Дано: глагол внутреннего слушателя с полом «2» (П10) — пол читается у каталога")

	stub := &secondLockReached{}
	client := iamv1.NewInternalClusterServiceClient(serveSecondLock(t, reg, stub))
	grant := func(acr string) error {
		md := metadata.Pairs(
			grpcsrv.MDKeyTokenACR, acr,
			grpcsrv.MDKeyPrincipalType, "user",
			grpcsrv.MDKeyPrincipalID, string(user.ID),
		)
		callCtx, cancel := context.WithTimeout(metadata.NewOutgoingContext(ctx, md), 5*time.Second)
		defer cancel()
		_, err := client.GrantAdmin(callCtx, &iamv1.GrantClusterAdminRequest{
			SubjectType: iamv1.ClusterGrantSubjectType_USER, SubjectId: string(user.ID),
		})
		return err
	}
	firstLock := func(acr string) grpcsrv.StepUpVerdict {
		return grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{PrincipalType: "user", PresentedACR: acr, RequiredACR: required})
	}

	// Положительная половина: пересланное значение нашей сессии — пол пройден.
	require.NoError(t, grant(forwarded), "второй замок отверг уровень %q нашей сессии на полу %q", forwarded, required)
	require.True(t, stub.reached.Load(), "пол пройден — вызов дошёл до обработчика")
	require.Equal(t, grpcsrv.StepUpAllow, firstLock(forwarded), "первый замок над тем же значением — тоже проход")

	// В обход первого: пересланное «1» — отказ второго замка своей формой.
	stub.reached.Store(false)
	err = grant("1")
	st := status.Convert(err)
	require.Equal(t, codes.PermissionDenied, st.Code(), "второй замок пропустил пересланное «1» на полу %q: %v", required, err)
	require.Equal(t, "permission denied", st.Message())
	require.False(t, stub.reached.Load(), "отказ второго замка — до обработчика, без следствий")
	var stepUp *errdetails.PreconditionFailure_Violation
	for _, d := range st.Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok {
			for _, v := range pf.GetViolations() {
				if v.GetType() == "authz.step_up" {
					stepUp = v
				}
			}
		}
	}
	require.NotNil(t, stepUp, "отказ несёт нарушение вида authz.step_up: детали %v", st.Details())
	require.Equal(t, "acr_values:2", stepUp.GetSubject(), "нарушение требует «2»")
	require.NotEqual(t, grpcsrv.StepUpAllow, firstLock("1"), "первый замок над тем же «1» — тоже отказ: решение одно")
}

// secondLockReached — обработчик-дублёр: отмечает, что вызов прошёл цепочку.
// Отметка атомарна не ради детектора гонок: он размечает «произошло-до» на
// `syscall.Read` / `syscall.Write`, и ответ по TCP сам упорядочивает запись
// обработчика и чтение пробы. Атомарность нужна, чтобы корректность пробы не
// держалась на этой разметке транспорта: обработчик и проба — разные
// горутины, и отметка упорядочена сама.
type secondLockReached struct {
	iamv1.UnimplementedInternalClusterServiceServer
	reached atomic.Bool
}

func (s *secondLockReached) GrantAdmin(context.Context, *iamv1.GrantClusterAdminRequest) (*operationpb.Operation, error) {
	s.reached.Store(true)
	return &operationpb.Operation{Id: "iop-second-lock-probe", Done: true}, nil
}

// registerSecondLockPerson — личность регистрацией паролем (Ф4) тем же
// адаптером, что корень (`registrationStore`).
func registerSecondLockPerson(t *testing.T, ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) domain.User {
	t.Helper()
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}})
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, logger)
	require.NoError(t, err)
	regLane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	register, err := registration.NewRegisterUseCase(registration.Deps{
		Store: registrationStore{inner: kanamepg.NewRegistrationStore(pool)}, Rule: rule, Hasher: hasher, Lane: regLane,
		TTL: 24 * time.Hour, Observer: registration.NopObserver{}, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	out, err := register.Execute(ctx, registration.Input{
		Email: "sl20-" + ids.NewID("tst")[3:11] + "@example.invalid", Password: "second-lock-person-f11-20", Source: "203.0.113.20",
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.View.User.ID, "Дано: регистрация назвала личность")
	return out.View.User
}

// serveSecondLock — внутренний слушатель службы по mTLS с цепочкой боевого
// режима; отдаёт соединение клиента с сертификатом края.
func serveSecondLock(t *testing.T, reg *seed.PermissionRegistry, srv iamv1.InternalClusterServiceServer) *grpc.ClientConn {
	t.Helper()
	serverTLS, clientTLS := secondLockTLS(t, acrTestGatewaySAN)
	chain := append([]grpc.UnaryServerInterceptor{authzguard.DenyDetailUnary(reg)}, identityUnary(fwdCfg(acrTestGatewaySAN))...)
	chain = append(chain,
		authzguard.NewCallerPolicy(true, authzguard.GatewayFrontedInternalRPCs()).Unary(),
		authzguard.NewACRFloor(reg, authzguard.GatewayFrontedInternalRPCs()).WithProductionMode(true).Unary(),
	)
	gsrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)), grpc.ChainUnaryInterceptor(chain...))
	iamv1.RegisterInternalClusterServiceServer(gsrv, srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// secondLockTLS — центр пробы, лист слушателя и клиентский лист с SAN
// вызывающего: личность сертификата извлекает слушатель, а не проба.
func secondLockTLS(t *testing.T, clientSAN string) (server, client *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "second-lock-probe-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leaf := func(serial int64, usage x509.ExtKeyUsage, san string) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "second-lock-probe-leaf"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		if san != "" {
			tmpl.URIs = mustParseURIs(t, san)
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server = &tls.Config{
		Certificates: []tls.Certificate{leaf(2, x509.ExtKeyUsageServerAuth, "")},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12,
	}
	client = &tls.Config{
		Certificates: []tls.Certificate{leaf(3, x509.ExtKeyUsageClientAuth, clientSAN)},
		RootCAs:      roots, ServerName: "localhost", MinVersion: tls.VersionTLS12,
	}
	return server, client
}
