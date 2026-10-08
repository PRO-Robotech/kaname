// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ntf_grant_fixture_test.go — ФИКСТУРА проб звена Р2 (K5) и записи выдачи
// (K3) приёмки NTF-1. Предмета здесь нет: файл собирается на дереве, где ни
// звена Р2 в корне, ни службы выдачи ещё нет, и каждое его средство проверяет
// СВОЙ исход раньше, чем проба спросит предмет (скил `change-graph` §2: порядок
// «фикстура → близнец → предмет» несущий — сломанная фикстура не имеет права
// выдать себя за отсутствующую возможность).
//
// Что даёт фикстура и чем каждое средство себя проверяет:
//
//   - центр пробы и листы с точным SAN — рукопожатие слушателя проверяет
//     цепочку, личность извлекает слушатель, а не проба;
//   - база пробы с журналом операторов — счётчик видит ровно те операторы,
//     что ушли в базу через пул службы: «чтений записи выдачи 0» и «вопрос о
//     праве задан с субъектом X» — это измерение провода, а не вызов дублёра.
//     Счётчик проверяется положительным контролем (вопрос двери, заданный
//     фикстурой сам, обязан в нём появиться) — иначе «0» читался бы и у
//     слепого счётчика;
//   - дверь решения — та же форма, что строит корень (`relverdict` +
//     `personmarks` под `authzcascade.WrapAdmitted`), без дублёра;
//   - посев — настоящий применитель манифестов (`moduleseed`);
//   - администратор кластера — посеянная миграцией служебная учётка; фикстура
//     сама спрашивает дверь, что она администратор, прежде чем проба
//     опереться на это.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Личности пробы. Домен доверия тот же, что у соседних проб корня
// (`fwdCfg`): у разных доменов разные круги, и проба судила бы домен.
const (
	ntfTrustDomain = "kacho.cloud"
	// ntfNotifySAN — сертификат A сценария NTF1-J03: точный SAN notify.
	ntfNotifySAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-notify"
	// ntfForeignNotifySAN — сертификат B NTF1-J03: та же учётка, другое
	// пространство имён. Отличается от A РОВНО одним сегментом.
	ntfForeignNotifySAN = "spiffe://kacho.cloud/ns/x/sa/kacho-notify"
	// ntfVPCSAN — модульная учётка корпуса NTF1-M07.
	ntfVPCSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"

	// ntfResolveSendKey — запись перечня Р2 в ФОРМЕ ФАЙЛА (замысел З13,
	// «Ручка kaname»): полное имя без ведущей косой.
	ntfResolveSendKey = "kaname.cloud.iam.v1.InternalNotificationGrantService/ResolveSend"
	// ntfCheckKey — метод, который ЕСТЬ в реестре прав и которого НЕТ в
	// закрытом перечне корня (NTF1-M09 (в), М07).
	ntfCheckKey = "kaname.cloud.iam.v1.InternalIAMService/Check"

	// ntfProbeManifest — фикстурный модуль `probe` со строкой F01.
	ntfProbeManifest = `
apiVersion: iam/v1
module: probe
resources: []
notifications: {namespace: probe, readers: [notify]}
`
	// ntfProbeManifestNoLine — тот же модуль без строки (NTF1-F04, Дано).
	ntfProbeManifestNoLine = `
apiVersion: iam/v1
module: probe
resources: []
`
)

// ntfServiceIdentityYAML — ключ `authn.service-identity` в форме файла (З13).
// Пустой перечень или пустая таблица опускают свою часть целиком — так
// «половина ключа» отличается от согласного ключа ровно одной частью.
func ntfServiceIdentityYAML(methods []string, services [][2]string) string {
	var b strings.Builder
	b.WriteString("authn:\n  service-identity:\n")
	if len(methods) > 0 {
		b.WriteString("    methods:\n")
		for _, m := range methods {
			fmt.Fprintf(&b, "      - %s\n", m)
		}
	}
	if len(services) > 0 {
		b.WriteString("    services:\n")
		for _, s := range services {
			fmt.Fprintf(&b, "      - san: %q\n        name: %q\n", s[0], s[1])
		}
	}
	return b.String()
}

// ntfAgreedIdentityYAML — согласный ключ: перечень `{ResolveSend}`, таблица
// `{SAN notify → notify}`.
func ntfAgreedIdentityYAML() string {
	return ntfServiceIdentityYAML([]string{ntfResolveSendKey}, [][2]string{{ntfNotifySAN, "notify"}})
}

// ntfConfig — настройка корня: ключи, которых декодер ещё мог не знать,
// приходят ФАЙЛОМ через настоящую загрузку (значение получает ровно тот путь,
// которым его получит процесс), прочее — полями.
//
// Пустой yaml — файл не передаётся вовсе: фикстура «ключа нет».
func ntfConfig(t *testing.T, yaml string) (config.Config, error) {
	t.Helper()
	path := ""
	if yaml != "" {
		path = filepath.Join(t.TempDir(), "kaname.yaml")
		require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600), "фикстура: файл настройки не записан")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, err
	}
	cfg.AuthN.Mode = config.ModeProductionStrict
	cfg.AuthN.TrustDomainName = ntfTrustDomain
	cfg.AuthN.TrustedForwarderSANs = []string{acrTestGatewaySAN}
	return cfg, nil
}

// ── ЦЕНТР И ЛИСТЫ ───────────────────────────────────────────────────────────

// ntfPKI — центр пробы и лист слушателя. Клиентские листы выпускаются по
// SAN тем же центром.
type ntfPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	roots  *x509.CertPool
	server tls.Certificate
	serial int64
	mu     sync.Mutex
}

func newNTFPKI(t *testing.T) *ntfPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ntf1-probe-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	p := &ntfPKI{ca: ca, caKey: caKey, roots: x509.NewCertPool(), serial: 1}
	p.roots.AddCert(ca)
	p.server = p.leaf(t, x509.ExtKeyUsageServerAuth, "")
	return p
}

func (p *ntfPKI) leaf(t *testing.T, usage x509.ExtKeyUsage, san string) tls.Certificate {
	t.Helper()
	p.mu.Lock()
	p.serial++
	serial := p.serial
	p.mu.Unlock()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "ntf1-probe-leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if san != "" {
		tmpl.URIs = mustParseURIs(t, san)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ntfListener — внутренний слушатель пробы: mTLS с проверкой клиента, цепочка
// приходит снаружи (её собирает корень, а не проба), службы регистрирует
// вызывающий.
type ntfListener struct {
	pki  *ntfPKI
	addr string
	srv  *grpc.Server
}

func ntfServe(t *testing.T, pki *ntfPKI, chain []grpc.UnaryServerInterceptor, register func(grpc.ServiceRegistrar)) *ntfListener {
	t.Helper()
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pki.roots, MinVersion: tls.VersionTLS12,
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)), grpc.ChainUnaryInterceptor(chain...))
	register(srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return &ntfListener{pki: pki, addr: lis.Addr().String(), srv: srv}
}

// dial — соединение пира с листом точного SAN.
func (l *ntfListener) dial(t *testing.T, san string) *grpc.ClientConn {
	t.Helper()
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{l.pki.leaf(t, x509.ExtKeyUsageClientAuth, san)},
		RootCAs:      l.pki.roots, ServerName: "localhost", MinVersion: tls.VersionTLS12,
	}
	conn, err := grpc.NewClient(l.addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// ── БАЗА И ЖУРНАЛ ОПЕРАТОРОВ ────────────────────────────────────────────────

// ntfStatement — один оператор, ушедший в базу через пул службы.
type ntfStatement struct {
	sql  string
	args []string
}

// ntfWire — журнал операторов пула службы (pgx QueryTracer + BatchTracer).
//
// Измеряется провод, а не вызов: «чтений записи выдачи 0» — ноль операторов
// о таблицах записи выдачи, «вопрос о праве задан с субъектом X» — оператор
// двери, аргументы которого несут тип `notification_feed` и субъекта X.
type ntfWire struct {
	mu    sync.Mutex
	stmts []ntfStatement
}

func (w *ntfWire) record(sql string, args []any) {
	s := ntfStatement{sql: sql, args: make([]string, 0, len(args))}
	for _, a := range args {
		s.args = append(s.args, fmt.Sprint(a))
	}
	w.mu.Lock()
	w.stmts = append(w.stmts, s)
	w.mu.Unlock()
}

func (w *ntfWire) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	w.record(d.SQL, d.Args)
	return ctx
}
func (w *ntfWire) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (w *ntfWire) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}
func (w *ntfWire) TraceBatchQuery(_ context.Context, _ *pgx.Conn, d pgx.TraceBatchQueryData) {
	w.record(d.SQL, d.Args)
}
func (w *ntfWire) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

// reset — начало измеряемого окна.
func (w *ntfWire) reset() {
	w.mu.Lock()
	w.stmts = nil
	w.mu.Unlock()
}

func (w *ntfWire) snapshot() []ntfStatement {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]ntfStatement(nil), w.stmts...)
}

// grantStatements — операторы о таблицах записи выдачи (замысел §6:
// `notification_grants`, `notification_template_grants`).
func (w *ntfWire) grantStatements() int {
	n := 0
	for _, s := range w.snapshot() {
		if strings.Contains(s.sql, "notification_grants") || strings.Contains(s.sql, "notification_template_grants") {
			n++
		}
	}
	return n
}

// feedQuestionSubjects — субъекты вопросов о `notification_feed`, заданных
// двери: аргумент оператора несёт тип ленты, субъект — аргумент с
// приставкой типа субъекта.
func (w *ntfWire) feedQuestionSubjects() []string {
	var out []string
	for _, s := range w.snapshot() {
		feed := false
		for _, a := range s.args {
			if strings.Contains(a, "notification_feed") {
				feed = true
				break
			}
		}
		if !feed {
			continue
		}
		for _, a := range s.args {
			if strings.HasPrefix(a, "service:") || strings.HasPrefix(a, "user:") || strings.HasPrefix(a, "service_account:") {
				out = append(out, a)
			}
		}
	}
	return out
}

// ntfDB — база пробы: свой клон, пул службы с журналом операторов и пул
// фикстуры БЕЗ журнала (её собственные чтения в счёт не идут).
type ntfDB struct {
	pool    *pgxpool.Pool
	fixture *pgxpool.Pool
	wire    *ntfWire
	// dsn — адрес клона: удерживаемая транзакция гонки берёт по нему СВОЁ
	// соединение, а не соединение пула фикстуры (см. afBegin).
	dsn string
}

func newNTFDB(t *testing.T) *ntfDB {
	t.Helper()
	ctx := context.Background()
	dsn := pgtest.NewDB(t)
	pcfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	wire := &ntfWire{}
	pcfg.ConnConfig.Tracer = wire
	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	fixture, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, fixture)
	return &ntfDB{pool: pool, fixture: fixture, wire: wire, dsn: dsn}
}

// ntfDoor — дверь решения той же формы, что строит корень (`wiring.go`,
// `relationStore` и `buildAuthZServices`), на пуле службы.
func ntfDoor(db *ntfDB) (*service.AuthorizeService, *authzcascade.Client) {
	relations := authzcascade.WrapAdmitted(relverdict.NewAsker(db.pool), personmarks.New(db.pool))
	return service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: relations, ClusterAdminChecker: relations,
	}), relations
}

// requireWireSeesDoorQuestions — положительный контроль журнала: вопрос
// двери о ленте, заданный фикстурой, обязан появиться в журнале со своим
// субъектом. Без него «вопросов 0» в пробе было бы неотличимо от слепого
// журнала.
func requireWireSeesDoorQuestions(t *testing.T, db *ntfDB, door *service.AuthorizeService) {
	t.Helper()
	db.wire.reset()
	_, err := door.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: "service:wire-control", Relation: "reader", Object: "notification_feed:wire-control",
	})
	require.NoError(t, err, "фикстура: дверь не ответила на вопрос положительного контроля журнала")
	require.Contains(t, db.wire.feedQuestionSubjects(), "service:wire-control",
		"фикстура: журнал операторов не видит вопроса двери о ленте — счётчик пробы слеп, "+
			"его «0» ничего не доказывал бы; операторов в окне: %d", len(db.wire.snapshot()))
	db.wire.reset()
}

// ntfApply — посев настоящим применителем манифестов.
func ntfApply(t *testing.T, db *ntfDB, yamls ...string) {
	t.Helper()
	ms := make([]*manifest.Manifest, 0, len(yamls))
	for _, y := range yamls {
		m, err := manifest.Load([]byte(y))
		require.NoError(t, err, "фикстура: манифест не принят разбором — вердикт беспредметен")
		ms = append(ms, m)
	}
	_, err := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(db.fixture)).ApplyAll(context.Background(), ms)
	require.NoError(t, err, "фикстура: посев не прошёл")
}

// ntfFactCount — число фактов модели под условием (чтение фикстуры).
func ntfFactCount(t *testing.T, db *ntfDB, subject, relation, objectType, objectID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.fixture.QueryRow(context.Background(), `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE subject = $1 AND relation = $2 AND object_type = $3 AND object_id = $4`,
		subject, relation, objectType, objectID).Scan(&n))
	return n
}

// ntfSeedFeedReader — факт `service:notify reader notification_feed:<ns>`
// напрямую, без строки манифеста: ось «право читать ленту» отделена от оси
// «запись выдачи» (NTF1-F04, F14, F23 — у них записи выдачи нет, а читатель
// есть).
func ntfSeedFeedReader(t *testing.T, db *ntfDB, ns string) {
	t.Helper()
	_, err := db.fixture.Exec(context.Background(), `
		INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		VALUES ('notification_feed', $1, 'reader', 'service:notify')`, ns)
	require.NoError(t, err, "фикстура: факт читателя ленты не посеян")
	require.Equal(t, 1, ntfFactCount(t, db, "service:notify", "reader", "notification_feed", ns))
}

// ntfAdminCtx — контекст администратора кластера: служебная учётка, которой
// миграция выдаёт `system_admin` на кластер. Фикстура сама спрашивает дверь,
// что это так, прежде чем проба на это опрётся.
func ntfAdminCtx(t *testing.T, db *ntfDB, door *service.AuthorizeService) context.Context {
	t.Helper()
	ctx := context.Background()
	var id string
	require.NoError(t, db.fixture.QueryRow(ctx, `
		SELECT subject_id FROM kaname.cluster_admin_grants
		 WHERE subject_type = 'service_account' AND granted_until IS NULL
		 ORDER BY subject_id LIMIT 1`).Scan(&id), "фикстура: посеянного администратора кластера нет")
	res, err := door.CheckRelation(ctx, service.CheckRelationRequest{
		Subject: "service_account:" + id, Relation: "system_admin", Object: "cluster:cluster_root",
	})
	require.NoError(t, err)
	require.True(t, res.Allowed, "фикстура: дверь не признаёт посеянного администратора кластера")
	return operations.WithPrincipal(ctx, operations.Principal{Type: "service_account", ID: id})
}

// ntfUserCtx — контекст пользователя без роли администратора (NTF1-F10).
func ntfUserCtx(t *testing.T, db *ntfDB, door *service.AuthorizeService, id string) context.Context {
	t.Helper()
	ctx := context.Background()
	res, err := door.CheckRelation(ctx, service.CheckRelationRequest{
		Subject: "user:" + id, Relation: "system_admin", Object: "cluster:cluster_root",
	})
	require.NoError(t, err)
	require.False(t, res.Allowed, "фикстура: пользователь близнеца F10 оказался администратором")
	return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: id})
}

// ntfOperationsCount — число строк операций (`Operation` не создана при
// отказе — NTF1-F13, F15–F17).
func ntfOperationsCount(t *testing.T, db *ntfDB) int {
	t.Helper()
	var n int
	require.NoError(t, db.fixture.QueryRow(context.Background(), `SELECT count(*) FROM kaname.operations`).Scan(&n))
	return n
}

// ntfAwaitOperation — исход операции, дочитанный из базы до `done`
// (ожидание условия, а не паузы).
func ntfAwaitOperation(t *testing.T, db *ntfDB, id string) *operations.Operation {
	t.Helper()
	repo := operations.NewRepo(db.fixture, "kaname")
	var got *operations.Operation
	require.Eventually(t, func() bool {
		op, err := repo.Get(context.Background(), id)
		if err != nil {
			return false
		}
		got = op
		return op.Done
	}, 10*time.Second, 50*time.Millisecond, "операция %s не дошла до done", id)
	return got
}

// ntfRefusal — разобранный отказ: код, текст, причина, домен, метаданные,
// поле нарушения.
type ntfRefusal struct {
	code     string
	message  string
	reason   string
	domain   string
	metadata map[string]string
	fields   []string
}

func ntfRefusalOf(err error) ntfRefusal {
	st, _ := status.FromError(err)
	r := ntfRefusal{code: st.Code().String(), message: st.Message()}
	for _, d := range st.Details() {
		switch v := d.(type) {
		case *errdetails.ErrorInfo:
			r.reason, r.domain, r.metadata = v.GetReason(), v.GetDomain(), v.GetMetadata()
		case *errdetails.BadRequest:
			for _, fv := range v.GetFieldViolations() {
				r.fields = append(r.fields, fv.GetField())
			}
		}
	}
	return r
}

// errNTFNoRow — строки нет (фикстура отличает «нет» от «сбой чтения»).
var errNTFNoRow = errors.New("строки нет")

// ntfRow — строка таблицы записи выдачи целиком, текстом (побайтовое
// сравнение «запись та же»). Нет строки — errNTFNoRow.
func ntfRow(t *testing.T, db *ntfDB, query string, args ...any) (string, error) {
	t.Helper()
	var s *string
	err := db.fixture.QueryRow(context.Background(), query, args...).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && s == nil) {
		return "", errNTFNoRow
	}
	if err != nil {
		return "", err
	}
	return *s, nil
}
