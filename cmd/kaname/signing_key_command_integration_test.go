// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// signing_key_command_integration_test.go — жизненный цикл ключа подписи,
// достижимый ОПЕРАТОРОМ (#314): проба идёт СКВОЗЬ поверхность.
//
// # Что значит «сквозь поверхность» здесь
//
// Объявление утечки подаётся командой процесса (`kaname signing-key …`), тем же
// входом, которым его подаёт оператор, а исход читается у ОБСЛУЖИВАЕМОГО
// набора — у публикатора, собранного так же, как его собирает `serve`, и у
// подписанта, выдающего токены. Глагол ключницы напрямую здесь не зовётся:
// проба, зовущая его, судила бы глагол, а не наличие у него пути с поверхности.
//
// Публикатор и подписант — ДРУГОЙ процесс по отношению к команде: у них свой
// пул и своя ключница. Это и есть условие пробы — команда, отработавшая у себя,
// обязана сменить то, что видит служба, а не только собственную память.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// signingCommandCfg — посадка с поднятой своей чеканкой над отдельной базой.
func signingCommandCfg(t *testing.T) config.Config {
	t.Helper()
	cfg := postureCfg(config.ModeDev, "disable")
	cfg.Repository.Postgres.URL = pgtest.WithSearchPath(pgtest.NewDB(t), "kaname,public")
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.AuthN.TokenSigning = config.TokenSigningConfig{
		Enabled:           true,
		Issuer:            "https://kaname.kacho.local",
		Algorithm:         "ES256",
		AllowedAlgorithms: "ES256",
		KeySetPath:        "/.well-known/kaname/jwks.json",
		KeyLifetime:       90 * 24 * time.Hour,
	}
	return cfg
}

// servingSide — то, что видит служба: публикатор набора и подписант,
// собранные тем же построением, что у `serve`.
type servingSide struct {
	keySet http.Handler
	signer *tokensigner.Signer
	ks     *signingkeys.Keystore
}

func startServingSide(t *testing.T, cfg config.Config) servingSide {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, cfg.DSN())
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	ks, signer, err := buildTokenSigning(ctx, pool, cfg, quietLogger())
	require.NoError(t, err)
	require.NotNil(t, ks)
	return servingSide{
		keySet: jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: ks}),
		signer: signer,
		ks:     ks,
	}
}

// servedKIDs — идентификаторы ключей в ОТВЕТЕ публикатора, а не в базе:
// строка в базе не означает, что потребитель ключ увидит.
func (s servingSide) servedKIDs(t *testing.T) map[domain.KeyID]bool {
	t.Helper()
	rec := httptest.NewRecorder()
	s.keySet.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/kaname/jwks.json", nil))
	require.Equal(t, http.StatusOK, rec.Code, "публикатор обязан отвечать: %s", rec.Body.String())
	var body struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	out := map[domain.KeyID]bool{}
	for _, k := range body.Keys {
		out[domain.KeyID(k.KID)] = true
	}
	return out
}

// servedKIDsOrEmpty — то же, что servedKIDs, для состояния, в котором
// законно ключей нет вовсе (утёкший ключ снят, замены нет). Публикатор отвечает
// тогда не пустым набором, а НАЗВАННЫМ отказом; любой иной ответ — поломка.
func (s servingSide) servedKIDsOrEmpty(t *testing.T) map[domain.KeyID]bool {
	t.Helper()
	rec := httptest.NewRecorder()
	s.keySet.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/kaname/jwks.json", nil))
	if rec.Code == http.StatusOK {
		return s.servedKIDs(t)
	}
	var refusal struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &refusal), "ответ публикатора: %s", rec.Body.String())
	require.Equal(t, "jwks_keyset_empty", refusal.Error, "публикатор обязан либо отдать набор, либо назвать его пустым: %d %s",
		rec.Code, rec.Body.String())
	return map[domain.KeyID]bool{}
}

// signedKID — ключ, которым служба подписывает СЕЙЧАС: читается у выданного
// токена, а не у строки ключницы.
func (s servingSide) signedKID(t *testing.T) domain.KeyID {
	t.Helper()
	tok, err := s.signer.Sign(context.Background(), tokensigner.Request{
		Subject: "sva-signing-command", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 5 * time.Minute,
	})
	require.NoError(t, err, "служба обязана подписывать")
	return tok.KID
}

func runCommand(t *testing.T, cfg config.Config, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := runSigningKeyCommand(context.Background(), cfg, args, &out, quietLogger())
	return code, out.String()
}

// TestSigningKeyCommand_CompromiseTakesTheKeyOutOfTheServedSet — объявили
// утечку с поверхности оператора → ключ покинул обслуживаемый набор, служба
// подписывает новым.
func TestSigningKeyCommand_CompromiseTakesTheKeyOutOfTheServedSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	leaked := svc.signedKID(t)
	require.True(t, svc.servedKIDs(t)[leaked], "до команды ключ обязан быть в обслуживаемом наборе")

	code, out := runCommand(t, cfg, "compromise", "-kid="+string(leaked), "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitDone, code, "вывод команды: %s", out)

	served := svc.servedKIDs(t)
	require.False(t, served[leaked], "утёкший ключ обязан покинуть обслуживаемый набор")
	next := svc.signedKID(t)
	require.NotEqual(t, leaked, next, "служба обязана подписывать новым ключом")
	require.True(t, served[next], "новый подписывающий обязан быть в наборе раньше первого токена")
	require.Contains(t, out, string(leaked))
	require.Contains(t, out, string(next), "оператор обязан узнать, к какому ключу перешла подпись")
}

// TestSigningKeyCommand_RetireKeepsTheKeyInTheServedSet — законный близнец:
// вывод из обращения тем же путём меняет подписывающего, но ключ остаётся в
// наборе на отсрочку — подписанные им токены доживают свой срок.
func TestSigningKeyCommand_RetireKeepsTheKeyInTheServedSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	old := svc.signedKID(t)

	code, out := runCommand(t, cfg, "retire", "-kid="+string(old), "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitDone, code, "вывод команды: %s", out)

	served := svc.servedKIDs(t)
	require.True(t, served[old], "выведенный ключ остаётся в наборе всю отсрочку")
	next := svc.signedKID(t)
	require.NotEqual(t, old, next)
	require.True(t, served[next])
}

// TestSigningKeyCommand_RefusalsLeaveTheServedSetAlone — отказы команды не
// трогают набор и различимы кодом: «ключа нет» — отказ по существу, неверный
// вызов — «не исполнялось».
func TestSigningKeyCommand_RefusalsLeaveTheServedSetAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	signer := svc.signedKID(t)
	before := svc.servedKIDs(t)

	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"ключа нет", []string{"compromise", "-kid=kaname-no-such-key", "-decided-by=oncall"}, signingKeyExitRefused},
		{"решивший не назван", []string{"compromise", "-kid=" + string(signer)}, signingKeyExitNotRun},
		{"ключ не назван", []string{"retire", "-decided-by=oncall"}, signingKeyExitNotRun},
		{"неизвестное действие", []string{"destroy", "-kid=" + string(signer), "-decided-by=oncall"}, signingKeyExitNotRun},
		{"действие не названо", nil, signingKeyExitNotRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := runCommand(t, cfg, tc.args...)
			require.Equal(t, tc.code, code, "вывод команды: %s", out)
			require.Equal(t, before, svc.servedKIDs(t), "отказ не трогает набор")
			require.Equal(t, signer, svc.signedKID(t), "отказ не трогает подписывающего")
		})
	}
}

// TestSigningKeyMaintenancePass_RotatesBeforeTheDeclaredTerm — объявленный
// срок ключа управляет подписью в работающей службе: проход обслуживания,
// поднятый так же, как в `serve`, в запасе ротации передаёт подпись новому
// ключу ДО срока и считается как проход сметателя.
func TestSigningKeyMaintenancePass_RotatesBeforeTheDeclaredTerm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	cfg := signingCommandCfg(t)
	pool, err := coredb.NewPool(ctx, cfg.DSN())
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	ks, _, err := buildTokenSigningAt(ctx, pool, cfg, func() time.Time { return now }, quietLogger())
	require.NoError(t, err)
	repoActive := func() domain.SigningKeyRecord {
		var rec domain.SigningKeyRecord
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT kid, not_after FROM kaname.token_signing_keys WHERE state = 'ACTIVE'`).Scan(&rec.KID, &rec.NotAfter))
		return rec
	}
	first := repoActive()
	due := first.NotAfter.Add(-signingKeyRotationLead)

	// Близнец: до запаса ротации проход подпись не трогает, но проходом считается.
	now = due.Add(-time.Minute)
	signingKeyMaintenancePass(ctx, ks, quietLogger())
	require.Equal(t, first.KID, repoActive().KID)
	require.Equal(t, uint64(1), ks.Stats().Sweeps)

	// В запасе ротации — подпись переходит раньше срока.
	now = due
	signingKeyMaintenancePass(ctx, ks, quietLogger())
	next := repoActive()
	require.NotEqual(t, first.KID, next.KID, "в запасе ротации подпись обязана перейти")
	require.True(t, now.Before(first.NotAfter), "переход обязан случиться ДО объявленного срока")
	require.Equal(t, uint64(2), ks.Stats().Sweeps)
}

// TestStartSigningKeyMaintenance_FirstPassRunsAtStart — первый проход идёт при
// старте, а не через интервал: ноль проходов у живого процесса иначе читался
// бы как норма целых пятнадцать минут.
func TestStartSigningKeyMaintenance_FirstPassRunsAtStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)

	startSigningKeyMaintenance(ctx, svc.ks, quietLogger())
	require.Equal(t, uint64(1), svc.ks.Stats().Sweeps, "первый проход обязан завершиться до возврата старта")
}

// signs — подписывает ли служба СЕЙЧАС: читается попыткой выдать токен, а не
// строкой ключницы.
func (s servingSide) signs(t *testing.T) bool {
	t.Helper()
	_, err := s.signer.Sign(context.Background(), tokensigner.Request{
		Subject: "sva-signing-command", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 5 * time.Minute,
	})
	return err == nil
}

// storePool — пул к базе службы для того, что в пробе делает НЕ команда:
// держит замок, отказывает в записи. Строится тем же построением, что у
// команды, поэтому и его настройки сессии — те же.
func storePool(t *testing.T, cfg config.Config) *pgxpool.Pool {
	t.Helper()
	pool, err := coredb.NewPool(context.Background(), cfg.DSN())
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// refuseKeyInserts — хранилище отказывает в записи НОВОГО ключа, а переходы
// существующих принимает: так получается частичный исход утечки («снять
// удалось, завести замену — нет») настоящим отказом базы, а не дублёром.
func refuseKeyInserts(t *testing.T, pool *pgxpool.Pool) (allow func()) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `CREATE FUNCTION kaname.probe_refuse_signing_key_insert() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'probe: signing key insert refused'; END $$`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CREATE TRIGGER probe_refuse_signing_key_insert BEFORE INSERT
		ON kaname.token_signing_keys FOR EACH ROW EXECUTE FUNCTION kaname.probe_refuse_signing_key_insert()`)
	require.NoError(t, err)
	return func() {
		_, err := pool.Exec(ctx, `DROP TRIGGER probe_refuse_signing_key_insert ON kaname.token_signing_keys`)
		require.NoError(t, err)
	}
}

// TestSigningKeyCommand_RepeatAfterPartialNamesTheReplacement — после
// частичного исхода утечки (ключ снят, замену завести не удалось) повтор той же
// команды довершает замену И НАЗЫВАЕТ её: подпись перешла внутри этого вызова,
// и оператор обязан узнать, к какому ключу.
func TestSigningKeyCommand_RepeatAfterPartialNamesTheReplacement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	leaked := svc.signedKID(t)
	allow := refuseKeyInserts(t, storePool(t, cfg))

	code, out := runCommand(t, cfg, "compromise", "-kid="+string(leaked), "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitRefused, code, "вывод команды: %s", out)
	require.Contains(t, out, "outcome=partial")
	require.False(t, svc.servedKIDsOrEmpty(t)[leaked], "снятие состоялось")
	require.False(t, svc.signs(t), "частичный исход: служба не подписывает")

	allow()
	code, out = runCommand(t, cfg, "compromise", "-kid="+string(leaked), "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitDone, code, "вывод команды: %s", out)
	require.Contains(t, out, "outcome=already-done")
	next := svc.signedKID(t)
	require.Contains(t, out, "replacement="+string(next), "повтор обязан назвать ключ, к которому перешла подпись")
	served := svc.servedKIDs(t)
	require.True(t, served[next])
	require.False(t, served[leaked])
}

// TestSigningKeyCommand_RefusalAfterPartialLeavesTheSignerAlone — отказ команды
// не трогает подпись и тогда, когда подписывающего нет: команда, отказавшая по
// ключу, не заводит подписывающего мимо глагола. Близнец — повтор утечки в
// пробе выше: тот же вызов с существующим ключом замену заводит.
func TestSigningKeyCommand_RefusalAfterPartialLeavesTheSignerAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	leaked := svc.signedKID(t)
	allow := refuseKeyInserts(t, storePool(t, cfg))
	code, out := runCommand(t, cfg, "compromise", "-kid="+string(leaked), "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitRefused, code, "вывод команды: %s", out)
	allow()
	before := svc.servedKIDsOrEmpty(t)

	code, out = runCommand(t, cfg, "compromise", "-kid=kaname-no-such-key", "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitRefused, code, "вывод команды: %s", out)
	require.Equal(t, before, svc.servedKIDsOrEmpty(t), "отказ не трогает набор")
	require.False(t, svc.signs(t), "отказ не заводит подписывающего")
}

// awaitLockWaiter — ждёт, пока обслуживающий процесс базы не встанет в
// ожидание замка. Не дождался — сцена конкуренции не построена: это отказ
// фикстуры, а не вердикт о предмете.
func awaitLockWaiter(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ни один процесс базы не ждёт замка за 10 с — сцена конкуренции не построена")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSigningKeyCommand_RepeatUnderAConcurrentSignerNamesItAndDoesNotClaimAStoppedService —
// после частичного исхода утечки повтор команды заводит замену, а в это время
// подписывающим становится ключ соседа (реплика стартует и обеспечивает
// подписывающего, второй оператор гонит тот же повтор). Повышение замены
// отказывает нарушением уникальности подписывающего, но служба ПОДПИСЫВАЕТ — и
// команда обязана это сказать: исход без отказа, подписывающий назван, «служба
// не подписывает» не печатается. Законный близнец —
// TestSigningKeyCommand_RepeatAfterPartialNamesTheReplacement: тот же повтор без
// соседа, и там подпись переходит к замене этого вызова.
func TestSigningKeyCommand_RepeatUnderAConcurrentSignerNamesItAndDoesNotClaimAStoppedService(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	const bound = 15 * time.Second
	ctx := context.Background()
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	leaked := svc.signedKID(t)
	pool := storePool(t, cfg)
	allow := refuseKeyInserts(t, pool)
	code, out := runCommand(t, cfg, "compromise", "-kid="+string(leaked), "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitRefused, code, "предпосылка — частичный исход; вывод команды: %s", out)
	require.False(t, svc.signs(t), "предпосылка — служба не подписывает")
	allow()

	// Сосед: его ключ опубликован и повышается в подпись транзакцией, которая
	// ещё не зафиксирована, — повтор команды его подписывающим не видит.
	neighbour, err := svc.ks.Generate(ctx)
	require.NoError(t, err)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	_, err = tx.Exec(ctx, `UPDATE kaname.token_signing_keys SET state = 'ACTIVE', activated_at = now()
		WHERE kid = $1 AND state = 'PUBLISHED'`, string(neighbour.KID))
	require.NoError(t, err)

	type result struct {
		code int
		out  string
	}
	done := make(chan result, 1)
	go func() {
		code, out := runCommand(t, cfg, "compromise", "-kid="+string(leaked), "-decided-by=oncall@example.invalid")
		done <- result{code, out}
	}()
	// Повышение замены ждёт замка соседа — и сосед фиксируется первым.
	awaitLockWaiter(t, pool)
	require.NoError(t, tx.Commit(ctx))

	var repeat result
	select {
	case repeat = <-done:
	case <-time.After(bound):
		t.Fatalf("повтор команды не вернулся за %s", bound)
	}
	require.Equal(t, signingKeyExitDone, repeat.code, "служба подписывает — отказа по существу нет; вывод команды: %s", repeat.out)
	require.Contains(t, repeat.out, "outcome=already-done")
	require.Contains(t, repeat.out, "signer="+string(neighbour.KID), "оператор обязан узнать, каким ключом служба подписывает")
	require.NotContains(t, repeat.out, "служба не подписывает", "служба подписывает ключом соседа")
	require.NotContains(t, repeat.out, "replacement=", "замена этим вызовом не легла")
	require.Equal(t, neighbour.KID, svc.signedKID(t), "служба подписывает ключом соседа")
	served := svc.servedKIDs(t)
	require.True(t, served[neighbour.KID])
	require.False(t, served[leaked], "утёкший ключ в набор не вернулся")
}

// TestSigningKeyCommand_OwnLimitEndsAHungStoreWithNoVerdict — хранилище
// зависло (строку ключа держит чужая транзакция): команда кончается СВОИМ
// пределом, отвечает «не исполнялось» и называет предел, а набор и
// подписывающий остаются прежними. Близнец в той же пробе — тот же вызов с тем
// же пределом, когда строку никто не держит: он исполняется.
func TestSigningKeyCommand_OwnLimitEndsAHungStoreWithNoVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	const (
		limit = 2 * time.Second
		// bound — сколько проба ждёт возврата. Меньше statement_timeout пула:
		// иначе возврат по чужому пределу был бы неотличим от возврата по своему.
		bound = 15 * time.Second
	)
	ctx := context.Background()
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	leaked := svc.signedKID(t)
	pool := storePool(t, cfg)

	// Предпосылка пробы: предел запроса у пула либо не задан, либо длиннее
	// ожидания пробы. Иначе зависание кончал бы он, и проба не различала бы
	// команду со своим пределом и команду без него.
	var statementTimeoutMS int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout'`).Scan(&statementTimeoutMS))
	require.Truef(t, statementTimeoutMS == 0 || time.Duration(statementTimeoutMS)*time.Millisecond > bound,
		"предпосылка пробы не выполняется: statement_timeout пула %dms не длиннее ожидания пробы %s", statementTimeoutMS, bound)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT kid FROM kaname.token_signing_keys WHERE kid = $1 FOR UPDATE`, string(leaked))
	require.NoError(t, err)

	type result struct {
		code int
		out  string
	}
	run := func() <-chan result {
		done := make(chan result, 1)
		go func() {
			var out bytes.Buffer
			code := runSigningKeyCommandWithin(context.Background(), limit, cfg,
				[]string{"compromise", "-kid=" + string(leaked), "-decided-by=oncall@example.invalid"}, &out, quietLogger())
			done <- result{code, out.String()}
		}()
		return done
	}
	var hung result
	select {
	case hung = <-run():
	case <-time.After(bound):
		_ = tx.Rollback(ctx)
		t.Fatalf("команда не вернулась за %s при своём пределе %s", bound, limit)
	}
	require.NoError(t, tx.Rollback(ctx))
	require.Equal(t, signingKeyExitNotRun, hung.code, "вывод команды: %s", hung.out)
	require.Contains(t, hung.out, "outcome=not-run")
	require.Contains(t, hung.out, "предел команды "+limit.String()+" истёк", "оператор обязан узнать, что кончился предел самой команды")
	require.True(t, svc.servedKIDs(t)[leaked], "истёкший предел не трогает набор")
	require.Equal(t, leaked, svc.signedKID(t), "истёкший предел не трогает подписывающего")

	var free result
	select {
	case free = <-run():
	case <-time.After(bound):
		t.Fatalf("команда без зависшей строки не вернулась за %s", bound)
	}
	require.Equal(t, signingKeyExitDone, free.code, "вывод команды: %s", free.out)
	require.False(t, svc.servedKIDs(t)[leaked])
}

// TestSigningKeyCommand_ForeignWrappingKeyIsNotRunAndTouchesNothing — команда
// с ключом обёртки, который не открывает записанное, не исполняется: замена,
// порождённая им, была бы нечитаема каждой репликой. Отказ называет ручку и
// говорит о команде, а не о старте службы.
func TestSigningKeyCommand_ForeignWrappingKeyIsNotRunAndTouchesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	cfg := signingCommandCfg(t)
	svc := startServingSide(t, cfg)
	signer := svc.signedKID(t)
	before := svc.servedKIDs(t)

	foreign := cfg
	foreign.AuthN.JWKSEncryptionKeyHex = strings.Repeat("cd", 32)
	code, out := runCommand(t, foreign, "compromise", "-kid="+string(signer), "-decided-by=oncall@example.invalid")
	require.Equal(t, signingKeyExitNotRun, code, "вывод команды: %s", out)
	require.Contains(t, out, "authn.jwks-encryption-key-hex")
	require.Contains(t, out, "команда не исполнялась")
	require.NotContains(t, out, "стартовать", "отказ команды не выдаёт себя за отказ старта службы")
	require.Equal(t, before, svc.servedKIDs(t), "отказ не трогает набор")
	require.Equal(t, signer, svc.signedKID(t), "отказ не трогает подписывающего")
}
