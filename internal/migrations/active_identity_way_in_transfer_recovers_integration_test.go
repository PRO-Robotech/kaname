// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// active_identity_way_in_transfer_recovers_integration_test.go — строка,
// засеянная В НЫНЕШНЕМ ВИДЕ (до миграции пары), после переноса получает вход
// продуктовым путём (задача PRO-Robotech/kaname#608, предикат п. 2; приёмки
// `active-identity-has-a-way-in.md` C6, AWI-11, AWI-12 и `recovery-of-access.md`
// Ф5-29, Ф5-30, Ф5-31).
//
// # Чем отличается от соседей
//
// AWI-11 (`active_identity_has_a_way_in_integration_test.go`) судит перенос и
// останавливается на отметке. Ф5-29/30 на полосе входа
// (`loginlanehttp/recovery_without_a_way_in_integration_test.go`) судят выход и
// начинают с формы «после переноса», поставленной ПРЯМОЙ ЗАПИСЬЮ. Ни одна проба
// не проводит одну и ту же строку через оба шага, поэтому расхождение формы,
// которую оставляет перенос, с формой, которую ждёт выход, не увидела бы ни
// одна. Здесь цепочка одна:
//
//  1. база доведена до миграции, ПРЕДШЕСТВУЮЩЕЙ паре, и в ней посеяна строка
//     в том виде, в каком такие строки лежат сейчас: `ACTIVE`, без строки
//     пароля, адрес не подтверждён, отметки нет (колонки ещё не существует);
//  2. накат всей цепочки до головы — перенос C6 и всё, что после него;
//  3. продуктовый путь: запрос кода восстановления и предъявление кода с новым
//     паролем — те же use-case'ы и тот же адаптер базы, что у полосы входа.
//
// Исход — личность входит: заведена первая строка пароля, адрес подтверждён,
// отметки нет, статус прежний, выдана сессия. Статус переносом не менялся.
//
// Близнец — соседняя строка в том же нынешнем виде, но СО строкой пароля
// (единственный отличающий факт): перенос её не отмечает, код на
// неподтверждённый адрес ей не выдаётся (Ф5-31), письма нет.
//
// Журнал выхода не несёт адреса (hard-no-pii-in-logs).
//
// # Чем краснеет
//
// Предмет — цепочка двух уже лежащих частей; красного «до кода» у неё нет.
// Способность упасть доказана инъекцией: перенос, не ставящий отметки
// (ключ отвергает накат) либо ставящий её только подтверждённым адресам,
// краснит шаг 2 или шаг 3.
package migrations_test

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// standFormSource — адрес источника обращений пробы.
const standFormSource = "198.51.100.208"

// standFormNewPassword — первый пароль, заводимый выходом.
const standFormNewPassword = "first-password-of-a-stand-form-row-608"

type wayInState struct {
	passwords int
	verified  bool
	open      bool
	status    string
}

func standFormState(t *testing.T, db *sql.DB, id string) wayInState {
	t.Helper()
	var s wayInState
	require.NoError(t, db.QueryRow(`
		SELECT (SELECT count(*) FROM kaname.user_login_methods WHERE user_id = u.id AND kind = 'password'),
		       u.email_verified_at IS NOT NULL, u.recovery_path_opened_at IS NOT NULL, u.invite_status
		  FROM kaname.users u WHERE u.id = $1`, id).Scan(&s.passwords, &s.verified, &s.open, &s.status))
	return s
}

func recoveryLetters(t *testing.T, db *sql.DB, id string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.invite_mail_outbox
		  WHERE resource_id = $1 AND event_type = 'mail.recovery.send'`, id).Scan(&n))
	return n
}

func TestIntegration_StandFormRowGetsInByTheProductPathAfterTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	_, previous := versionsOf(t, awiMigration)
	dsn := pgtest.NewEmptyDB(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", previous), "база до миграции пары")

	// (1) Посев в нынешнем виде: A — без пароля, B — близнец со строкой пароля.
	account := awiAccount(t, db, "sf608")
	seed := func(tag string, password bool) (id, email string) {
		tx, err := db.Begin()
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()
		id, err = awiInsertPerson(tx, account, tag, "ACTIVE")
		require.NoError(t, err, "посев %s", tag)
		if password {
			require.NoError(t, awiInsertPassword(tx, id))
		}
		require.NoError(t, tx.Commit(), "посев %s на ревизии до пары: ключа ещё нет", tag)
		require.NoError(t, db.QueryRow(`SELECT email FROM kaname.users WHERE id = $1`, id).Scan(&email))
		return id, email
	}
	idA, emailA := seed("sf608a", false)
	idB, emailB := seed("sf608b", true)

	// (2) Накат всей цепочки до головы.
	require.NoError(t, goose.Up(db, "."), "накат до головы: перенос C6 и всё, что после")
	require.Equal(t, wayInState{passwords: 0, verified: false, open: true, status: "ACTIVE"}, standFormState(t, db, idA),
		"после переноса A: путь открыт, статус и подтверждённость прежние")
	require.Equal(t, wayInState{passwords: 1, verified: false, open: false, status: "ACTIVE"}, standFormState(t, db, idB),
		"после переноса B (близнец со строкой пароля): отметки нет")

	// (3) Продуктовый путь — те же use-case'ы и адаптер, что у полосы входа.
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = "kaname,public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	sessions := kanamepg.NewHumanSessionRepo(pool)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	prev := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(prev) })

	nop := humansession.NopObserver{}
	request, err := humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: sessions, CodeTTL: 5 * time.Minute, Dispatcher: humansession.SyncDispatcher{}, Observer: nop,
		Sources: sessions, SourcePace: humansession.SourcePace{Limit: 10000, Window: time.Hour},
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 10000, Window: time.Hour},
		Now:       time.Now, Logger: logger,
	})
	require.NoError(t, err)
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4,
		}})
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, nop, logger)
	require.NoError(t, err)
	complete, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
		CutoffClock: momentclock.Func(time.Now),
		Store:       sessions, Hasher: hasher, Rule: rule,
		Limits: humansession.Limits{AddressAttempts: 50, AddressWindow: 10 * time.Minute, SourceAttempts: 500, SourceWindow: 10 * time.Minute},
		TTL:    24 * time.Hour, Observer: nop, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)

	// Близнец Ф5-31: строка с паролем и неподтверждённым адресом кода не получает.
	require.NoError(t, request.Execute(ctx, humansession.RequestRecoveryInput{Email: emailB, Source: standFormSource}))
	require.Zero(t, recoveryLetters(t, db, idB), "Ф5-31: письма для близнеца со строкой пароля нет")

	// Ф5-29: код выдаётся на неподтверждённый адрес перенесённой строки.
	require.NoError(t, request.Execute(ctx, humansession.RequestRecoveryInput{Email: emailA, Source: standFormSource}))
	require.Equal(t, 1, recoveryLetters(t, db, idA), "Ф5-29: письмо восстановления для перенесённой строки в очереди")
	var code string
	require.NoError(t, db.QueryRow(`SELECT payload->>'code' FROM kaname.invite_mail_outbox
		  WHERE resource_id = $1 AND event_type = 'mail.recovery.send'`, idA).Scan(&code))
	require.NotEmpty(t, code, "письмо несёт код")

	// Ф5-30: предъявление кода заводит первый пароль — личность входит.
	out, err := complete.Execute(ctx, humansession.CompleteRecoveryInput{
		Email: emailA, Code: code, NewPassword: standFormNewPassword, Source: standFormSource,
	})
	require.NoError(t, err, "Ф5-30: перенесённая строка входит продуктовым путём")
	require.Equal(t, domain.UserID(idA), out.View.User.ID, "сессия выдана той же личности")
	require.True(t, out.View.EmailVerified, "Ф5-30: адрес подтверждён тем же исходом")
	require.Equal(t, wayInState{passwords: 1, verified: true, open: false, status: "ACTIVE"}, standFormState(t, db, idA),
		"Ф5-30: первый пароль заведён, адрес подтверждён, отметки нет, статус прежний")
	var liveSessions int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1 AND ended_at IS NULL`, idA).Scan(&liveSessions))
	require.Equal(t, 1, liveSessions, "Ф5-30: сессия записана")

	require.NotContains(t, logBuf.String(), emailA, "журнал выхода не несёт адреса")
	require.NotContains(t, logBuf.String(), emailB, "журнал выхода не несёт адреса близнеца")
}
