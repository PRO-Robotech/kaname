// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// store_double_parity_integration_test.go — ДУБЛЁР ХРАНИЛИЩА ≡ АДАПТЕР БАЗЫ на
// осях, которыми различаются полосы отказа (задача PRO-Robotech/kaname#305).
//
// # Зачем
//
// Замок равенства работы полос отказа завершения восстановления
// (`recovery_refusal_work_test.go`) судит работу базы по дублёру: рядом
// обращений к портам и числом операторов базы, которое дублёр объявляет у
// каждого обращения (`fakeStore.trips`). Оба утверждения сделаны о дублёре, а
// предмет замка — база; о ней они верны ровно тогда, когда дублёр на каждом
// входе, которым полосы различаются, отвечает тем же исходом и исполняет то же
// число операторов, что настоящий адаптер. Дублёр, принимающий вход, который
// адаптер отвергает без обхода базы, делает замок слепым: полосы равны в
// дублёре и неравны в базе.
//
// Эта проба сверяет это ОПЫТОМ, а не чтением: один и тот же набор входов
// исполняется над настоящим адаптером (`internal/repo/kaname/pg`, Postgres в
// контейнере) и над дублёром, и у каждого входа сравниваются
//
//   - исход — класс отказа либо ответ;
//   - число операторов базы — у адаптера счётчиком трассировщика соединения
//     (каждое обращение соединения к базе: чтение, запись, BEGIN, COMMIT,
//     ROLLBACK), у дублёра — его объявлением.
//
// # Оси входа
//
// Всё, чем полоса «адреса нет» отличается от полосы «адрес есть», — это
// личность и то, что из неё выводится:
//
//   - личность: у «адреса нет» каждое выводимое из личности значение нулевое —
//     идентификатор, адрес, аккаунт, её сессия, её носитель, её код;
//   - заведённый второй фактор: есть / нет;
//   - состояние личности: действующая / заблокирована;
//   - адрес полосы: найден / не найден.
//
// Ключ счёта, адрес и свёртка кода у полосы бывают двух происхождений —
// набранные (у всех полос непусты) и выведенные из личности (у «адреса нет»
// пусты); у таких входов сверяются обе формы. Входы, одинаковые у всех полос
// (вид способа, момент, форма свёртки, вид события), берутся постоянными
// допустимыми значениями; отдельной группой сверяются остальные отказы
// аргументом адаптера (пустой вид события, строка не той формы, фиксация
// закрытой транзакции) — оси полос они не несут, но дублёр, принимающий их,
// был бы мягче адаптера в той же форме.
//
// Граница сверки: непустая, но несуществующая личность полосами не подаётся
// (у полосы личность либо найдена, либо нулевая), и отказ базы по внешнему
// ключу на ней здесь не сверяется.
//
// # Предпосылки, без которых «расхождений 0» ничего не значит
//
//   - перечень методов выводится из самих портов отражением: метод, добавленный
//     в `humansession.Store` либо `humansession.Writer` без случая здесь, —
//     находка, случай без метода — тоже;
//   - счётчик адаптера обязан видеть обе стороны оси работы: среди входов есть
//     и исполненные без единого оператора, и исполненные операторами. Счётчик,
//     не видящий ничего, дал бы «0 = 0» у каждого отказа аргументом.
//
// Run: `go test ./internal/apps/kaname/api/humansession/ -run StoreDouble`.
// Пропускается с -short.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// parityMoment — момент записей сверки, кратный микросекунде: такова точность
// отметок базы, и сверка по моменту (`ActivateTOTP`) у адаптера иначе не нашла
// бы строку, которую нашёл бы дублёр.
var parityMoment = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

// parityNow — момент обращений сверки: после записей, до их сроков.
var parityNow = parityMoment.Add(time.Minute)

// parityPerson — личность одной полосы и всё, что из неё выводится. У «адреса
// нет» личности нет, и всё выводимое — нулевые значения.
type parityPerson struct {
	label    string
	user     domain.User
	lane     string // адрес, набранный полосой: непуст у всех
	factor   bool
	verified bool
	session  domain.HumanSessionID
	bearer   domain.BearerDigest
	codeID   domain.RecoveryCodeID
	code     domain.RecoveryCodeValue
	tag      string
}

func (p parityPerson) someone() bool { return p.user.ID != "" }

// hexOf — свёртка в форме, которую принимает база (64 шестнадцатеричных знака).
func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func parityPeople(t *testing.T) []parityPerson {
	t.Helper()
	account := domain.AccountID(fmt.Sprintf("acc%017s", "parity"))
	person := func(tag string, status domain.InviteStatus, factor, verified bool) parityPerson {
		code, err := domain.NewRecoveryCodeValue()
		require.NoError(t, err)
		id := domain.UserID(fmt.Sprintf("usr%017s", "prt"+tag))
		return parityPerson{
			label: tag,
			user: domain.User{ID: id, AccountID: account, ExternalID: domain.ExternalSubject("ext-prt-" + tag),
				Email: domain.Email("prt-" + tag + "@example.invalid"), DisplayName: domain.DisplayName("Person " + tag),
				InviteStatus: status},
			lane: "prt-" + tag + "@example.invalid", factor: factor, verified: verified,
			session: domain.HumanSessionID("hss-parity-" + tag), bearer: domain.BearerDigest(hexOf("bearer-" + tag)),
			codeID: domain.RecoveryCodeID("rcv-parity-" + tag), code: code, tag: tag,
		}
	}
	return []parityPerson{
		{label: "адреса нет", lane: "prt-nobody@example.invalid", tag: "nobody"},
		person("plain", domain.InviteStatusActive, false, true),
		person("factor", domain.InviteStatusActive, true, false),
		person("blocked", domain.InviteStatusBlocked, false, true),
	}
}

// parityVerifier — материал способа из постоянного литерала сверки.
func parityVerifier(material string) domain.LoginVerifier {
	v, err := domain.NewLoginVerifier(material)
	if err != nil {
		panic(fmt.Sprintf("parity: literal login material %q rejected: %v", material, err))
	}
	return v
}

// seedParityRows — строки полос ЧЕРЕЗ ПОРТ: сессия, память первой
// аутентификации, код восстановления, у личности со вторым фактором — фактор и
// набор. Обе стороны получают их одними и теми же обращениями. Подтверждение
// фактора — отдельной транзакцией: транзакция дублёра своих записей до фиксации
// не видит, и сверка на этом не держится.
func seedParityRows(t *testing.T, ctx context.Context, st humansession.Store, people []parityPerson) {
	t.Helper()
	inTx := func(step string, f func(w humansession.Writer)) {
		w, err := st.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		f(w)
		require.NoError(t, w.Commit(ctx), "посев: %s", step)
	}
	inTx("строки личностей", func(w humansession.Writer) {
		for _, p := range people {
			if !p.someone() {
				continue
			}
			require.NoError(t, w.InsertSession(ctx, domain.HumanSession{
				ID: p.session, UserID: p.user.ID, AuthenticatedAt: parityMoment, LastPresentedAt: parityMoment,
				ExpiresAt: parityMoment.Add(24 * time.Hour), AssuranceLevel: "1", PresentedMethods: []string{"password"},
			}, p.bearer), "посев: сессия %s", p.label)
			require.NoError(t, w.RememberFirstAuthentication(ctx, p.user.ID, parityMoment), "посев: первая аутентификация %s", p.label)
			require.NoError(t, w.InsertRecoveryCode(ctx, domain.RecoveryCode{
				ID: p.codeID, UserID: p.user.ID, Digest: p.code.Digest(), IssuedAt: parityMoment, ExpiresAt: parityMoment.Add(5 * time.Minute),
			}), "посев: код %s", p.label)
			if p.factor {
				accepted, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: p.user.ID, Kind: domain.LoginMethodTOTP,
					Verifier: parityVerifier("material-totp-parity"), State: domain.LoginMethodStatePending, CreatedAt: parityMoment})
				require.NoError(t, err)
				require.True(t, accepted, "посев: заведение фактора %s", p.label)
			}
		}
	})
	inTx("подтверждение фактора и набор", func(w humansession.Writer) {
		for _, p := range people {
			if !p.factor {
				continue
			}
			activated, err := w.ActivateTOTP(ctx, p.user.ID, parityMoment, 100, parityMoment.Add(time.Second))
			require.NoError(t, err)
			require.True(t, activated, "посев: подтверждение фактора %s", p.label)
			require.NoError(t, w.ReplaceLookupSet(ctx, domain.LoginMethod{UserID: p.user.ID, Kind: domain.LoginMethodLookupSecret,
				Verifier: parityVerifier(",e1,e2,"), State: domain.LoginMethodStateActive, CreatedAt: parityMoment}), "посев: набор %s", p.label)
		}
	})
}

// statementCounter — трассировщик соединения: каждое обращение соединения к
// базе (Query, QueryRow, Exec — в том числе BEGIN, COMMIT, ROLLBACK).
type statementCounter struct{ n atomic.Int64 }

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// adapterSide — настоящий адаптер над своей базой: люди, аккаунт и пароль —
// строками базы (портов их записи у хранилища сессии нет), прочее — портом.
func adapterSide(t *testing.T, ctx context.Context, people []parityPerson) paritySide {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	counter := &statementCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	var owner domain.UserID
	for _, p := range people {
		if !p.someone() {
			continue
		}
		if owner == "" {
			owner = p.user.ID
		}
		var verifiedAt *time.Time
		if p.verified {
			at := parityMoment
			verifiedAt = &at
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO users (id, external_id, email, display_name, account_id, invite_status, email_verified_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			string(p.user.ID), string(p.user.ExternalID), string(p.user.Email), string(p.user.DisplayName),
			string(p.user.AccountID), string(p.user.InviteStatus), verifiedAt)
		require.NoError(t, err, "посев: личность %s", p.label)
	}
	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		string(people[1].user.AccountID), "acc-parity", string(owner))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	methods := kanamepg.NewLoginMethodRepo(pool)
	for _, p := range people {
		if !p.someone() {
			continue
		}
		_, err := methods.Create(ctx, domain.LoginMethod{UserID: p.user.ID, Kind: domain.LoginMethodPassword,
			Verifier: parityVerifier("material-password-parity"), State: domain.LoginMethodStateActive})
		require.NoError(t, err, "посев: пароль %s", p.label)
	}
	store := kanamepg.NewHumanSessionRepo(pool)
	seedParityRows(t, ctx, store, people)
	return paritySide{name: "адаптер", store: store, count: counter.n.Load}
}

// doubleSide — дублёр с тем же посевом: люди, аккаунт и пароль — его таблицами,
// прочее — тем же портом.
func doubleSide(t *testing.T, ctx context.Context, people []parityPerson) paritySide {
	t.Helper()
	f := newFakeStore()
	for _, p := range people {
		if !p.someone() {
			continue
		}
		f.users[p.user.ID] = p.user
		f.verified[p.user.ID] = p.verified
		f.verifiers[p.user.ID] = parityVerifier("material-password-parity")
	}
	seedParityRows(t, ctx, f, people)
	return paritySide{name: "дублёр", store: f, count: f.tripCount}
}

type paritySide struct {
	name  string
	store humansession.Store
	count func() int64
}

// parityCase — один метод порта в одной форме входа.
type parityCase struct {
	method string // "Store.<метод>" либо "Writer.<метод>"
	form   string
	// store — обращение к хранилищу; later откладывает уборку за замер.
	store func(ctx context.Context, s humansession.Store, p parityPerson, later func(func())) string
	// writer — обращение к транзакции, открытой до замера; closeFirst —
	// закрыть её до замера: "commit" либо "rollback".
	writer     func(ctx context.Context, w humansession.Writer, p parityPerson) string
	closeFirst string
}

func (s paritySide) run(t *testing.T, ctx context.Context, c parityCase, p parityPerson) (string, int64) {
	t.Helper()
	if c.store != nil {
		var cleanup []func()
		before := s.count()
		out := c.store(ctx, s.store, p, func(f func()) { cleanup = append(cleanup, f) })
		n := s.count() - before
		for _, f := range cleanup {
			f()
		}
		return out, n
	}
	w, err := s.store.Writer(ctx)
	require.NoError(t, err, "%s: транзакция сверки не открылась", s.name)
	defer func() { _ = w.Rollback(ctx) }()
	switch c.closeFirst {
	case "commit":
		require.NoError(t, w.Commit(ctx))
	case "rollback":
		require.NoError(t, w.Rollback(ctx))
	}
	before := s.count()
	out := c.writer(ctx, w, p)
	return out, s.count() - before
}

// errClass — класс отказа словарём ошибок службы; отказ вне словаря — своим
// именем «без класса» (так его и увидит вызывающий).
func errClass(err error) string {
	for _, c := range []struct {
		name     string
		sentinel error
	}{
		{"invalid-argument", iamerr.ErrInvalidArg}, {"not-found", iamerr.ErrNotFound},
		{"failed-precondition", iamerr.ErrFailedPrecondition}, {"already-exists", iamerr.ErrAlreadyExists},
		{"internal", iamerr.ErrInternal}, {"unavailable", iamerr.ErrUnavailable},
	} {
		if errors.Is(err, c.sentinel) {
			return c.name
		}
	}
	return "без класса"
}

func said(err error, format string, args ...any) string {
	if err != nil {
		return "отказ " + errClass(err)
	}
	return fmt.Sprintf(format, args...)
}

// laneWrongDigest — свёртка кода, предъявленного полосой: у всех полос непуста.
var laneWrongDigest = domain.PresentedRecoveryCode("AAAAA-AAAAA").Digest()

func byAddress(p parityPerson) string  { return humansession.AddressKey(p.lane) }
func byIdentity(p parityPerson) string { return string(p.user.ID) }

func parityCases() []parityCase {
	keyForms := []struct {
		form string
		key  func(parityPerson) string
	}{{"ключ — набранный адрес", byAddress}, {"ключ — её личность", byIdentity}}
	var cs []parityCase
	st := func(method, form string, f func(ctx context.Context, s humansession.Store, p parityPerson) string) {
		cs = append(cs, parityCase{method: "Store." + method, form: form,
			store: func(ctx context.Context, s humansession.Store, p parityPerson, _ func(func())) string {
				return f(ctx, s, p)
			}})
	}
	wr := func(method, form string, f func(ctx context.Context, w humansession.Writer, p parityPerson) string) {
		cs = append(cs, parityCase{method: "Writer." + method, form: form, writer: f})
	}

	// --- Store ---
	st("Resolve", "носитель её сессии", func(ctx context.Context, s humansession.Store, p parityPerson) string {
		_, reason, err := s.Resolve(ctx, p.bearer, parityNow)
		return said(err, "причина %s", reason)
	})
	for _, k := range keyForms {
		st("CountFailures", k.form, func(ctx context.Context, s humansession.Store, p parityPerson) string {
			n, err := s.CountFailures(ctx, humansession.FailureByAddress, k.key(p), parityMoment)
			return said(err, "счёт %d", n)
		})
		st("OldestFailureSince", k.form, func(ctx context.Context, s humansession.Store, p parityPerson) string {
			_, ok, err := s.OldestFailureSince(ctx, humansession.FailureByAddress, k.key(p), parityMoment)
			return said(err, "найден %v", ok)
		})
	}
	st("FirstAuthentication", "её личность", func(ctx context.Context, s humansession.Store, p parityPerson) string {
		_, ok, err := s.FirstAuthentication(ctx, p.user.ID)
		return said(err, "найдена %v", ok)
	})
	for _, a := range []struct {
		form  string
		email func(parityPerson) domain.Email
	}{
		{"набранный адрес", func(p parityPerson) domain.Email { return domain.Email(byAddress(p)) }},
		{"её адрес", func(p parityPerson) domain.Email { return p.user.Email }},
	} {
		st("RecoveryTarget", a.form, func(ctx context.Context, s humansession.Store, p parityPerson) string {
			target, found, err := s.RecoveryTarget(ctx, a.email(p))
			return said(err, "найден %v подтверждён %v", found, target.EmailVerified)
		})
	}
	cs = append(cs, parityCase{method: "Store.Writer", form: "—",
		store: func(ctx context.Context, s humansession.Store, _ parityPerson, later func(func())) string {
			w, err := s.Writer(ctx)
			if err == nil {
				later(func() { _ = w.Rollback(ctx) })
			}
			return said(err, "открыта")
		}})
	// Транзакция, открытая держащей строку личности (kaname#340): у «адреса
	// нет» личность пуста, и оператор замка исполняется так же — строки нет.
	cs = append(cs, parityCase{method: "Store.SessionSetWriter", form: "её личность",
		store: func(ctx context.Context, s humansession.Store, p parityPerson, later func(func())) string {
			w, err := s.SessionSetWriter(ctx, p.user.ID)
			if err == nil {
				later(func() { _ = w.Rollback(ctx) })
			}
			return said(err, "открыта")
		}})

	// --- Writer: захват строки личности входа (kaname#385) ---
	// У «адреса нет» личность пуста: отказ аргументом без обхода базы; у
	// прочих — оператор захвата и оператор чтения отсечки.
	wr("LockPersonForLogin", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		_, found, err := w.LockPersonForLogin(ctx, p.user.ID)
		return said(err, "взята, отсечка %v", found)
	})

	// --- Writer: сессия и память первой аутентификации ---
	wr("InsertSession", "новая сессия её личности", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		err := w.InsertSession(ctx, domain.HumanSession{
			ID: domain.HumanSessionID("hss-parity-new-" + p.tag), UserID: p.user.ID, AuthenticatedAt: parityNow,
			LastPresentedAt: parityNow, ExpiresAt: parityNow.Add(time.Hour), AssuranceLevel: "1", PresentedMethods: []string{"password"},
		}, domain.BearerDigest(hexOf("new-bearer-"+p.tag)))
		return said(err, "записана")
	})
	wr("RememberFirstAuthentication", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.RememberFirstAuthentication(ctx, p.user.ID, parityNow), "запомнена")
	})
	wr("FirstAuthentication", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		_, ok, err := w.FirstAuthentication(ctx, p.user.ID)
		return said(err, "найдена %v", ok)
	})
	wr("EndSession", "её сессия", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		ended, err := w.EndSession(ctx, p.session, parityNow, domain.RevokeReasonLogout)
		return said(err, "снята %v", ended)
	})
	wr("EndOtherSessions", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		n, err := w.EndOtherSessions(ctx, p.user.ID, "", parityNow, domain.RevokeReasonPasswordChange)
		return said(err, "снято %d", n)
	})
	wr("RotateBearer", "её сессия", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.RotateBearer(ctx, p.session, domain.BearerDigest(hexOf("rotated-"+p.tag)), parityNow), "сменён")
	})
	wr("PresentInSession", "её сессия", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.PresentInSession(ctx, p.session, []string{"password", "totp"}, "2",
			domain.BearerDigest(hexOf("presented-"+p.tag)), parityNow), "записано")
	})
	wr("UpsertCutoff", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.UpsertCutoff(ctx, domain.UserTokenRevocation{UserID: p.user.ID, RevokeBefore: parityNow,
			Reason: domain.RevokeReasonPasswordChange}, p.user.ID), "записана")
	})

	// --- Writer: способы входа ---
	wr("ReplaceLoginVerifier", "пароль её личности", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		replaced, err := w.ReplaceLoginVerifier(ctx, domain.LoginMethod{UserID: p.user.ID, Kind: domain.LoginMethodPassword,
			Verifier: parityVerifier("material-password-new"), State: domain.LoginMethodStateActive})
		return said(err, "заменён %v", replaced)
	})
	for _, kind := range []domain.LoginMethodKind{domain.LoginMethodPassword, domain.LoginMethodTOTP, domain.LoginMethodLookupSecret} {
		wr("LoginMethod", "её личность, вид "+string(kind), func(ctx context.Context, w humansession.Writer, p parityPerson) string {
			m, err := w.LoginMethod(ctx, p.user.ID, kind)
			return said(err, "строка %s", m.State)
		})
	}
	wr("UpsertPendingTOTP", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		accepted, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: p.user.ID, Kind: domain.LoginMethodTOTP,
			Verifier: parityVerifier("material-totp-new"), State: domain.LoginMethodStatePending, CreatedAt: parityNow})
		return said(err, "принято %v", accepted)
	})
	wr("ActivateTOTP", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		ok, err := w.ActivateTOTP(ctx, p.user.ID, parityNow, 200, parityNow.Add(time.Second))
		return said(err, "подтверждено %v", ok)
	})
	wr("ReplaceLookupSet", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.ReplaceLookupSet(ctx, domain.LoginMethod{UserID: p.user.ID, Kind: domain.LoginMethodLookupSecret,
			Verifier: parityVerifier(",e7,e8,"), State: domain.LoginMethodStateActive, CreatedAt: parityNow}), "записан")
	})
	wr("LockLookupSet", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		m, ok, err := w.LockLookupSet(ctx, p.user.ID)
		return said(err, "найден %v %s", ok, m.State)
	})
	wr("ConsumeLookupElement", "её личность, элемент её набора", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		ok, err := w.ConsumeLookupElement(ctx, p.user.ID, "e1")
		return said(err, "снят %v", ok)
	})
	wr("RecordAcceptedStep", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		ok, err := w.RecordAcceptedStep(ctx, p.user.ID, 101)
		return said(err, "записан %v", ok)
	})
	wr("RemoveSecondFactor", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		ok, err := w.RemoveSecondFactor(ctx, p.user.ID)
		return said(err, "снят %v", ok)
	})

	// --- Writer: счёт неверных предъявлений ---
	for _, k := range keyForms {
		wr("RecordFailure", k.form, func(ctx context.Context, w humansession.Writer, p parityPerson) string {
			return said(w.RecordFailure(ctx, humansession.FailureByAddress, k.key(p), parityNow), "записан")
		})
		wr("ResetFailures", k.form, func(ctx context.Context, w humansession.Writer, p parityPerson) string {
			return said(w.ResetFailures(ctx, humansession.FailureByAddress, k.key(p)), "снят")
		})
	}

	// --- Writer: событие, код, письмо, журнал завершений ---
	wr("EmitAudit", "событие её аккаунта", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.EmitAudit(ctx, outboxtypes.AuditEvent{EventType: humansession.AuditRecoveryCompleted,
			TenantAccountID: string(p.user.AccountID), Payload: map[string]any{"user_id": string(p.user.ID)}}), "записано")
	})
	wr("InsertRecoveryCode", "новый код её личности", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.InsertRecoveryCode(ctx, domain.RecoveryCode{ID: domain.RecoveryCodeID("rcv-parity-new-" + p.tag),
			UserID: p.user.ID, Digest: domain.CodeDigest(hexOf("new-code-" + p.tag)), IssuedAt: parityNow,
			ExpiresAt: parityNow.Add(5 * time.Minute)}), "записан")
	})
	wr("SupersedeRecoveryCodes", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		n, err := w.SupersedeRecoveryCodes(ctx, p.user.ID)
		return said(err, "снято %d", n)
	})
	for _, d := range []struct {
		form   string
		digest func(parityPerson) domain.CodeDigest
	}{
		{"код, предъявленный полосой", func(parityPerson) domain.CodeDigest { return laneWrongDigest }},
		{"её код", func(p parityPerson) domain.CodeDigest { return p.code.Digest() }},
	} {
		wr("ConsumeRecoveryCode", d.form, func(ctx context.Context, w humansession.Writer, p parityPerson) string {
			_, ok, err := w.ConsumeRecoveryCode(ctx, p.user.ID, d.digest(p), parityNow)
			return said(err, "применён %v", ok)
		})
	}
	for _, c := range []struct {
		form string
		code func(parityPerson) domain.RecoveryCodeValue
	}{
		{"её код", func(p parityPerson) domain.RecoveryCodeValue { return p.code }},
		{"код полосы", func(parityPerson) domain.RecoveryCodeValue { return domain.PresentedRecoveryCode("AAAAA-AAAAA") }},
	} {
		wr("EmitRecoveryMail", "письмо её личности, "+c.form, func(ctx context.Context, w humansession.Writer, p parityPerson) string {
			return said(w.EmitRecoveryMail(ctx, humansession.RecoveryMailIntent{UserID: p.user.ID, AccountID: p.user.AccountID,
				To: string(p.user.Email), Code: c.code(p), ValidFor: 5 * time.Minute}), "поставлено")
		})
	}
	wr("InsertRecoveryCompletion", "её личность", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		inserted, err := w.InsertRecoveryCompletion(ctx, domain.RecoveryCompletion{RecoveryJTI: "rcv-parity-jti-" + p.tag,
			UserID: p.user.ID, RevokedSessionCount: 1})
		return said(err, "вставлено %v", inserted)
	})

	// --- Writer: исход транзакции ---
	commit := func(ctx context.Context, w humansession.Writer, _ parityPerson) string {
		return said(w.Commit(ctx), "зафиксирована")
	}
	rollback := func(ctx context.Context, w humansession.Writer, _ parityPerson) string {
		return said(w.Rollback(ctx), "откачена")
	}
	wr("Commit", "открытая транзакция", commit)
	wr("Rollback", "открытая транзакция", rollback)
	cs = append(cs,
		parityCase{method: "Writer.Commit", form: "после фиксации", writer: commit, closeFirst: "commit"},
		parityCase{method: "Writer.Commit", form: "после отката", writer: commit, closeFirst: "rollback"},
		parityCase{method: "Writer.Rollback", form: "после фиксации", writer: rollback, closeFirst: "commit"},
		parityCase{method: "Writer.Rollback", form: "после отката", writer: rollback, closeFirst: "rollback"})

	// --- Прочие отказы аргументом: вне осей полос, но той же природы ---
	// Вход, одинаково недопустимый у всех полос, осей полос не несёт; сверяется
	// он потому, что дублёр, принимающий его, был бы мягче адаптера в той же
	// форме — и полоса, начавшая его подавать, различилась бы в базе, а не в
	// дублёре.
	wr("EmitAudit", "вид события пуст", func(ctx context.Context, w humansession.Writer, p parityPerson) string {
		return said(w.EmitAudit(ctx, outboxtypes.AuditEvent{TenantAccountID: string(p.user.AccountID)}), "записано")
	})
	wr("UpsertPendingTOTP", "строка не заведения", func(ctx context.Context, w humansession.Writer, _ parityPerson) string {
		accepted, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: domain.UserID(fmt.Sprintf("usr%017s", "prtplain")),
			Kind: domain.LoginMethodTOTP, Verifier: parityVerifier("material-totp-new"), State: domain.LoginMethodStateActive, CreatedAt: parityNow})
		return said(err, "принято %v", accepted)
	})
	wr("ReplaceLookupSet", "строка без момента", func(ctx context.Context, w humansession.Writer, _ parityPerson) string {
		return said(w.ReplaceLookupSet(ctx, domain.LoginMethod{UserID: domain.UserID(fmt.Sprintf("usr%017s", "prtfactor")),
			Kind: domain.LoginMethodLookupSecret, Verifier: parityVerifier(",e7,e8,"), State: domain.LoginMethodStateActive}), "записан")
	})
	wr("ConsumeLookupElement", "элемент с разделителем", func(ctx context.Context, w humansession.Writer, _ parityPerson) string {
		ok, err := w.ConsumeLookupElement(ctx, domain.UserID(fmt.Sprintf("usr%017s", "prtfactor")), "e1,e2")
		return said(err, "снят %v", ok)
	})
	return cs
}

// portMethods — имена методов порта, выведенные отражением.
func portMethods(prefix string, iface reflect.Type) []string {
	out := make([]string, 0, iface.NumMethod())
	for i := 0; i < iface.NumMethod(); i++ {
		out = append(out, prefix+"."+iface.Method(i).Name)
	}
	return out
}

// TestStoreDouble_AnswersAndWorksAsTheAdapterOnEveryLaneAxis — на каждом входе
// каждой оси полос дублёр отвечает тем же исходом и исполняет то же число
// операторов базы, что настоящий адаптер.
func TestStoreDouble_AnswersAndWorksAsTheAdapterOnEveryLaneAxis(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	people := parityPeople(t)
	cases := parityCases()

	// Предпосылка 1: случаи покрывают порты целиком и ничего сверх них.
	declared := append(portMethods("Store", reflect.TypeOf((*humansession.Store)(nil)).Elem()),
		portMethods("Writer", reflect.TypeOf((*humansession.Writer)(nil)).Elem())...)
	covered := map[string]int{}
	for _, c := range cases {
		covered[c.method]++
	}
	var missing, orphan []string
	for _, m := range declared {
		if covered[m] == 0 {
			missing = append(missing, m)
		}
	}
	known := map[string]bool{}
	for _, m := range declared {
		known[m] = true
	}
	for m := range covered {
		if !known[m] {
			orphan = append(orphan, m)
		}
	}
	sort.Strings(orphan)
	require.Empty(t, missing, "у метода порта нет случая сверки — дублёр на нём не сверен с адаптером")
	require.Empty(t, orphan, "случай сверки без метода порта — сверять нечего")

	adapter := adapterSide(t, ctx, people)
	double := doubleSide(t, ctx, people)

	var (
		diverged           []string
		inputs             int
		zeroWork, withWork int
		statements         int64
	)
	for _, c := range cases {
		for _, p := range people {
			inputs++
			aOut, aN := adapter.run(t, ctx, c, p)
			dOut, dN := double.run(t, ctx, c, p)
			statements += aN
			if aN == 0 {
				zeroWork++
			} else {
				withWork++
			}
			if aOut != dOut || aN != dN {
				diverged = append(diverged, fmt.Sprintf("%s [%s] · %s: адаптер «%s», операторов %d; дублёр «%s», операторов %d",
					c.method, c.form, p.label, aOut, aN, dOut, dN))
			}
		}
	}
	t.Logf("перепись: методов портов %d (Store %d · Writer %d) · случаев (метод × форма) %d · личностей %d · входов сверено %d · "+
		"у адаптера без единого оператора %d, с операторами %d (всего операторов %d) · расхождений %d",
		len(declared), reflect.TypeOf((*humansession.Store)(nil)).Elem().NumMethod(),
		reflect.TypeOf((*humansession.Writer)(nil)).Elem().NumMethod(), len(cases), len(people), inputs,
		zeroWork, withWork, statements, len(diverged))

	// Предпосылка 2: счётчик адаптера видит обе стороны оси работы.
	require.Positive(t, zeroWork, "среди входов нет исполненных адаптером без оператора — сверка не видит отказа аргументом")
	require.Positive(t, withWork, "среди входов нет исполненных адаптером операторами — счётчик ничего не видит")

	require.Empty(t, diverged, "дублёр расходится с адаптером на осях полос (%d из %d входов):\n  %s",
		len(diverged), inputs, strings.Join(diverged, "\n  "))
}
