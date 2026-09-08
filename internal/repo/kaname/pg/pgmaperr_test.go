// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_test.go — unit coverage for the SQLSTATE→sentinel bridge that moved
// out of internal/errors into this adapter layer (keeping internal/errors
// pgx-free). No DB: exercises wrapPgErr against synthetic *pgconn.PgError values.

import (
	stderrors "errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Sensitive strings a raw *pgconn.PgError carries — they must NEVER reach the
// client-facing message (data-integrity.md / api-conventions.md: no pgx leak).
const (
	secretConstraint = "super_secret_internal_constraint"
	secretMessage    = `duplicate key value violates unique constraint "super_secret_internal_constraint"`
	secretDetail     = "Key (internal_hostid)=(host-42) already exists."
	secretTable      = "internal_secret_table"
)

func mkPgErr(code, constraint string) *pgconn.PgError {
	return &pgconn.PgError{
		Code:           code,
		ConstraintName: constraint,
		Message:        secretMessage,
		Detail:         secretDetail,
		ColumnName:     "internal_hostid",
		TableName:      secretTable,
	}
}

func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{secretConstraint, secretDetail, secretTable, secretMessage} {
		if strings.Contains(out, s) {
			t.Errorf("LEAK: client-facing text %q contains sensitive pgx fragment %q", out, s)
		}
	}
}

// TestWrapPgErr_NotNull_NoColumnLeak — 23502 (not_null_violation) must map to a
// generic InvalidArgument message; the raw Postgres column name (internal schema
// identifier, differs from the public proto field name) must never be echoed.
func TestWrapPgErr_NotNull_NoColumnLeak(t *testing.T) {
	err := wrapPgErr(mkPgErr("23502", ""), "", "")
	if !stderrors.Is(err, iamerr.ErrInvalidArg) {
		t.Fatalf("want ErrInvalidArg, got %v", err)
	}
	out := iamerr.StripSentinel(err)
	if strings.Contains(out, "internal_hostid") {
		t.Errorf("LEAK: client-facing text %q echoes raw pg column name", out)
	}
	if out != "a required field is missing" {
		t.Errorf("text = %q; want generic no-leak text", out)
	}
}

// TestWrapPgErr_NoLeak_OnUnmappedConstraints — every fallback path (unknown
// SQLSTATE + unknown constraint per family) must produce a fixed, schema-free
// message and the correct sentinel, never the raw pgErr text.
func TestWrapPgErr_NoLeak_OnUnmappedConstraints(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		sentinel error
		wantText string
	}{
		// Код состояния остаётся в ЦЕПОЧКЕ ради журнала (#666); клиенту он не
		// достаётся — перевод sentinel'а в статус заменяет сообщение `Internal`
		// целиком, и это утверждает отдельная проба ниже.
		{"unmapped-sqlstate", "XX000", iamerr.ErrInternal, "database error: sqlstate XX000"},
		{"unmapped-unique", "23505", iamerr.ErrAlreadyExists, "resource with these attributes already exists"},
		// Неразобранная связь называет ОДНО состояние. Пустая подсказка — сторона
		// ссылки; обратная сторона утверждается отдельно
		// (`TestUnmappedForeignKeyNamesOneStateNotTwo`), и там же стоит
		// требование, чтобы два состояния не сходились в один текст.
		{"unmapped-fk", "23503", iamerr.ErrReferenceMissing, "referenced resource does not exist; create it or correct the reference before retrying"},
		{"unmapped-check", "23514", iamerr.ErrInvalidArg, "Illegal argument: value violates a constraint"},
		{"exclusion", "23P01", iamerr.ErrFailedPrecondition, "resource conflicts with an existing reservation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := wrapPgErr(mkPgErr(c.code, secretConstraint), "", "")
			if !stderrors.Is(err, c.sentinel) {
				t.Fatalf("want sentinel %v, got %v", c.sentinel, err)
			}
			out := iamerr.StripSentinel(err)
			if out != c.wantText {
				t.Errorf("text = %q; want %q", out, c.wantText)
			}
			assertNoLeak(t, out)
		})
	}
}

// TestWrapPgErr_SerializationFailure_Aborted — 40001 (serialization_failure) is a
// transient, retryable concurrency conflict; it must map to the retryable
// ErrAborted (gRPC ABORTED), NOT ErrFailedPrecondition (which tells a client not
// to retry). The message text and the sentinel must agree on "retry".
func TestWrapPgErr_SerializationFailure_Aborted(t *testing.T) {
	err := wrapPgErr(mkPgErr("40001", secretConstraint), "", "")
	if !stderrors.Is(err, iamerr.ErrAborted) {
		t.Fatalf("40001: want ErrAborted (retryable), got %v", err)
	}
	if stderrors.Is(err, iamerr.ErrFailedPrecondition) {
		t.Fatalf("40001: must NOT be FailedPrecondition (non-retryable)")
	}
	out := iamerr.StripSentinel(err)
	if out != "conflicting concurrent change, retry the request" {
		t.Errorf("text = %q; want %q", out, "conflicting concurrent change, retry the request")
	}
	assertNoLeak(t, out)
}

// TestWrapPgErr_ConnFamily_Unavailable — an 08xxx connection-family SQLSTATE maps
// to a retryable ErrUnavailable with a generic, schema-free message.
func TestWrapPgErr_ConnFamily_Unavailable(t *testing.T) {
	err := wrapPgErr(mkPgErr("08006", secretConstraint), "", "")
	if !stderrors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("08006: want ErrUnavailable, got %v", err)
	}
	out := iamerr.StripSentinel(err)
	if out != "database unavailable" {
		t.Errorf("text = %q; want %q", out, "database unavailable")
	}
	assertNoLeak(t, out)
}

// TestWrapPgErr_KnownConstraint_KeepsVerbatimContract — the no-leak hardening
// must NOT regress the constraint-aware verbatim Kachō text contract.
func TestWrapPgErr_KnownConstraint_KeepsVerbatimContract(t *testing.T) {
	err := wrapPgErr(mkPgErr("23505", "accounts_name_unique"), "", "my-acct")
	if !stderrors.Is(err, iamerr.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
	if got := iamerr.StripSentinel(err); got != "Account with name my-acct already exists" {
		t.Errorf("verbatim contract text regressed: %q", got)
	}
}

// Проба `TestWrapPgErr_ConditionFK_DirectionSensitive` снята ВМЕСТЕ со своим
// предметом: тенантская поверхность ресурса `Condition` ретайрнута целиком, а
// миграция `0075` снесла таблицы и внешний ключ, чьё имя проба закрепляла. Она
// оставалась зелёной и после снятия — вход подавала сама, синтетическим
// `pgconn.PgError`, — то есть удостоверяла текст, который сервер больше не
// произведёт. Класс держит `TestRefusalTextNeverNamesARetiredConstraint`.

// TestWrapPgErr_SubjectRefBeforeDelete_ResourceAware — migration 0050's BEFORE
// DELETE trigger RAISEs 23503 tagged CONSTRAINT='access_binding_subjects_subject_ref'
// when a User/SA/Group is still referenced as a subjects[0..N] grantee. wrapPgErr
// must map it to FailedPrecondition with the canonical resource-aware text derived
// from the repo's "<Resource>.Delete" kindHint (SEC r8), never leaking pgx text.
func TestWrapPgErr_SubjectRefBeforeDelete_ResourceAware(t *testing.T) {
	const constraint = "access_binding_subjects_subject_ref"
	cases := []struct {
		kindHint string
		idHint   string
		want     string
	}{
		{"User.Delete", "usr_x", "User usr_x has active access bindings and cannot be deleted"},
		{"ServiceAccount.Delete", "sva_x", "ServiceAccount sva_x has active access bindings and cannot be deleted"},
		{"Group.Delete", "grp_x", "Group grp_x has active access bindings and cannot be deleted"},
		{"", "prn_x", "Principal prn_x has active access bindings and cannot be deleted"},
	}
	for _, c := range cases {
		err := wrapPgErr(mkPgErr("23503", constraint), c.kindHint, c.idHint)
		if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
			t.Fatalf("kindHint %q: want ErrFailedPrecondition, got %v", c.kindHint, err)
		}
		if got := iamerr.StripSentinel(err); got != c.want {
			t.Errorf("kindHint %q: text = %q; want %q", c.kindHint, got, c.want)
		}
		assertNoLeak(t, iamerr.StripSentinel(err))
	}
}

// TestWrapPgErr_AccountsOwnerFK_CommitTime — accounts_owner_fk is DEFERRABLE
// INITIALLY DEFERRED, so a non-existent account owner is NOT caught by the INSERT
// statement: the 23503 surfaces at COMMIT (writeTx.Commit runs the commit error
// through this same bridge with the owner-id hint recorded by accountWriter.Insert).
// It must map to FailedPrecondition with the canonical "User <id> not found" text —
// NOT the sentinel-only INTERNAL fallback that a raw *pgconn.PgError would trigger.
func TestWrapPgErr_AccountsOwnerFK_CommitTime(t *testing.T) {
	err := wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "", "usr_missing")
	if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
		t.Fatalf("commit-time accounts_owner_fk: want ErrFailedPrecondition, got %v", err)
	}
	if stderrors.Is(err, iamerr.ErrInternal) {
		t.Fatalf("commit-time accounts_owner_fk: must NOT map to ErrInternal")
	}
	out := iamerr.StripSentinel(err)
	if out != "User usr_missing not found" {
		t.Errorf("text = %q; want %q", out, "User usr_missing not found")
	}
	assertNoLeak(t, out)
}

// TestWrapPgErr_NilPassesThrough — a nil error (successful commit) must stay nil
// so writeTx.Commit's wrapping is a no-op on the happy path.
func TestWrapPgErr_NilPassesThrough(t *testing.T) {
	if got := wrapPgErr(nil, "", "usr_x"); got != nil {
		t.Errorf("wrapPgErr(nil) = %v; want nil", got)
	}
}

// TestWrapPgErr_NonPgError_PassesThrough — a non-pgx error is returned as-is
// (the bridge only translates SQLSTATEs).
func TestWrapPgErr_NonPgError_PassesThrough(t *testing.T) {
	orig := stderrors.New("some domain error")
	if got := wrapPgErr(orig, "", ""); got != orig {
		t.Errorf("non-pg error not passed through: %v", got)
	}
}

// ── #666: отказ соединения — недоступность, а не поломка ────────────────────

// TestWrapPgErr_ConnectionRefusals_AreUnavailable — отказ ОТКРЫТЬ соединение
// читается как временная недоступность, а не как поломка сервиса.
//
// ПОЧЕМУ ЭТО НЕ ПЕДАНТИЗМ. Пул строится без нижней границы, соединения
// открываются лениво на первом обращении, готовность базы служебный бинарь не
// ждёт — значит быстрый транзиторный отказ открытия в загрузочной буре ожидаем
// ПО ПОСТРОЕНИЮ. `Internal` не повторяется (`retry.OnUnavailable` повторяет
// только недоступность), поэтому тянущий пределы получал терминальный отказ на
// состояние, которое проходит само за секунды.
//
// Семейство `08*` уже читалось верно; здесь добавлены два класса, которые
// поднимает САМ сервер, отказываясь принять соединение, и они лежат вне
// восьмого семейства.
func TestWrapPgErr_ConnectionRefusals_AreUnavailable(t *testing.T) {
	for _, tc := range []struct {
		code string
		what string
	}{
		{"53300", "too_many_connections — сервер исчерпал слоты"},
		{"57P03", "cannot_connect_now — сервер ещё поднимается"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			err := wrapPgErr(mkPgErr(tc.code, ""), "", "")
			if !stderrors.Is(err, iamerr.ErrUnavailable) {
				t.Fatalf("%s: want ErrUnavailable, got %v", tc.what, err)
			}
			assertNoLeak(t, iamerr.StripSentinel(err))
		})
	}
}

// TestWrapPgErr_DialFailure_IsUnavailable — отказ, приехавший НЕ строкой
// состояния сервера, а невозможностью до него дозвониться.
//
// Такой отказ вовсе не несёт SQLSTATE (сервер не ответил), поэтому прежняя ветвь
// пропускала его нетронутым, а общий перевод отправлял в `Internal` — «сервис
// сломан» вместо «сосед сейчас недоступен».
func TestWrapPgErr_DialFailure_IsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{
			// Форма, в которой отказ набора соединения приходит чаще всего:
			// сетевая операция не состоялась.
			name: "сокет не открылся",
			err: &net.OpError{
				Op: "dial", Net: "tcp",
				Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.7"), Port: 5432},
				Err:  stderrors.New("connection refused"),
			},
		},
		{
			// Драйвер закрыл соединение под нами — предыдущий запрос сняли на
			// полпути либо сокет ушёл. Повтор осмыслен.
			name: "соединение закрыто драйвером",
			err:  fmt.Errorf("query: %w", pgconn.ErrConnClosed),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := wrapPgErr(tc.err, "", "")
			if !stderrors.Is(err, iamerr.ErrUnavailable) {
				t.Fatalf("want ErrUnavailable, got %v", err)
			}
			// Адрес наружу не идёт: сообщение отказа фиксированное
			// (`security.md` §Hardening #1).
			out := iamerr.StripSentinel(err)
			for _, secret := range []string{"10.0.0.7", "5432", "connection refused"} {
				if strings.Contains(out, secret) {
					t.Errorf("LEAK: клиентский текст %q несёт координату соединения %q", out, secret)
				}
			}
		})
	}
}

// TestWrapPgErr_ConnectError_IsUnavailable — та же полоса для собственного типа
// драйвера.
//
// Причину внутрь этого типа положить нельзя: поле не экспортировано, и вызов его
// `Error()` на пустой причине падает. Поэтому проба НИЧЕГО НЕ ФОРМАТИРУЕТ — ни в
// удачном исходе, ни в отказе: диагностика здесь стоила бы паники вместо
// вердикта. Что распознавание идёт по типу, а не по тексту, видно по тому же
// значению — текста у него нет.
func TestWrapPgErr_ConnectError_IsUnavailable(t *testing.T) {
	dial := &pgconn.ConnectError{
		Config: &pgconn.Config{Host: "kaname-db", Port: 5432, User: "kacho", Database: "kaname"},
	}
	if !stderrors.Is(wrapPgErr(dial, "", ""), iamerr.ErrUnavailable) {
		t.Fatal("отказ соединения драйвера не прочитан как недоступность")
	}
}

// TestWrapPgErr_OrdinaryErrorStaysUntouched — отрицательный контроль: обычная
// ошибка недоступностью НЕ становится.
//
// Без него предыдущая проба зеленела бы и на переводе «всё непонятное — это
// недоступность», а он вернул бы вызывающему обещание повтора там, где
// повторять нечего.
func TestWrapPgErr_OrdinaryErrorStaysUntouched(t *testing.T) {
	plain := stderrors.New("scan quota state: bad column type")
	err := wrapPgErr(plain, "", "")
	if stderrors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("обычная ошибка объявлена недоступностью: %v", err)
	}
	if err != plain { //nolint:errorlint // сравнение по тождеству намеренно: ветвь обязана вернуть ТОТ ЖЕ объект
		t.Fatalf("обычная ошибка подменена: %v", err)
	}
}

// TestWrapPgErr_UnmappedSqlstate_KeepsTheCodeForTheLog — неопознанный SQLSTATE
// обязан оставить СВОЙ код в цепочке ошибки.
//
// Клиент по-прежнему видит фиксированный текст (перевод в статус заменяет
// сообщение `Internal` целиком), а вот журнал сервера без кода не может назвать
// причину вовсе — и «отказ есть, причину назвать нечем» становится штатным
// состоянием. Комментарии на этом пути обещали журналу деталь; обещание держится
// только если деталь в цепочке ЕСТЬ.
func TestWrapPgErr_UnmappedSqlstate_KeepsTheCodeForTheLog(t *testing.T) {
	err := wrapPgErr(mkPgErr("XX000", ""), "", "")
	if !stderrors.Is(err, iamerr.ErrInternal) {
		t.Fatalf("want ErrInternal, got %v", err)
	}
	if !strings.Contains(err.Error(), "XX000") {
		t.Fatalf("код состояния потерян для журнала: %q — причину отказа назвать будет нечем", err.Error())
	}
	// Но НЕ ценой утечки: текст сервера, имя ограничения и таблица в цепочку не
	// попадают, а клиенту достаётся фиксированный текст перевода.
	assertNoLeak(t, err.Error())
}
