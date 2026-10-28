// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// errors_unclassified_journal_test.go — НЕРАЗОБРАННЫЙ ОТКАЗ ХРАНИЛИЩА ОСТАВЛЯЕТ
// ЗАПИСЬ В ЖУРНАЛЕ, И ЗАПИСЬ НЕСЁТ СТРУКТУРУ, А НЕ ТЕКСТ (задача kaname#662).
//
// Ветка по умолчанию `MapRepoErr` отвечает фиксированным `internal error`, и
// это верно для провода. Но до kaname#662 причина не доезжала НИКУДА: ни у
// хранилища, ни у use-case логгера нет, журнала доступа у службы нет, и 500 на
// стенде разбирали без единой строки о причине.
//
// Запись обязана назвать СТРУКТУРУ отказа (где, какими типами, каким кодом
// состояния) и не обязана — и не смеет — нести его ТЕКСТ: текст драйвера и
// обёртки вызывающего несут значения арендатора (адрес почты, идентификаторы,
// введённое значение в «invalid input syntax»), а журнал читает оператор.
//
// Законный близнец: отказ, НАЗЫВАЮЩИЙ свою причину (строки нет, ввод негоден,
// конец контекста, отказ, классифицированный производителем как внутренний),
// журналу не называется — у него либо причина на проводе, либо свой писатель.
package shared_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// unclassifiedMsg — сообщение записи о неразобранном отказе; проба держит его
// дословно, чтобы запись можно было найти поиском по журналу.
const unclassifiedMsg = "repository error is not classified"

// Текст, которого в журнале быть не должно: ТЕКСТ драйвера и данные арендатора
// из обёртки вызывающего.
const (
	driverText   = "invalid input syntax for type uuid: \"tenant-typed-value-7f3\""
	tenantEmail  = "alice.tenant@example.org"
	tenantObject = "prj9tenantsecret0042"
)

// driverFault — отказ драйвера той формы, какую кладёт `pgconn.PgError`: свой
// текст и метод `SQLState()`. Пакет pgx здесь не импортируется намеренно —
// переводчик живёт в слое без драйвера и опознаёт код состояния по методу.
type driverFault struct {
	state string
	text  string
}

func (e *driverFault) Error() string    { return e.text }
func (e *driverFault) SQLState() string { return e.state }

// captureJournal подменяет журнал по умолчанию буфером на время пробы. Проба не
// параллельна: журнал по умолчанию — общий для процесса.
func captureJournal(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// recordsOf разбирает журнал построчно и возвращает записи с данным сообщением.
func recordsOf(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("строка журнала не JSON: %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

func assertNoTenantText(t *testing.T, journal string) {
	t.Helper()
	for _, leak := range []string{driverText, "tenant-typed-value-7f3", tenantEmail, tenantObject} {
		if strings.Contains(journal, leak) {
			t.Fatalf("журнал несёт текст драйвера или данные арендатора %q:\n%s", leak, journal)
		}
	}
}

func TestMapRepoErr_UnclassifiedErrorIsJournaledWithItsStructure(t *testing.T) {
	buf := captureJournal(t)
	err := fmt.Errorf("read binding of %s in %s: %w", tenantEmail, tenantObject,
		&driverFault{state: "22P02", text: driverText})

	mapped := shared.MapRepoErr(err)

	// Провод — прежний: фиксированный текст, код Internal.
	assertAnswer(t, mapped, codes.Internal, "internal error")

	recs := recordsOf(t, buf, unclassifiedMsg)
	if len(recs) != 1 {
		t.Fatalf("записей о неразобранном отказе %d, want 1; журнал:\n%s", len(recs), buf.String())
	}
	rec := recs[0]
	if rec["level"] != "ERROR" {
		t.Fatalf("уровень записи %v, want ERROR", rec["level"])
	}
	if got := rec["sqlstate"]; got != "22P02" {
		t.Fatalf("sqlstate = %v, want 22P02", got)
	}
	if got := rec["err_type"]; got != "*fmt.wrapError" {
		t.Fatalf("err_type = %v, want *fmt.wrapError", got)
	}
	chain, _ := rec["err_chain"].(string)
	if chain != "*fmt.wrapError > *shared_test.driverFault" {
		t.Fatalf("err_chain = %q, want типы звеньев по порядку", chain)
	}
	site, _ := rec["site"].(string)
	if !strings.HasSuffix(site, ".TestMapRepoErr_UnclassifiedErrorIsJournaledWithItsStructure") {
		t.Fatalf("site = %q, want вызывающий MapRepoErr", site)
	}
	at, _ := rec["at"].(string)
	if !strings.HasPrefix(at, "errors_unclassified_journal_test.go:") {
		t.Fatalf("at = %q, want файл:строка вызывающего", at)
	}
	assertNoTenantText(t, buf.String())
}

// Цепочка с несколькими причинами (`errors.Join`) называет КАЖДОЕ звено; без
// кода состояния поле sqlstate не пишется вовсе — пустое значение читалось бы
// как «код есть и он пуст».
func TestMapRepoErr_JoinedChainNamesEveryLink(t *testing.T) {
	buf := captureJournal(t)
	err := errors.Join(errors.New(tenantEmail), fmt.Errorf("scan %s: %w", tenantObject, errors.New(driverText)))

	assertAnswer(t, shared.MapRepoErr(err), codes.Internal, "internal error")

	recs := recordsOf(t, buf, unclassifiedMsg)
	if len(recs) != 1 {
		t.Fatalf("записей %d, want 1; журнал:\n%s", len(recs), buf.String())
	}
	if got := recs[0]["err_chain"]; got != "*errors.joinError > [*errors.errorString | *fmt.wrapError > *errors.errorString]" {
		t.Fatalf("err_chain = %v", got)
	}
	if _, ok := recs[0]["sqlstate"]; ok {
		t.Fatalf("sqlstate записан без кода состояния в цепочке: %v", recs[0]["sqlstate"])
	}
	assertNoTenantText(t, buf.String())
}

// Законный близнец: исход, называющий свою причину, либо отказ, который
// производитель уже классифицировал, журналу этим переводчиком не называется.
func TestMapRepoErr_NamedOutcomesAreNotJournaled(t *testing.T) {
	cases := map[string]error{
		"строки нет":                  iamerr.Wrapf(iamerr.ErrNotFound, "Access binding %s not found", tenantObject),
		"ввод негоден":                iamerr.Wrapf(iamerr.ErrInvalidArg, "bad"),
		"внутренний по производителю": iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate 57014"),
		"конец контекста":             fmt.Errorf("read: %w", context.DeadlineExceeded),
		"illegal argument":            errors.New("Illegal argument page_size"),
		"статус с кодом":              status.Error(codes.Internal, "internal error"),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			buf := captureJournal(t)
			_ = shared.MapRepoErr(err)
			if recs := recordsOf(t, buf, unclassifiedMsg); len(recs) != 0 {
				t.Fatalf("исход с названной причиной записан как неразобранный: %v", recs)
			}
		})
	}
}

// MapRepoErrAt на живом контексте пишет ту же запись и называет СВОЕГО
// вызывающего; на кончившемся — переклассифицирует в недоступность, и записи
// уровня ERROR о поломке нет: это конец срока, а не поломка.
func TestMapRepoErrAt_JournalFollowsTheVerdict(t *testing.T) {
	err := fmt.Errorf("read %s: %w", tenantObject, &driverFault{state: "XX000", text: driverText})

	t.Run("живой контекст", func(t *testing.T) {
		buf := captureJournal(t)
		assertAnswer(t, shared.MapRepoErrAt(context.Background(), err), codes.Internal, "internal error")
		recs := recordsOf(t, buf, unclassifiedMsg)
		if len(recs) != 1 {
			t.Fatalf("записей %d, want 1; журнал:\n%s", len(recs), buf.String())
		}
		site, _ := recs[0]["site"].(string)
		if !strings.Contains(site, "TestMapRepoErrAt_JournalFollowsTheVerdict") {
			t.Fatalf("site = %q, want вызывающий MapRepoErrAt", site)
		}
		assertNoTenantText(t, buf.String())
	})
	t.Run("кончившийся контекст", func(t *testing.T) {
		buf := captureJournal(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertAnswer(t, shared.MapRepoErrAt(ctx, err), codes.Unavailable, shared.UnavailableMessage)
		if recs := recordsOf(t, buf, unclassifiedMsg); len(recs) != 0 {
			t.Fatalf("конец срока записан как поломка: %v", recs)
		}
	})
}

// Законный близнец конца срока: ответ, называющий свою причину, на кончившемся
// контексте остаётся ТЕМ ЖЕ, что на живом, — и значением, а не только кодом.
// Отказ подаётся переводчику на кончившемся контексте в прозрачной обёртке, по
// которой запись в журнал узнаёт конец срока; наружу обёртка не выходит ни
// сквозным статусом, ни текстом признака.
func TestMapRepoErrAt_EndedContextKeepsNamedAnswers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("сквозной статус возвращается тем же значением", func(t *testing.T) {
		buf := captureJournal(t)
		in := status.Error(codes.NotFound, "Access binding x not found")
		got := shared.MapRepoErrAt(ctx, in)
		if got != in { //nolint:errorlint // проба утверждает тождество значения, а не цепочку
			t.Fatalf("сквозной статус подменён: got %#v (%T), want то же значение %#v", got, got, in)
		}
		if recs := recordsOf(t, buf, unclassifiedMsg); len(recs) != 0 {
			t.Fatalf("сквозной статус записан как неразобранный: %v", recs)
		}
	})
	t.Run("признак полосы отвечает тем же текстом, что на живом контексте", func(t *testing.T) {
		buf := captureJournal(t)
		in := iamerr.Wrapf(iamerr.ErrNotFound, "Access binding %s not found", tenantObject)
		want := shared.MapRepoErr(in)
		assertAnswer(t, shared.MapRepoErrAt(ctx, in), status.Code(want), status.Convert(want).Message())
		if recs := recordsOf(t, buf, unclassifiedMsg); len(recs) != 0 {
			t.Fatalf("исход с названной причиной записан как неразобранный: %v", recs)
		}
	})
	t.Run("illegal argument остаётся вводом", func(t *testing.T) {
		in := errors.New("Illegal argument page_size")
		assertAnswer(t, shared.MapRepoErrAt(ctx, in), codes.InvalidArgument, in.Error())
	})
}
