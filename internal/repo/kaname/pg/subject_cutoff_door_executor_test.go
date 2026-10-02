// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// subject_cutoff_door_executor_test.go — ТРЕТЬЕГО ИСПОЛНИТЕЛЯ ДВЕРЬ ОТСЕЧКИ НЕ
// ПРИНИМАЕТ (kaname#341).
//
// # ПОЧЕМУ ПРОБА ВНУТРИПАКЕТНАЯ
//
// Ветвь `default` двери `upsertSubjectCutoff` отвечает отказом исполнителю,
// который не есть ни пул, ни транзакция. Внешним тестовым пакетом она
// недостижима: порт исполнителя объявлен неэкспортируемым типом, и третьего
// вида из `package pg_test` не подать. Недостижимой В ПРИНЦИПЕ она от этого не
// становится: порт несёт ОДИН метод, и внутри пакета его выполняет любая
// заглушка. Ветвь отвечает до первого оператора, поэтому ни базы, ни
// контейнера пробе не нужно.
//
// # ЧТО УТВЕРЖДАЕТСЯ
//
// Третий вид получает отказ — полосы ВНУТРЕННЕЙ ошибки и с названием типа,
// который его вызвал, — и ни одного оператора исполнитель при этом не видит:
// отказ, случившийся после первой записи, был бы ровно той половиной, ради
// которой дверь заведена.
//
// # ЗАКОННЫЕ БЛИЗНЕЦЫ
//
// Без них отказ зеленел бы на двери, отвергающей ВСЕХ, — то есть на сломанной.
// Поэтому тот же вход подаётся обоим объявленным видам, и ни один из них этого
// отказа не получает:
//
//   - транзакция — тем же регистратором операторов, что у третьего вида:
//     различаются они РОВНО ОДНИМ фактом, видом исполнителя, и транзакция
//     получает обе записи, одну за другой;
//   - пул — без базы: его соединение отказывает на наборе адреса, и отказ этот
//     приходит из ветви пула (попытка открыть транзакцию), а не из `default`.
//     Что ветвь пула действительно взята, доказывает счётчик набора адреса, а не
//     отсутствие слов в тексте отказа.

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// cutoffDoorRefusalText — слова отказа ветви `default`. Выписаны один раз:
// отрицание близнецов и утверждение третьего вида обязаны судить ОДИН текст.
const cutoffDoorRefusalText = "subject cutoff needs a pool or a transaction"

// cutoffDoorInput — вход, законный для обеих записей отсечки: субъект назван,
// решивший назван. Незаконный вход дверь отвергла бы РАНЬШЕ выбора
// исполнителя, и отказ ветви `default` стал бы недостижим — проба судила бы
// проверку входа, а не вид исполнителя.
func cutoffDoorInput() (domain.UserTokenRevocation, domain.UserID) {
	return domain.UserTokenRevocation{
		UserID:       "usr0000000000000cut01",
		RevokeBefore: time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC),
		Reason:       "logout",
	}, "usr0000000000000admin"
}

// recordingCutoffStatements — регистратор операторов: что исполнителю подали,
// в каком порядке. Отвечает успехом — предмет пробы выбор исполнителя, а не
// отказ хранилища.
type recordingCutoffStatements struct {
	statements []string
}

func (r *recordingCutoffStatements) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	r.statements = append(r.statements, sql)
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

// undeclaredCutoffExecutor — ТРЕТИЙ вид: исполнять операторы умеет, но это ни
// пул, ни транзакция — ни атомарности, ни её обещания.
type undeclaredCutoffExecutor struct {
	rec *recordingCutoffStatements
}

func (u undeclaredCutoffExecutor) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return u.rec.Exec(ctx, sql, args...)
}

// declaredTxCutoffExecutor — объявленный вид «транзакция вызывающего» с тем же
// регистратором. Встроенная транзакция пуста НАМЕРЕННО: дверь на этой ветви
// обязана звать только исполнение операторов, и любой другой вызов (например,
// вложенное начало) упал бы на пустом значении — громко, а не молча.
type declaredTxCutoffExecutor struct {
	pgx.Tx
	rec *recordingCutoffStatements
}

func (d declaredTxCutoffExecutor) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return d.rec.Exec(ctx, sql, args...)
}

// TestSubjectCutoffDoorRefusesAnUndeclaredExecutor — третий вид получает отказ
// до первого оператора.
func TestSubjectCutoffDoorRefusesAnUndeclaredExecutor(t *testing.T) {
	rec := &recordingCutoffStatements{}
	u, revokedBy := cutoffDoorInput()

	err := upsertSubjectCutoff(context.Background(), undeclaredCutoffExecutor{rec: rec}, u, revokedBy)

	if err == nil {
		t.Fatal("дверь отсечки приняла исполнителя, который не есть ни пул, ни " +
			"транзакция: обе записи легли бы двумя независимыми операторами, и между " +
			"ними существовало бы состояние «одна без другой»")
	}
	if !stderrors.Is(err, iamerr.ErrInternal) {
		t.Errorf("отказ третьему виду обязан быть полосы внутренней ошибки — это "+
			"ошибка провязки, а не входа вызывающего; получено %v", err)
	}
	if !strings.Contains(err.Error(), cutoffDoorRefusalText) {
		t.Errorf("отказ пришёл не из ветви выбора исполнителя: ждали %q, получено %q",
			cutoffDoorRefusalText, err.Error())
	}
	if typeName := fmt.Sprintf("%T", undeclaredCutoffExecutor{}); !strings.Contains(err.Error(), typeName) {
		t.Errorf("отказ обязан назвать тип исполнителя (%s) — без него провязку, "+
			"подавшую его, не найти; получено %q", typeName, err.Error())
	}
	if len(rec.statements) != 0 {
		t.Errorf("третий вид получил %d оператор(ов) до отказа — отказ после первой "+
			"записи оставляет половину отсечки:\n%s",
			len(rec.statements), strings.Join(rec.statements, "\n---\n"))
	}
}

// TestSubjectCutoffDoorTakesTheCallersTransaction — ЗАКОННЫЙ БЛИЗНЕЦ: тот же
// регистратор и тот же вход, вид исполнителя — транзакция. Отказа нет, и обе
// записи ложатся этим исполнителем, одна за другой.
func TestSubjectCutoffDoorTakesTheCallersTransaction(t *testing.T) {
	rec := &recordingCutoffStatements{}
	u, revokedBy := cutoffDoorInput()

	err := upsertSubjectCutoff(context.Background(), declaredTxCutoffExecutor{rec: rec}, u, revokedBy)

	if err != nil {
		t.Fatalf("транзакция вызывающего — объявленный вид, и отказа ей быть не "+
			"должно; получено %v", err)
	}
	want := []string{subjectCutoffRowSQL, upsertMintedCutoffSQL}
	if len(rec.statements) != len(want) {
		t.Fatalf("на транзакции вызывающего исполнено %d оператор(ов), ждали %d — "+
			"обе записи отсечки и ничего сверх них", len(rec.statements), len(want))
	}
	for i := range want {
		if rec.statements[i] != want[i] {
			t.Errorf("оператор %d не тот: ждали\n%s\nполучено\n%s", i, want[i], rec.statements[i])
		}
	}
}

// TestSubjectCutoffDoorTakesThePool — ЗАКОННЫЙ БЛИЗНЕЦ второго объявленного
// вида. Базы нет: набор адреса отказывает сразу, и дверь обязана ответить
// отказом ОТКРЫТИЯ ТРАНЗАКЦИИ на пуле, а не отказом вида.
func TestSubjectCutoffDoorTakesThePool(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://kaname@127.0.0.1:1/kaname?sslmode=disable")
	if err != nil {
		t.Fatalf("настройка пула: %v", err)
	}
	errNoDatabase := stderrors.New("probe: no database behind this pool")
	dials := 0
	cfg.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errNoDatabase
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	t.Cleanup(pool.Close)
	u, revokedBy := cutoffDoorInput()

	err = upsertSubjectCutoff(context.Background(), pool, u, revokedBy)

	if err == nil {
		t.Fatal("за пулом нет базы, и открыть на нём транзакцию нельзя — успех " +
			"означает, что дверь не открывала её вовсе")
	}
	if strings.Contains(err.Error(), cutoffDoorRefusalText) {
		t.Fatalf("пул — объявленный вид, а получил отказ третьему: %v", err)
	}
	if dials == 0 {
		t.Fatalf("адрес базы не набирался ни разу — ветвь пула не взята, и отказ "+
			"%q пришёл не из попытки открыть транзакцию", err.Error())
	}
}
