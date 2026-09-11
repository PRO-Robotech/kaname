// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// withdrawal_producer_arrives_with_the_applier_injection_test.go —
// доказательство падучести по каждой клетке таблицы согласия (порт
// монорепошного предшественника-инъекции для гейта
// `withdrawalproducerarriveswiththeapplier`, снят вынесением службы доступа —
// `kacho#2597`; координата предшественника не воспроизводится здесь
// буквально — путь `internal/repohygiene/` в дереве kaname не существует, и
// цитата читалась бы этим же гейтом как необещанное).
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// withdrawalDrivenSrc — форма, действительно стоящая в дереве kaname
// (`cmd/kaname/serve.go`): применитель ПРИВОДИТСЯ В ДЕЙСТВИЕ.
const withdrawalDrivenSrc = `package main

import "github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"

func boot() {
	applier := moduleroles.NewApplier(nil, nil)
	_ = applier
}
`

// withdrawalMarkSrc — форма, действительно стоящая в дереве kaname
// (`internal/repo/kaname/pg/role_withdrawal_repo.go`): производитель отзыва.
const withdrawalMarkSrc = `package pg

func (w *roleWriter) Withdraw(ctx context.Context, id string) error {
	_, err := w.tx.Exec(ctx, ` + "`" + `
		UPDATE kaname.roles
		   SET live = false, retired_at = now()
		 WHERE id = $1` + "`" + `, id)
	return err
}
`

// withdrawalReadOnlySrc — законный близнец: `live` стоит в WHERE, то есть
// ЧИТАЕТСЯ, а не пишется — распознаватель обязан не засчитать это.
const withdrawalReadOnlySrc = `package pg

func (r *roleReader) ListLive(ctx context.Context) error {
	rows, err := r.pool.Query(ctx, ` + "`SELECT id FROM roles WHERE live = true`" + `)
	_ = rows
	return err
}
`

// withdrawalProseSrc — законный близнец: имя пакета и слово `retired_at` в
// КОММЕНТАРИИ, объясняющем сам предмет.
const withdrawalProseSrc = `package main

// moduleroles.Reconcile объявляет вид расхождения, а retired_at = ставится
// применителем — это проза, не код.
func explain() {}
`

// TestWithdrawal_RedOnDriveWithoutMark — ИНЪЕКЦИЯ: применитель приводится в
// действие, производителя нет вовсе (сведение по двум файлам).
func TestWithdrawal_RedOnDriveWithoutMark(t *testing.T) {
	t.Parallel()
	drive, mark, _, err := check.ScanRoleWithdrawalWiring("cmd/kaname/serve.go", []byte(withdrawalDrivenSrc))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(drive) != 1 {
		t.Fatalf("приведение применителя в действие не распознано: %+v", drive)
	}
	if len(mark) != 0 {
		t.Fatalf("производитель найден там, где его нет в этом файле: %+v", mark)
	}
	if !roleWithdrawalFinding(drive, mark) {
		t.Fatal("НЕСОГЛАСИЕ (drive>0, mark=0) не распознано как находка")
	}
}

// TestWithdrawal_SilentOnDriveWithMark — КОНТРОЛЬ: обе половины сведены —
// норма, работа сделана.
func TestWithdrawal_SilentOnDriveWithMark(t *testing.T) {
	t.Parallel()
	drive, _, _, err := check.ScanRoleWithdrawalWiring("cmd/kaname/serve.go", []byte(withdrawalDrivenSrc))
	if err != nil {
		t.Fatalf("разбор приведения: %v", err)
	}
	_, mark, _, err := check.ScanRoleWithdrawalWiring("internal/repo/kaname/pg/role_withdrawal_repo.go", []byte(withdrawalMarkSrc))
	if err != nil {
		t.Fatalf("разбор производителя: %v", err)
	}
	if len(mark) != 1 {
		t.Fatalf("производитель отзыва не распознан: %+v", mark)
	}
	if roleWithdrawalFinding(drive, mark) {
		t.Fatal("КОНТРОЛЬ: обе половины сведены, а согласие объявлено находкой")
	}
}

// TestWithdrawal_SilentOnNeitherDriveNorMark — законный близнец: остаток —
// ни применитель не приводится, ни производителя нет.
func TestWithdrawal_SilentOnNeitherDriveNorMark(t *testing.T) {
	t.Parallel()
	if roleWithdrawalFinding(nil, nil) {
		t.Fatal("остаток (обе половины пусты) объявлен находкой")
	}
}

// TestWithdrawal_SilentOnMarkWithoutDrive — законный близнец: производитель
// приехал раньше применителя — не находка by construction предиката.
func TestWithdrawal_SilentOnMarkWithoutDrive(t *testing.T) {
	t.Parallel()
	_, mark, _, err := check.ScanRoleWithdrawalWiring("internal/repo/kaname/pg/role_withdrawal_repo.go", []byte(withdrawalMarkSrc))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if roleWithdrawalFinding(nil, mark) {
		t.Fatal("производитель без приведения применителя объявлен находкой")
	}
}

// TestWithdrawal_SilentOnReadOnlyLive — `live` в WHERE не производитель.
func TestWithdrawal_SilentOnReadOnlyLive(t *testing.T) {
	t.Parallel()
	_, mark, census, err := check.ScanRoleWithdrawalWiring("internal/repo/kaname/pg/role_reader.go", []byte(withdrawalReadOnlySrc))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.WritesOverRoles != 0 {
		t.Fatalf("SELECT распознан как оператор записи: %+v", census)
	}
	if len(mark) != 0 {
		t.Errorf("чтение `live` в WHERE распознано производителем: %+v", mark)
	}
}

// TestWithdrawal_SilentOnItsOwnExplanation — комментарий, объясняющий сам
// предмет, не даёт ни приведения, ни производителя.
func TestWithdrawal_SilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	drive, mark, _, err := check.ScanRoleWithdrawalWiring("cmd/kaname/doc.go", []byte(withdrawalProseSrc))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(drive) != 0 || len(mark) != 0 {
		t.Errorf("гейт краснеет на КОММЕНТАРИИ, объясняющем предмет: drive=%+v mark=%+v", drive, mark)
	}
}

// TestWithdrawal_SelectorBindingFollowsAlias — обращение засчитывается по
// ПСЕВДОНИМУ импорта, а не по последнему сегменту пути.
func TestWithdrawal_SelectorBindingFollowsAlias(t *testing.T) {
	t.Parallel()
	src := `package main

import mr "github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"

func boot() {
	_ = mr.NewApplier(nil, nil)
}
`
	drive, _, census, err := check.ScanRoleWithdrawalWiring("cmd/kaname/serve.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.AppliedImports != 1 {
		t.Fatalf("импорт применителя не распознан: %+v", census)
	}
	if len(drive) != 1 {
		t.Fatalf("вызов через ПСЕВДОНИМ не распознан приведением: %+v", drive)
	}
	if !strings.Contains(drive[0].What, "NewApplier") {
		t.Errorf("находка не называет вызванную точку входа: %+v", drive[0])
	}
}
