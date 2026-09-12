// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// grant_removal_trace_injection_test.go — доказательство способности
// храповика упасть и смолчать (IAM-RM-1-12).
//
// Вход подаётся СИНТЕТИКОЙ, а не правкой дерева: писать в файлы репозитория,
// из которого запущена проба, запрещено. Граница отсюда следует и названа
// честно: инъекция не говорит НИЧЕГО о том, производит ли дерево предмет
// сегодня — это утверждает сам гейт своей переписью
// (`grant_removal_trace_test.go`).
//
// Оси — каждая с обеими сторонами:
//
//	перебор     лишний файл без следа → находка С ИМЕНЕМ; без него → молчание
//	след        тот же файл СО следом → молчание (половина предиката различает)
//	половина    удаление в ОТКАТНОЙ половине → не считается (снимает свою вставку)
//	маска       оператор в комментарии и в литерале → не считается
//	терпимость  иное написание того же оператора → считается
//	недобор     текст находки требует сознательного движения храповика ВНИЗ
package migrations_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// base — прощённые сегодня, минимальные тела, несущие ровно предмет. Их РОВНО
// столько, сколько объявляет храповик: при нуле база пуста, и все оси ниже
// остаются осмысленными, потому что каждая считает ОТНОСИТЕЛЬНО базы.
func grantRemovalBase() []migrations.GrantMigrationSource {
	out := make([]migrations.GrantMigrationSource, 0, migrations.GrantRemovalRatchet)
	for i := 0; i < migrations.GrantRemovalRatchet; i++ {
		out = append(out, migrations.GrantMigrationSource{
			Name: fmt.Sprintf("00%02d_retire.sql", i),
			Body: "-- +goose Up\nDELETE FROM kaname.access_bindings WHERE role_id = 'r';\n" +
				"-- +goose Down\nSELECT 1;\n",
		})
	}
	return out
}

func TestGrantRemovalTraceGateInjection(t *testing.T) {
	// КОНТРОЛЬ: корпус, каким гейт его застаёт, — молчание и непустая перепись.
	silent, c := migrations.AuditGrantRemovalTrace(grantRemovalBase())
	if len(silent) != migrations.GrantRemovalRatchet {
		t.Fatalf("контроль: ожидалось %d прощённых, получено %d (%v)",
			migrations.GrantRemovalRatchet, len(silent), silent)
	}
	if c.FilesRead != migrations.GrantRemovalRatchet || c.WithDelete != migrations.GrantRemovalRatchet ||
		c.InUpHalf != migrations.GrantRemovalRatchet {
		t.Fatalf("контроль: перепись (%+v) разошлась с базой в %d файлов — «ноль находок» "+
			"стало бы неотличимо от «ноль прочитанного»", c, migrations.GrantRemovalRatchet)
	}

	// ОСЬ «перебор»: седьмой файл, снимающий выдачи без следа.
	over := append(grantRemovalBase(), migrations.GrantMigrationSource{
		Name: "0099_seventh.sql",
		Body: "-- +goose Up\nDELETE FROM kaname.access_bindings WHERE subject_id = 's';\n" +
			"-- +goose Down\nSELECT 1;\n",
	})
	got, _ := migrations.AuditGrantRemovalTrace(over)
	if len(got) != migrations.GrantRemovalRatchet+1 {
		t.Errorf("перебор: ожидалось %d, получено %d (%v)", migrations.GrantRemovalRatchet+1, len(got), got)
	}
	msg := migrations.GrantRemovalFinding(len(got), got)
	if !strings.Contains(msg, "0099_seventh.sql") {
		t.Errorf("перебор: находка не НАЗЫВАЕТ виновника: %s", msg)
	}
	if !strings.Contains(msg, "стало больше") {
		t.Errorf("перебор: находка не отличает перебор от недобора: %s", msg)
	}

	// ОСЬ «след»: ТОТ ЖЕ файл, но со следом в журнале, находкой не является.
	traced := append(grantRemovalBase(), migrations.GrantMigrationSource{
		Name: "0099_seventh.sql",
		Body: "-- +goose Up\nDELETE FROM kaname.access_bindings WHERE subject_id = 's';\n" +
			"INSERT INTO kaname.audit_outbox (event_type) VALUES ('AccessBindingDeleted');\n" +
			"-- +goose Down\nSELECT 1;\n",
	})
	got, _ = migrations.AuditGrantRemovalTrace(traced)
	if len(got) != migrations.GrantRemovalRatchet {
		t.Errorf("след: удаление СО следом посчитано находкой — половина предиката "+
			"«без записи в журнал» не различает: %v", got)
	}

	// ОСЬ «недобор»: текст находки требует двигать храповик ВНИЗ сознательно.
	if migrations.GrantRemovalRatchet > 0 {
		under := grantRemovalBase()
		under[0].Body = "-- +goose Up\nDELETE FROM kaname.access_bindings WHERE role_id = 'r';\n" +
			"INSERT INTO kaname.audit_outbox (event_type) VALUES ('AccessBindingDeleted');\n" +
			"-- +goose Down\nSELECT 1;\n"
		got, _ = migrations.AuditGrantRemovalTrace(under)
		if len(got) != migrations.GrantRemovalRatchet-1 {
			t.Errorf("недобор: ожидалось %d, получено %d (%v)", migrations.GrantRemovalRatchet-1, len(got), got)
		}
	}
	msg = migrations.GrantRemovalFinding(migrations.GrantRemovalRatchet-1, []string{"0000_retire.sql"})
	if !strings.Contains(msg, "стало меньше") || !strings.Contains(msg, "СОЗНАТЕЛЬНО") {
		t.Errorf("недобор: находка не требует сознательного движения храповика: %s", msg)
	}

	// ОСЬ «половина»: законный близнец — удаление в ОТКАТНОЙ половине. Такая
	// миграция снимает СВОЮ ЖЕ вставку, откатываясь, и доступа не отбирает.
	twin := append(grantRemovalBase(), migrations.GrantMigrationSource{
		Name: "0100_rollback_only.sql",
		Body: "-- +goose Up\nINSERT INTO kaname.access_bindings (id) VALUES ('b1');\n" +
			"-- +goose Down\nDELETE FROM kaname.access_bindings WHERE id = 'b1';\n",
	})
	got, ctwin := migrations.AuditGrantRemovalTrace(twin)
	if len(got) != migrations.GrantRemovalRatchet {
		t.Errorf("половина: откатное удаление посчитано снятием: %v", got)
	}
	if ctwin.WithDelete != migrations.GrantRemovalRatchet+1 || ctwin.InUpHalf != migrations.GrantRemovalRatchet {
		t.Errorf("половина: перепись не различает «где угодно» и «в накатной половине»: %+v", ctwin)
	}

	// ОСЬ «маска»: оператор, названный ПРОЗОЙ и ЛИТЕРАЛОМ, снятием не является.
	prose := append(grantRemovalBase(), migrations.GrantMigrationSource{
		Name: "0101_prose.sql",
		Body: "-- +goose Up\n" +
			"-- Здесь НЕ делается DELETE FROM kaname.access_bindings — выдачи остаются.\n" +
			"SELECT 'DELETE FROM kaname.access_bindings' AS explanation;\n" +
			"-- +goose Down\nSELECT 1;\n",
	})
	got, cprose := migrations.AuditGrantRemovalTrace(prose)
	if len(got) != migrations.GrantRemovalRatchet {
		t.Errorf("маска: проза и литерал посчитаны оператором: %v", got)
	}
	if cprose.WithDelete != migrations.GrantRemovalRatchet {
		t.Errorf("маска: перепись посчитала прозу удалением: %+v", cprose)
	}

	// ОСЬ «терпимость»: то же снятие, записанное иначе.
	spelling := append(grantRemovalBase(), migrations.GrantMigrationSource{
		Name: "0102_other_spelling.sql",
		Body: "-- +goose Up\ndelete\n  from   kaname . access_bindings\n where id = 'x';\n" +
			"-- +goose Down\nSELECT 1;\n",
	})
	got, _ = migrations.AuditGrantRemovalTrace(spelling)
	if len(got) != migrations.GrantRemovalRatchet+1 {
		t.Errorf("терпимость: иное написание оператора не узнано: %v", got)
	}
}

// TestGrantRoleReassignmentDiscriminatorCutsBothWays — доказательство того,
// что разбор переноса судит ПРИСВАИВАНИЯ, а не весь оператор (IAM-RM-1-13).
func TestGrantRoleReassignmentDiscriminatorCutsBothWays(t *testing.T) {
	corpus := []migrations.GrantMigrationSource{
		// ЛОВИТСЯ: role_id стоит среди присваиваний.
		{Name: "0200_move.sql", Body: "-- +goose Up\n" +
			"UPDATE kaname.access_bindings SET role_id = 'rol-new' WHERE role_id = 'rol-old';\n" +
			"-- +goose Down\nSELECT 1;\n"},
		// МОЛЧИТ: role_id только в условии отбора — это мягкий отзыв, а не перенос.
		{Name: "0201_soft_revoke.sql", Body: "-- +goose Up\n" +
			"UPDATE kaname.access_bindings\n   SET status = 'REVOKED', revoked_at = now()\n" +
			" WHERE role_id = 'rol-old' AND revoked_at IS NULL;\n" +
			"-- +goose Down\nSELECT 1;\n"},
		// МОЛЧИТ: перенос в ОТКАТНОЙ половине — миграция откатывает свою же правку.
		{Name: "0202_rollback_move.sql", Body: "-- +goose Up\nSELECT 1;\n" +
			"-- +goose Down\nUPDATE kaname.access_bindings SET role_id = 'rol-old';\n"},
		// МОЛЧИТ: перенос, названный ПРОЗОЙ и ЛИТЕРАЛОМ.
		{Name: "0203_prose.sql", Body: "-- +goose Up\n" +
			"-- Переносить нельзя: UPDATE kaname.access_bindings SET role_id = …\n" +
			"SELECT 'UPDATE kaname.access_bindings SET role_id = x' AS explanation;\n" +
			"-- +goose Down\nSELECT 1;\n"},
	}

	moves, statements := migrations.AuditGrantRoleReassignment(corpus)
	if len(moves) != 1 || moves[0] != "0200_move.sql" {
		t.Errorf("разбор судит не присваивания: ожидалось [0200_move.sql], получено %v", moves)
	}
	if statements != 2 {
		t.Errorf("перепись прочитала %d операторов вместо 2 — «ноль переносов» стало бы "+
			"неотличимо от «ноль прочитанного»", statements)
	}
}
