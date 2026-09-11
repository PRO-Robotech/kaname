// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_role_row_is_never_deleted_injection_test.go — доказательство
// способности гейта упасть И смолчать (порт одноимённой пробы репозитория
// платформы, снят там вынесением службы доступа — `kacho#2597`).
//
// Инъекция снимает НОВОЕ свойство у элемента, чьё СТАРОЕ на месте: у
// настоящего оператора удаления дерева убирается сужение на пользовательскую
// роль.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// roleDeleteGuardedSrc — оператор дерева, каков он есть
// (`internal/repo/kaname/pg/role_repo.go`): сужен на пользовательскую роль.
const roleDeleteGuardedSrc = `package pg

func (w *roleWriter) Delete(ctx context.Context, id string) error {
	row := w.tx.QueryRow(ctx,
		` + "`DELETE FROM roles WHERE id = $1 AND is_system = false RETURNING 1`" + `, id)
	return row.Scan(new(int))
}
`

// roleDeleteUnguardedSrc — ТОТ ЖЕ оператор без сужения.
const roleDeleteUnguardedSrc = `package pg

func (w *roleWriter) Delete(ctx context.Context, id string) error {
	row := w.tx.QueryRow(ctx,
		` + "`DELETE FROM roles WHERE id = $1 RETURNING 1`" + `, id)
	return row.Scan(new(int))
}
`

// roleDeleteTierGuardSrc — второе ЗАКОННОЕ написание сужения.
const roleDeleteTierGuardSrc = `package pg

func (w *roleWriter) Delete(ctx context.Context, id string) error {
	row := w.tx.QueryRow(ctx,
		` + "`DELETE FROM kaname.roles WHERE id = $1 AND cluster_id IS NULL RETURNING 1`" + `, id)
	return row.Scan(new(int))
}
`

// roleDeleteProseSrc — законный близнец: тот же оператор словами.
const roleDeleteProseSrc = `package pg

import "errors"

// Прод-код НИКОГДА не производит DELETE FROM roles без сужения на
// пользовательскую роль: отзыв роли модуля — пометка, а не удаление строки.
var errNoSystemRoleDelete = errors.New("DELETE FROM roles здесь не производится безусловно")
`

// roleDeleteProjectionSrc — законный близнец: удаляется проекция, а не роль.
const roleDeleteProjectionSrc = `package pg

func (w *roleWriter) ReplaceRuleRefs(ctx context.Context, id string) error {
	_, err := w.tx.Exec(ctx, ` + "`DELETE FROM kaname.role_rule_ref WHERE role_id = $1`" + `, id)
	return err
}
`

func TestRoleDeleteGateStaysSilentOnTheGuardedStatement(t *testing.T) {
	t.Parallel()
	const rel = "internal/repo/kaname/pg/role_repo.go"
	sites, census, err := check.ScanRoleDeletes(rel, []byte(roleDeleteGuardedSrc))
	if err != nil {
		t.Fatalf("разбор контроля: %v", err)
	}
	if census.Statements != 1 {
		t.Fatalf("операторов удаления над `roles` прочитано %d из одного", census.Statements)
	}
	if census.Guarded != 1 {
		t.Fatalf("сужённых операторов прочитано %d из одного", census.Guarded)
	}
	if f := roleDeleteFindings(sites); len(f) != 0 {
		t.Fatalf("КОНТРОЛЬ: сужённый оператор объявлен находкой: %v", f)
	}
}

func TestRoleDeleteGateRedsOnAnUnguardedStatement(t *testing.T) {
	t.Parallel()
	const rel = "internal/repo/kaname/pg/role_repo.go"
	sites, census, err := check.ScanRoleDeletes(rel, []byte(roleDeleteUnguardedSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.Statements != 1 {
		t.Fatalf("операторов удаления прочитано %d из одного", census.Statements)
	}
	if census.Guarded != 0 {
		t.Fatalf("несужённый оператор зачтён сужённым: сужено %d", census.Guarded)
	}
	f := roleDeleteFindings(sites)
	if len(f) != 1 {
		t.Fatalf("несужённое удаление роли НЕ стало находкой: находок %d", len(f))
	}
	if !strings.Contains(f[0], rel) || !strings.Contains(f[0], "DELETE FROM roles") {
		t.Errorf("находка не называет ни координату, ни оператор: %q", f[0])
	}
}

func TestRoleDeleteGateKnowsBothGuardForms(t *testing.T) {
	t.Parallel()
	sites, census, err := check.ScanRoleDeletes("internal/repo/kaname/pg/role_repo.go",
		[]byte(roleDeleteTierGuardSrc))
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	if census.Statements != 1 || census.Guarded != 1 {
		t.Fatalf("прочитано операторов %d, сужено %d", census.Statements, census.Guarded)
	}
	if f := roleDeleteFindings(sites); len(f) != 0 {
		t.Fatalf("кластерный якорь как форма сужения объявлен находкой: %v", f)
	}
}

func TestRoleDeleteGateStaysSilentOnProse(t *testing.T) {
	t.Parallel()
	sites, census, err := check.ScanRoleDeletes("internal/repo/kaname/pg/doc.go",
		[]byte(roleDeleteProseSrc))
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	if census.Comments == 0 || census.StringLiterals == 0 {
		t.Fatalf("близнец беспредметен: комментариев %d, литералов %d",
			census.Comments, census.StringLiterals)
	}
	if census.Statements != 0 {
		t.Fatalf("проза о запрете прочитана как оператор: операторов %d", census.Statements)
	}
	if f := roleDeleteFindings(sites); len(f) != 0 {
		t.Fatalf("гейт судит текст, а не оператор: %v", f)
	}
}

func TestRoleDeleteGateStaysSilentOnProjectionDelete(t *testing.T) {
	t.Parallel()
	sites, census, err := check.ScanRoleDeletes("internal/repo/kaname/pg/role_repo.go",
		[]byte(roleDeleteProjectionSrc))
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	if census.StringLiterals == 0 {
		t.Fatalf("близнец беспредметен: литералов прочитано ноль")
	}
	if census.Statements != 0 {
		t.Fatalf("удаление ПРОЕКЦИИ прочитано как удаление роли: операторов %d", census.Statements)
	}
	if f := roleDeleteFindings(sites); len(f) != 0 {
		t.Fatalf("удаление проекции объявлено находкой: %v", f)
	}
}

// roleDeleteBareSrc — оператор БЕЗ условия вовсе.
const roleDeleteBareSrc = `package pg

func (w *roleWriter) wipe(ctx context.Context) error {
	_, err := w.tx.Exec(ctx, ` + "`DELETE FROM roles`" + `)
	return err
}
`

func TestRoleDeleteGateRedsOnAnUnconditionalStatement(t *testing.T) {
	t.Parallel()
	sites, census, err := check.ScanRoleDeletes("internal/repo/kaname/pg/role_repo.go",
		[]byte(roleDeleteBareSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.Statements != 1 {
		t.Fatalf("оператор без условия прочитан как НЕ оператор: операторов %d", census.Statements)
	}
	if f := roleDeleteFindings(sites); len(f) != 1 {
		t.Fatalf("безусловное удаление ролей НЕ стало находкой: находок %d", len(f))
	}
}
