// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_operation_response_state_injection_test.go — доказательство того, что
// гейт «ответ операции над ролью не несёт вычисленного состояния» способен
// упасть и способен смолчать.
//
// Порт одноимённой пробы репозитория платформы, снят там вынесением службы —
// `kacho#2597`. Дословно: все семь осей.
// Изменилось только: пакет (`repohygiene` → `check_test`, экспортированные
// имена — `check.Xxx`), `ServiceRoot` пуст (синтетическое дерево кладётся
// прямо в корень t.TempDir(), а не под services/iam).
//
// Вход НАСТОЯЩИЙ по форме и синтетический по содержанию: дерево собирается в
// t.TempDir(), поэтому вердикт не зависит ни от состояния репозитория, ни от
// порядка прогонов. Каждая ось двигает РОВНО ОДИН факт против положительного
// близнеца, и близнец стоит ПЕРВЫМ.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func roleOpStateInjOptions(t *testing.T, src string) check.RoleOperationResponseStateOptions {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "helpers.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("файл: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "helpers_test.go"),
		[]byte(roleOpStateInjTestFile), 0o600); err != nil {
		t.Fatalf("файл пробы: %v", err)
	}
	return check.RoleOperationResponseStateOptions{
		Root:             root,
		DomainPkg:        "domain",
		RoleType:         "Role",
		TransferFunc:     "Transfer",
		ProjectionMethod: "WithoutComputedState",
	}
}

const roleOpStateInjTestFile = `package role

func marshalRoleInFixture(r domain.Role) (*anypb.Any, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(r, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}
`

const roleOpStateInjSound = `package role

// marshalRole — переводчик роли: проекцию зовёт.
func marshalRole(r domain.Role) (*anypb.Any, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(r.WithoutComputedState(), &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

// marshalGroup — переводчик ЧУЖОГО ресурса: та же форма, другой тип.
func marshalGroup(g domain.Group) (*anypb.Any, error) {
	var dst *iamv1.Group
	if err := dto.Transfer(dto.FromTo(g, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

// doCreate — вызывающий, который перевод ДЕЛЕГИРУЕТ.
func (u *CreateRoleUseCase) doCreate(ctx context.Context, r domain.Role) (*anypb.Any, error) {
	return marshalRole(r)
}

// getRole — СИНХРОННОЕ чтение: состояние заполняет и обязано его нести.
func getRole(r domain.Role) (*iamv1.Role, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(r, &dst)); err != nil {
		return nil, err
	}
	return dst, nil
}
`

func roleOpStateInjRun(t *testing.T, src string) ([]check.RoleOperationResponseStateFinding, check.RoleOperationResponseStateCensus, error) {
	t.Helper()
	var log strings.Builder
	f, c, err := check.AuditRoleOperationResponseState(roleOpStateInjOptions(t, src), &log)
	t.Log(strings.TrimSpace(log.String()))
	return f, c, err
}

// TestRoleOperationResponseStateInjection — способность падать и молчать.
func TestRoleOperationResponseStateInjection(t *testing.T) {
	// ОСЬ 0 (положительный контроль, первым).
	f, c, err := roleOpStateInjRun(t, roleOpStateInjSound)
	if err != nil {
		t.Fatalf("законный близнец: анализатор не отработал: %v", err)
	}
	if len(f) != 0 {
		t.Fatalf("законный близнец: находок %d: %v", len(f), f)
	}
	if c.RoleTranslators != 1 {
		t.Fatalf("переводчиков роли %d, ожидался 1 — признак отбирает не то: чужой ресурс, "+
			"делегирующий вызывающий и синхронное чтение переводчиками не являются",
			c.RoleTranslators)
	}
	if c.AnypbFuncs != 3 {
		t.Fatalf("функций, возвращающих ответ операции, %d, ожидалось 3 — разбор результатов "+
			"разошёлся с деревом", c.AnypbFuncs)
	}
	if c.ProjectionCalled != 1 {
		t.Fatalf("зовущих проекцию %d, ожидался 1", c.ProjectionCalled)
	}

	// ОСЬ 1. Переводчик роли перестал звать проекцию.
	broken := strings.Replace(roleOpStateInjSound,
		"dto.FromTo(r.WithoutComputedState(), &dst)", "dto.FromTo(r, &dst)", 1)
	f, _, err = roleOpStateInjRun(t, broken)
	if err != nil {
		t.Fatalf("проекция снята: анализатор не отработал: %v", err)
	}
	if len(f) != 1 {
		t.Fatalf("проекция снята: находок %d, ожидалась 1: %v", len(f), f)
	}
	if !strings.Contains(f[0].String(), "helpers.go:") || !strings.Contains(f[0].Func, "marshalRole") {
		t.Fatalf("проекция снята: находка не называет координату и функцию: %s", f[0])
	}
	if f[0].Line == 0 {
		t.Fatal("проекция снята: находка без номера строки — координата неполна")
	}

	// ОСЬ 2. Проекция названа только в КОММЕНТАРИИ ВНУТРИ ТЕЛА.
	commented := strings.Replace(broken,
		"	var dst *iamv1.Role\n	if err := dto.Transfer(dto.FromTo(r, &dst)); err != nil {",
		"	// здесь полагалось бы звать WithoutComputedState(), но это ТЕКСТ, а не вызов\n"+
			"	var dst *iamv1.Role\n	if err := dto.Transfer(dto.FromTo(r, &dst)); err != nil {", 1)
	if commented == broken {
		t.Fatal("проекция в комментарии: фикстура не собралась — ось судит не то, что задумано")
	}
	f, _, err = roleOpStateInjRun(t, commented)
	if err != nil {
		t.Fatalf("проекция в комментарии: анализатор не отработал: %v", err)
	}
	if len(f) != 1 {
		t.Fatalf("проекция в комментарии: находок %d, ожидалась 1 — гейт зачёл упоминание "+
			"за вызов: %v", len(f), f)
	}

	// ОСЬ 3. Второй переводчик роли, в другом пакете и с приёмником.
	second := roleOpStateInjSound + `

func (rs *Resolver) marshalRole(role domain.Role) (*anypb.Any, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(role, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}
`
	f, c, err = roleOpStateInjRun(t, second)
	if err != nil {
		t.Fatalf("второй переводчик: анализатор не отработал: %v", err)
	}
	if len(f) != 1 {
		t.Fatalf("второй переводчик: находок %d, ожидалась 1: %v", len(f), f)
	}
	if f[0].Func != "(*Resolver).marshalRole" {
		t.Fatalf("второй переводчик: находка названа %q — приёмник потерян, и координата "+
			"не различает двух одноимённых", f[0].Func)
	}
	if c.RoleTranslators != 2 {
		t.Fatalf("второй переводчик: переводчиков %d, ожидалось 2", c.RoleTranslators)
	}

	// ОСЬ 4. Нарушение в ТЕСТОВОМ файле не судится.
	if c.Files != 1 {
		t.Fatalf("файлов прочитано %d, ожидался 1 — гейт читает тестовые файлы, и находки "+
			"в фикстурах станут неотличимы от находок в продукте", c.Files)
	}

	// ОСЬ 5. Пустой обход.
	empty := check.RoleOperationResponseStateOptions{
		Root:      t.TempDir(),
		DomainPkg: "domain", RoleType: "Role",
		TransferFunc: "Transfer", ProjectionMethod: "WithoutComputedState",
	}
	if _, _, err = check.AuditRoleOperationResponseState(empty, nil); err == nil {
		t.Fatal("пустое дерево: анализатор отработал успехом — обход пуст, вердикт беспредметен")
	}

	// ОСЬ 6. Дерево БЕЗ переводчиков роли.
	noRole := `package role

func marshalGroup(g domain.Group) (*anypb.Any, error) {
	var dst *iamv1.Group
	if err := dto.Transfer(dto.FromTo(g, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}
`
	f, c, err = roleOpStateInjRun(t, noRole)
	if err == nil {
		t.Fatalf("дерево без переводчиков роли: анализатор отработал успехом (находок %d) — "+
			"пустой предмет прочитан как «нарушений нет»", len(f))
	}
	if !strings.Contains(err.Error(), "переводчиков роли") {
		t.Fatalf("дерево без переводчиков роли: отказ не называет предмет: %v", err)
	}
	if c.Funcs == 0 {
		t.Fatal("дерево без переводчиков роли: разобрано ноль функций — отказ выше пришёл " +
			"от пустого обхода, а не от пустого предмета")
	}
}
