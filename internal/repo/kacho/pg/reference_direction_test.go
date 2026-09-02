// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// reference_direction_test.go — отказ по ссылке между ресурсами называет ОДНО
// состояние, а не два взаимоисключающих.
//
// ПРЕДМЕТ. Общий текст неразобранного внешнего ключа звучал как «referenced
// resource not found or still in use» — то есть объединял два ПРОТИВОПОЛОЖНЫХ
// состояния. Первое лечится созданием ссылаемого ресурса, второе —
// освобождением ссылок; вызывающий выбрать не мог, потому что ни текста, ни
// признака, ни кода, различающих их, у него не было. Отказ, объединяющий
// взаимоисключающие причины, следующего шага не восстанавливает **by
// construction**: любой выбранный шаг верен ровно в половине случаев.
//
// ЧЕМ РАЗЛИЧАЮТСЯ. Направление нарушения знает вызывающий репозиторий, и он же
// уже сообщает его подсказкой `<Ресурс>.<Глагол>` — на ней построены все
// разобранные ветви (`Account.Delete`, `Role.Delete`, …). Общая ветвь читает ту
// же подсказку: глагол снятия означает сторону ССЫЛАЮЩИХСЯ (ресурс ещё
// используется), всё прочее — сторону ССЫЛКИ (ссылаемого ресурса нет).
// Доказывает исполнимость этого различения гейт `delete_hint_test.go`: метод
// репозитория, снимающий строку, обязан подсказку передавать.

import (
	stderrors "errors"
	"strings"
	"testing"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// mergedRefusal — форма, ради снятия которой написана эта проба. Держится
// здесь дословно, чтобы возвращение объединяющего текста краснело по имени.
const mergedRefusal = "not found or still in use"

func TestUnmappedForeignKeyNamesOneStateNotTwo(t *testing.T) {
	const unmapped = "some_table_some_other_fk"

	t.Run("сторона ссылки — ссылаемого ресурса нет", func(t *testing.T) {
		err := wrapPgErr(mkPgErr("23503", unmapped), "", "prj_x")
		if !stderrors.Is(err, iamerr.ErrReferenceMissing) {
			t.Fatalf("признак = %v; ожидался ErrReferenceMissing", err)
		}
		// Тот же отказ обязан оставаться отказом ПРЕДУСЛОВИЯ: код не меняется,
		// меняется только различимость. Иначе правка была бы ломающей.
		if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
			t.Fatalf("отказ перестал быть предусловием: %v", err)
		}
		text := iamerr.StripSentinel(err)
		if strings.Contains(text, mergedRefusal) {
			t.Fatalf("текст по-прежнему объединяет два состояния: %q", text)
		}
		if !strings.Contains(text, "does not exist") {
			t.Errorf("текст не называет состояние «ссылаемого нет»: %q", text)
		}
		assertNoLeak(t, text)
	})

	t.Run("сторона ссылающихся — ресурс ещё используется", func(t *testing.T) {
		err := wrapPgErr(mkPgErr("23503", unmapped), "Project.Delete", "prj_x")
		if !stderrors.Is(err, iamerr.ErrReferenceInUse) {
			t.Fatalf("признак = %v; ожидался ErrReferenceInUse", err)
		}
		if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
			t.Fatalf("отказ перестал быть предусловием: %v", err)
		}
		text := iamerr.StripSentinel(err)
		if strings.Contains(text, mergedRefusal) {
			t.Fatalf("текст по-прежнему объединяет два состояния: %q", text)
		}
		if !strings.Contains(text, "still referenced") {
			t.Errorf("текст не называет состояние «ещё используется»: %q", text)
		}
		assertNoLeak(t, text)
	})

	t.Run("два состояния дают РАЗНЫЕ тексты", func(t *testing.T) {
		missing := iamerr.StripSentinel(wrapPgErr(mkPgErr("23503", unmapped), "", "prj_x"))
		inUse := iamerr.StripSentinel(wrapPgErr(mkPgErr("23503", unmapped), "Project.Delete", "prj_x"))
		if missing == inUse {
			t.Fatalf("оба состояния отвечают одним текстом %q — предмет пробы не снят", missing)
		}
	})
}

// TestMappedForeignKeyTextsAreUnchanged — положительный контроль. Без него
// отрицания выше зеленели бы на отказе, потерявшем ВСЕ свои тексты: тон
// сообщения есть часть контракта, и разбор направления не вправе его тронуть.
func TestMappedForeignKeyTextsAreUnchanged(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		kindHint   string
		idHint     string
		want       string
		wantErr    error
	}{
		{"владелец аккаунта не найден", "accounts_owner_fk", "", "usr_1", "User usr_1 not found", iamerr.ErrReferenceMissing},
		{"аккаунт со проектами", "projects_account_fk", "Account.Delete", "acc_1", "Account acc_1 contains projects and cannot be deleted", iamerr.ErrReferenceInUse},
		{"аккаунт для проекта не найден", "projects_account_fk", "", "acc_1", "Account acc_1 not found", iamerr.ErrReferenceMissing},
		{"роль занята выдачами", "access_bindings_role_fk", "Role.Delete", "", "role is in use by access bindings", iamerr.ErrReferenceInUse},
		{"роль не найдена", "access_bindings_role_fk", "", "rol_1", "Role rol_1 not found", iamerr.ErrReferenceMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := wrapPgErr(mkPgErr("23503", c.constraint), c.kindHint, c.idHint)
			if got := iamerr.StripSentinel(err); got != c.want {
				t.Errorf("текст = %q; контракт-тон = %q", got, c.want)
			}
			if !stderrors.Is(err, c.wantErr) {
				t.Errorf("признак = %v; ожидался %v", err, c.wantErr)
			}
			if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
				t.Errorf("отказ перестал быть предусловием: %v", err)
			}
		})
	}
}
