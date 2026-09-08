// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// delete_revoke_producer_injection_test.go — доказательство, что гейт симметрии
// снятия (kacho#2055) СПОСОБЕН упасть и что он молчит на законных близнецах.
//
// Инъекция идёт НАСТОЯЩИМ входом гейта — исходниками Go, которые он разбирает, —
// а не подделкой его результата. По каждой оси названы обе стороны: дефект
// обязан находиться, законный близнец обязан молчать.
//
// # Оси и их близнецы
//
//  1. отсутствие отзыва — находка; наличие — молчание;
//  2. форма записи вида события: гейт знает ОБЕ (именованная константа и её
//     строковое значение). Знай он одну, половина дерева ушла бы из наблюдения
//     не нарушением, а невидимостью;
//  3. ЧУЖОЙ тип отзывом своего не считается: пакет, эмитирующий upsert на свой
//     тип и delete на соседний, — находка;
//  4. каталог БЕЗ пути снятия в популяцию не входит: снимать нечего;
//  5. каталог, чей единственный upsert идёт на ЧУЖОЙ тип, своего типа не имеет и
//     не судится вовсе;
//  6. имя в КОММЕНТАРИИ и в строковом литерале эмиссией не является — ровно та
//     форма, на которой проверка по подстроке зеленела бы при неработающем
//     снятии.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// srcCreateUpsert — создание со-коммитит событие вида upsert на свой тип.
const srcCreateUpsert = `package role

func create(ctx C, w W, id string) error {
	return w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.role", id)
}
`

// srcDeleteNoEmit — ДЕФЕКТ оси 1: снятие есть, отзыва нет.
const srcDeleteNoEmit = `package role

func doDelete(ctx C, w W, id string) error {
	return w.RolesW().Delete(ctx, id)
}
`

// srcDeleteEmitConst — ЗАКОННЫЙ БЛИЗНЕЦ оси 1 и ось 2 (именованная константа).
const srcDeleteEmitConst = `package role

func doDelete(ctx C, w W, id string) error {
	if err := w.RolesW().Delete(ctx, id); err != nil {
		return err
	}
	return w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.role", id)
}
`

// srcDeleteEmitLiteral — ось 2, вторая законная форма: вид назван строкой.
const srcDeleteEmitLiteral = `package role

func doDelete(ctx C, w W, id string) error {
	return w.EmitReconcileEvent(ctx, "mirror.delete", "iam.role", id)
}
`

// srcDeleteEmitForeignType — ДЕФЕКТ оси 3: отзыв эмитируется на ЧУЖОЙ тип.
const srcDeleteEmitForeignType = `package role

func doDelete(ctx C, w W, id string) error {
	return w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.accessBinding", id)
}
`

// srcOnlyForeignUpsert — ось 5: свой тип не выводится, каталог не судится.
const srcOnlyForeignUpsert = `package role

func invite(ctx C, w W, id string) error {
	return w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.accessBinding", id)
}
`

// srcDeleteOnlyMentioned — ДЕФЕКТ оси 6: имена есть в комментарии и в строке,
// вызова нет. Проверка по подстроке молчала бы здесь при неработающем снятии.
const srcDeleteOnlyMentioned = `package role

// EmitReconcileEvent со значением "mirror.delete" на "iam.role" здесь обязателен,
// но пока не провязан.
func doDelete(ctx C, w W, id string) error {
	return errors.New("EmitReconcileEvent не провязан: mirror.delete на iam.role")
}
`

// plantDir складывает синтетический каталог use-case.
func plantDir(t *testing.T, apiDir, name string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(apiDir, name)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for fn, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fn), []byte(body), 0o600))
	}
}

func TestDeleteRevokeProducerGateCanFail(t *testing.T) {
	cases := []struct {
		name       string
		files      map[string]string
		wantFind   bool
		wantPop    int
		wantOwned  int
		wantReason string
	}{
		{
			name:       "ось 1 дефект: снятие без отзыва — находка",
			files:      map[string]string{"create.go": srcCreateUpsert, "delete.go": srcDeleteNoEmit},
			wantFind:   true,
			wantPop:    1,
			wantOwned:  1,
			wantReason: "отсутствие производителя обязано находиться",
		},
		{
			name:       "ось 1 близнец: отзыв именованной константой — молчание",
			files:      map[string]string{"create.go": srcCreateUpsert, "delete.go": srcDeleteEmitConst},
			wantFind:   false,
			wantPop:    1,
			wantOwned:  1,
			wantReason: "законная форма обязана молчать, иначе гейт отключат первым",
		},
		{
			name:       "ось 2 близнец: вид события назван СТРОКОЙ — молчание",
			files:      map[string]string{"create.go": srcCreateUpsert, "delete.go": srcDeleteEmitLiteral},
			wantFind:   false,
			wantPop:    1,
			wantOwned:  1,
			wantReason: "распознаватель обязан знать обе законные формы записи вида события",
		},
		{
			name:       "ось 3 дефект: отзыв на ЧУЖОЙ тип своим не считается",
			files:      map[string]string{"create.go": srcCreateUpsert, "delete.go": srcDeleteEmitForeignType},
			wantFind:   true,
			wantPop:    1,
			wantOwned:  1,
			wantReason: "отзыв соседнего типа не отзывает свой объект",
		},
		{
			name:       "ось 4: каталог без пути снятия в популяцию не входит",
			files:      map[string]string{"create.go": srcCreateUpsert},
			wantFind:   false,
			wantPop:    0,
			wantOwned:  1,
			wantReason: "снимать нечего — требовать отзыва не с чего",
		},
		{
			name:       "ось 5: только ЧУЖОЙ upsert — свой тип не выводится",
			files:      map[string]string{"invite.go": srcOnlyForeignUpsert, "delete.go": srcDeleteNoEmit},
			wantFind:   false,
			wantPop:    0,
			wantOwned:  0,
			wantReason: "пакет, не материализующий свой тип, этим гейтом не судится",
		},
		{
			name:       "ось 6 дефект: имена в комментарии и в строке — не эмиссия",
			files:      map[string]string{"create.go": srcCreateUpsert, "delete.go": srcDeleteOnlyMentioned},
			wantFind:   true,
			wantPop:    1,
			wantOwned:  1,
			wantReason: "проверка по подстроке зеленела бы на собственном объяснении",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiDir := t.TempDir()
			plantDir(t, apiDir, "role", tc.files)

			census, findings, err := check.ScanDeleteRevokeProducers(apiDir)
			require.NoError(t, err)
			t.Log(census.String())

			require.Equal(t, tc.wantOwned, census.OwnTyped,
				"вывод своего типа: %s", tc.wantReason)
			require.Equal(t, tc.wantPop, census.Population,
				"популяция: %s", tc.wantReason)
			if tc.wantFind {
				require.NotEmpty(t, findings, "дефект обязан находиться: %s", tc.wantReason)
				require.Contains(t, findings[0], "role", "находка обязана называть каталог")
			} else {
				require.Empty(t, findings, "законный близнец обязан молчать: %s", tc.wantReason)
			}
		})
	}
}

// TestDeleteRevokeProducerScanRefusesAnAbsentTree — обход, которому нечего
// читать, обязан быть ОТКАЗОМ, а не тихим нулём находок.
func TestDeleteRevokeProducerScanRefusesAnAbsentTree(t *testing.T) {
	_, _, err := check.ScanDeleteRevokeProducers(filepath.Join(t.TempDir(), "нет-такого"))
	require.Error(t, err, "несуществующий каталог обязан быть отказом обхода, а не пустым успехом")
}
