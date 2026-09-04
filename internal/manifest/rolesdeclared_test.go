// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// rolesdeclared_test.go — ОБЪЯВЛЕННОСТЬ раздела `roles` доезжает до
// применителя ЗНАЧЕНИЕМ (приёмка
// `services/iam/docs/engineering/acceptance/role-withdrawal-has-a-producer.md`
// §2.2, сценарии IAM-RW-1-09 и -24; задача продукта #1913).
//
// # Почему это не педантизм, а предмет
//
// Состояний у раздела ТРИ, и дерево это уже решило — `linkage.go`, комментарий
// `roleIDs`: «раздел не объявлен · объявлен и пуст · объявлен с перечнем».
// Первое означает «сверять не с чем», второе — «автор сказал, что ролей у него
// нет».
//
// Дискриминатор существовал и НЕ ДОЕЗЖАЛ: `roleIDs.declared` не экспортирован,
// наружу выходил только переписью (`LinkageCensus.RolesDeclared`), а применитель
// получает `*manifest.Manifest`, у которого `Roles` — обычный срез. Значит
// «ключа `roles:` нет» и «`roles: []`» давали `len == 0` и были неразличимы.
//
// Цена прямая и наступает при отзыве: манифест, потерявший ключ `roles:`
// (правка соседнего раздела, съехавший отступ, обрезанная доставка), снял бы
// ВСЕ роли модуля — то самое, от чего защищает решение «отсутствие файла
// манифеста снятием НЕ является». Отличить это от намеренного «ролей у меня
// нет» нечем by construction, пока объявленность не доехала значением.
package manifest_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// TestRolesDeclaredDistinguishesTheThreeStatesOfTheSection — три состояния и
// два положительных контроля.
//
// Отрицание («раздел не объявлен») стоит В ПАРЕ с обоими положительными: без
// них проба зеленела бы на загрузчике, у которого объявленность ложна ВСЕГДА,
// и утверждала бы о нём ничего.
func TestRolesDeclaredDistinguishesTheThreeStatesOfTheSection(t *testing.T) {
	const head = "apiVersion: iam/v1\nmodule: vpc\n"

	cases := []struct {
		name         string
		doc          string
		wantDeclared bool
		wantLen      int
	}{
		{
			name:         "ключа roles нет — раздел НЕ объявлен",
			doc:          head,
			wantDeclared: false,
			wantLen:      0,
		},
		{
			name:         "roles: [] — объявлен и ПУСТ",
			doc:          head + "roles: []\n",
			wantDeclared: true,
			wantLen:      0,
		},
		{
			name: "roles с перечнем — объявлен",
			doc: head + "roles:\n" +
				"  - id: vpc.probe1913.admin\n" +
				"    description: Роль пробы.\n" +
				"    tier: {tierType: iam.cluster, tierId: cluster_kacho_root}\n" +
				"    rules:\n" +
				"      - {module: vpc, resources: [network], classes: [get]}\n",
			wantDeclared: true,
			wantLen:      1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := manifest.Load([]byte(tc.doc))
			if err != nil {
				t.Fatalf("манифест не загружен: %v — проба беспредметна", err)
			}
			if got := m.RolesDeclared(); got != tc.wantDeclared {
				t.Errorf("объявленность раздела: получено %t, ожидалось %t — "+
					"применитель не отличит «раздела нет» от «раздел пуст», и "+
					"манифест, потерявший ключ, снимет ВСЕ роли модуля (kacho#1913)",
					got, tc.wantDeclared)
			}
			if got := len(m.Roles); got != tc.wantLen {
				t.Errorf("ролей разобрано %d, ожидалось %d", got, tc.wantLen)
			}
		})
	}
}

// TestRolesDeclaredIsFalseOnlyWhenTheKeyIsAbsent — премиса пары выше: пустой
// перечень и отсутствующий ключ дают ОДНУ длину, и потому длина различителем
// быть не может.
//
// Проба утверждает именно это — что различает не длина. Без неё «объявленность»
// выглядела бы производной от `len(Roles)`, и следующий читатель снял бы поле
// как избыточное.
func TestRolesDeclaredIsFalseOnlyWhenTheKeyIsAbsent(t *testing.T) {
	const head = "apiVersion: iam/v1\nmodule: vpc\n"

	absent, err := manifest.Load([]byte(head))
	if err != nil {
		t.Fatalf("манифест без раздела не загружен: %v", err)
	}
	empty, err := manifest.Load([]byte(head + "roles: []\n"))
	if err != nil {
		t.Fatalf("манифест с пустым разделом не загружен: %v", err)
	}

	if len(absent.Roles) != len(empty.Roles) {
		t.Fatalf("длины разошлись (%d против %d) — премиса пробы исчезла: "+
			"если длина различает, поле объявленности не нужно",
			len(absent.Roles), len(empty.Roles))
	}
	if absent.RolesDeclared() == empty.RolesDeclared() {
		t.Fatalf("при РАВНОЙ длине объявленность одинакова (%t) — состояния "+
			"схлопнуты, и снятие всех ролей неотличимо от намеренно пустого раздела",
			absent.RolesDeclared())
	}
}
