// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// retired_type_refused_by_both_verbs_test.go — `IAM-SUC-04` ВЫЗОВОМ ОБОИХ
// ГЛАГОЛОВ (kacho#1814, приёмка
// `docs/engineering/acceptance/retired-resource-names-its-successor.md`, DoD п. 7).
//
// # Почему проба идёт через use-case, а не через `Rule.Validate`
//
// Соседняя доменная проба (`internal/domain/rule_retired_type_names_the_catalog_test.go`)
// зовёт проверку правила НАПРЯМУЮ: она закрепляет ОТВЕТ проверки и ничего не
// говорит о её МЕСТЕ. Готовность требует другого — что оба глагола роли отвечают
// одинаково, и порядок гейтов у правки СВОЙ (доменная проверка правила стоит
// раньше гейта грантуемости и в создании, и в правке — двумя отдельными строками
// кода). Совпадение порядка у двух глаголов есть свойство, а не данность, и
// утверждается только их вызовом.
//
// # Что различает эта проба
//
//   - ПОЛОСУ: отказ снятия называет слово `retired`. Гейт грантуемости тот же тип
//     тоже отверг бы (`compute.disk` живой строкой каталога не является) — кодом
//     `INVALID_ARGUMENT`, но ДРУГИМ текстом. Проба, спрашивающая только код,
//     зеленела бы на переставленном порядке;
//   - МОМЕНТ: отказ синхронный и раньше любой записи. Счётчик писателя стоит у
//     дублёра, и его способность считать доказана положительным контролем — живой
//     тип доходит до записи, иначе «записей ноль» было бы верно тривиально.
import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

const (
	sucRetiredModule   = "compute"
	sucRetiredResource = "disk"
	sucRetiredDotted   = sucRetiredModule + "." + sucRetiredResource
)

// writeCountingRepo — тот же дублёр, что у соседних проб правки, плюс счётчик
// открытых писателей. Больше он ничего не меняет: снисходительнее продукта он
// быть не должен.
type writeCountingRepo struct {
	*rlUpdRepo
	writers int
}

func (r *writeCountingRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	r.writers++
	return r.rlUpdRepo.Writer(ctx)
}

// liveSeedFacts — живые строки ПОСЕВА, тем же перечнем, которым каталог посеян.
func liveSeedFacts(t *testing.T) *catalog.Facts {
	t.Helper()
	f, err := catalog.NewFacts(catalog.Halves{Live: seed.LiteralRows()})
	if err != nil {
		t.Fatalf("снимок живых строк посева: %v", err)
	}
	return f
}

// requireRetiredRefusal — пара «код + текст» и отсутствие записи.
func requireRetiredRefusal(t *testing.T, verb string, err error, repo *writeCountingRepo) {
	t.Helper()
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("%s: правило над снятым %s не отвергнуто синхронно кодом INVALID_ARGUMENT "+
			"(получено %v): %v", verb, sucRetiredDotted, st.Code(), err)
	}
	for _, want := range []string{sucRetiredDotted, "retired", domain.CatalogEndpoint} {
		if !strings.Contains(st.Message(), want) {
			t.Errorf("%s: текст отказа не называет %q — отказ пришёл не той полосой "+
				"либо не называет, где узнать преемника: %s", verb, want, st.Message())
		}
	}
	if repo.writers != 0 {
		t.Errorf("%s: отказ вынесен ПОСЛЕ открытия писателя (открыто %d) — ключ базы "+
			"успел увидеть правило над снятым типом", verb, repo.writers)
	}
}

// TestIAMSUC04_CreateRoleRefusesRetiredTypeBeforeAnyWrite — создание роли.
func TestIAMSUC04_CreateRoleRefusesRetiredTypeBeforeAnyWrite(t *testing.T) {
	if !domain.IsRetiredType(sucRetiredDotted) {
		t.Fatalf("предпосылка: %s не в доменном словаре снятого — проба была бы "+
			"о другой полосе", sucRetiredDotted)
	}

	// Положительный контроль ПЕРВЫМ: живой тип тем же путём доходит до записи.
	live := &writeCountingRepo{rlUpdRepo: newRlUpdRepo(domain.Labels{})}
	op, err := NewCreateRoleUseCase(live, newRlFakeOps(), catalog.Fixed{F: liveSeedFacts(t)}).
		Execute(authnCtx(), domain.Role{
			AccountID: "acc0000000000000abcd",
			Name:      "live_control_role",
			Rules: domain.Rules{
				{Module: sucRetiredModule, Resources: []string{"instance"}, Verbs: []string{"get"}},
			},
		})
	if err != nil || op == nil {
		t.Fatalf("живой контроль compute.instance не принят (%v) — отрицание ниже "+
			"неотличимо от «отвергается всё»", err)
	}
	waitOps(t)
	if live.writers == 0 {
		t.Fatal("живой контроль не открыл ни одного писателя — счётчик не считает, " +
			"и «записей ноль» ниже было бы верно тривиально")
	}

	retired := &writeCountingRepo{rlUpdRepo: newRlUpdRepo(domain.Labels{})}
	op, err = NewCreateRoleUseCase(retired, newRlFakeOps(), catalog.Fixed{F: liveSeedFacts(t)}).
		Execute(authnCtx(), domain.Role{
			AccountID: "acc0000000000000abcd",
			Name:      "retired_type_role",
			Rules: domain.Rules{
				{Module: sucRetiredModule, Resources: []string{sucRetiredResource}, Verbs: []string{"get"}},
			},
		})
	if op != nil {
		t.Fatalf("создание: на снятом типе вернулась Operation — отказ не синхронный")
	}
	requireRetiredRefusal(t, "создание", err, retired)
}

// TestIAMSUC04_UpdateRoleRefusesRetiredTypeBeforeAnyWrite — правка роли тем же
// правилом. Порядок гейтов у правки свой, поэтому утверждается отдельно.
func TestIAMSUC04_UpdateRoleRefusesRetiredTypeBeforeAnyWrite(t *testing.T) {
	live := &writeCountingRepo{rlUpdRepo: newRlUpdRepo(domain.Labels{})}
	_, err := NewUpdateRoleUseCase(live, newRlFakeOps(), catalog.Fixed{F: liveSeedFacts(t)}).
		Execute(ownerCtx(), UpdateRoleInput{
			ID: rlUpdRoleID,
			Rules: domain.Rules{
				{Module: sucRetiredModule, Resources: []string{"instance"}, Verbs: []string{"get"}},
			},
			UpdateMask: []string{"rules"},
		})
	if err != nil {
		t.Fatalf("живой контроль: правка на compute.instance отвергнута (%v) — "+
			"отрицание ниже неотличимо от «отвергается всё»", err)
	}
	waitOps(t)
	if live.writers == 0 {
		t.Fatal("живой контроль не открыл ни одного писателя — счётчик не считает")
	}

	retired := &writeCountingRepo{rlUpdRepo: newRlUpdRepo(domain.Labels{})}
	op, err := NewUpdateRoleUseCase(retired, newRlFakeOps(), catalog.Fixed{F: liveSeedFacts(t)}).
		Execute(ownerCtx(), UpdateRoleInput{
			ID: rlUpdRoleID,
			Rules: domain.Rules{
				{Module: sucRetiredModule, Resources: []string{sucRetiredResource}, Verbs: []string{"get"}},
			},
			UpdateMask: []string{"rules"},
		})
	if op != nil {
		t.Fatalf("правка: на снятом типе вернулась Operation — отказ не синхронный")
	}
	requireRetiredRefusal(t, "правка", err, retired)
}
