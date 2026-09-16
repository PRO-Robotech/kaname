// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hook_lane_reconciler_injection_test.go — доказательство способности гейта
// упасть И смолчать.
//
// Инъекция подаёт НАСТОЯЩИЙ вход — сборщик хуков в том виде, в каком он лежал на
// `kaname@5303cebd`: со своим построением реконсайлера и без параметра
// (kaname#116). Законные близнецы — те же формы записи там, где они законны.
package main

import (
	"strings"
	"testing"
)

// hookLaneDefectSrc — дефект дословно: свой экземпляр, параметра нет.
const hookLaneDefectSrc = `package main

import (
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func buildHooksMux(pool *pgxpool.Pool, catalogSource catalog.Source, logger *slog.Logger) http.Handler {
	provisionReconciler := reconcileapp.New(kanamepg.NewReconcileAdapter(pool, catalogSource), logger, catalogSource)
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kanameRepo, opsRepo).
		WithReconciler(provisionReconciler)
	return mux(userUpsert)
}
`

// hookLaneFixedSrc — он же после правки: экземпляр принимается параметром.
const hookLaneFixedSrc = `package main

import (
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func buildHooksMux(pool *pgxpool.Pool, bindingReconciler *reconcileapp.Reconciler, logger *slog.Logger) http.Handler {
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kanameRepo, opsRepo).
		WithReconciler(bindingReconciler)
	return mux(userUpsert)
}
`

// hookLaneRenamedAliasSrc — законный близнец: ТОТ ЖЕ дефект под ДРУГИМ
// псевдонимом импорта. Распознаватель читает псевдоним из объявления импорта,
// поэтому переименование его не обманывает — форма, о которой он не знал бы,
// давала бы МОЛЧАНИЕ, а не находку.
const hookLaneRenamedAliasSrc = `package main

import (
	rec "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func buildHooksMux(pool *pgxpool.Pool, logger *slog.Logger) http.Handler {
	own := rec.New(adapter, logger, catalogSource)
	return mux(own)
}
`

// hookLaneProseSrc — законный близнец: имя построения названо в КОММЕНТАРИИ и в
// СТРОКЕ, а вызова нет. Гейт судит узел разбора и обязан молчать — иначе он
// краснел бы на собственном объяснении.
const hookLaneProseSrc = `package main

import (
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

// Реконсайлер здесь НЕ строится: reconcileapp.New зовут в wiring.go, а сюда
// экземпляр приезжает параметром.
const why = "reconcileapp.New — второе построение было бы вторым решением"

func buildHooksMux(bindingReconciler *reconcileapp.Reconciler) http.Handler {
	return mux(bindingReconciler, why)
}
`

// TestHookLaneGateRedsOnItsOwnBuild — инъекция настоящим дефектом.
func TestHookLaneGateRedsOnItsOwnBuild(t *testing.T) {
	r, err := readHookLane("hooks_mux.go", []byte(hookLaneDefectSrc), "buildHooksMux")
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if r.Calls == 0 {
		t.Fatalf("перепись инъекции пуста — разбор ничего не прочитал, и его молчание "+
			"сказано ни о чём: %+v", r)
	}
	if len(r.Builds) != 1 {
		t.Fatalf("собственное построение НЕ опознано: построений %d при переписи %+v\n"+
			"Гейт, не краснеющий на дефекте, из которого он выведен, не удерживает ничего",
			len(r.Builds), r)
	}
	if r.AcceptsReconciler {
		t.Errorf("сборщик дефекта параметра не несёт, а разбор насчитал, что несёт: %+v", r)
	}
}

// TestHookLaneGateRedsUnderARenamedAlias — та же находка под другим псевдонимом.
func TestHookLaneGateRedsUnderARenamedAlias(t *testing.T) {
	r, err := readHookLane("hooks_mux.go", []byte(hookLaneRenamedAliasSrc), "buildHooksMux")
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if r.Alias != "rec" {
		t.Fatalf("псевдоним прочитан как %q вместо \"rec\" — распознаватель читает имя "+
			"пакета, а не объявление импорта, и переименование увело бы построение вне "+
			"наблюдения", r.Alias)
	}
	if len(r.Builds) != 1 {
		t.Fatalf("построение под псевдонимом %q не опознано: %+v", r.Alias, r)
	}
}

// TestHookLaneGateStaysSilentOnLegalTwins — гейт обязан молчать там, где форма
// законна.
func TestHookLaneGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Run("экземпляр принимается параметром", func(t *testing.T) {
		r, err := readHookLane("hooks_mux.go", []byte(hookLaneFixedSrc), "buildHooksMux")
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if len(r.Builds) != 0 {
			t.Fatalf("исправленный сборщик объявлен строящим: %+v", r)
		}
		if !r.AcceptsReconciler {
			t.Fatalf("параметр *Reconciler не опознан — тогда гейт не отличил бы «принимает» "+
				"от «не материализует вовсе»: %+v", r)
		}
	})

	t.Run("имя построения названо в комментарии и строке", func(t *testing.T) {
		r, err := readHookLane("hooks_mux.go", []byte(hookLaneProseSrc), "buildHooksMux")
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if len(r.Builds) != 0 {
			t.Fatalf("гейт судит подстроку, а не узел разбора: построений %d на файле БЕЗ "+
				"вызова — он краснел бы на собственном объяснении: %+v", len(r.Builds), r)
		}
		if !r.AcceptsReconciler {
			t.Fatalf("параметр не опознан на законном близнеце: %+v", r)
		}
	})

	t.Run("чужой пакет с тем же именем New", func(t *testing.T) {
		const src = `package main

import (
	other "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func buildHooksMux(bindingReconciler *reconcileapp.Reconciler) http.Handler {
	u := other.New(repo)
	return mux(u, bindingReconciler)
}
`
		r, err := readHookLane("hooks_mux.go", []byte(src), "buildHooksMux")
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if len(r.Builds) != 0 {
			t.Fatalf("построение ЧУЖОГО пакета объявлено находкой — распознаватель судит "+
				"имя метода, а не пакет: %+v", r)
		}
	})
}

// TestHookLaneGateNoticesAMissingParameter — вторая сторона: своего не строит И
// параметра не несёт. Без этой ветви «полоса материализацию не ведёт вовсе»
// читалось бы как исправное состояние.
func TestHookLaneGateNoticesAMissingParameter(t *testing.T) {
	const src = `package main

import (
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

var _ = reconcileapp.Reconciler{}

func buildHooksMux(pool *pgxpool.Pool) http.Handler { return mux(pool) }
`
	r, err := readHookLane("hooks_mux.go", []byte(src), "buildHooksMux")
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(r.Builds) != 0 || r.AcceptsReconciler {
		t.Fatalf("ожидалось «не строит и не принимает», прочитано %+v", r)
	}
	if r.Params == 0 {
		t.Fatalf("параметры сборщика не прочитаны — перепись обязана их называть, иначе "+
			"«параметра нет» неотличимо от «сборщика не нашли»: %+v", r)
	}
	if !strings.Contains(r.Alias, "reconcileapp") {
		t.Fatalf("псевдоним не прочитан: %+v", r)
	}
}
