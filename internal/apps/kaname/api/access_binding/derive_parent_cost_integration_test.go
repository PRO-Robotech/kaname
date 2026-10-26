// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// derive_parent_cost_integration_test.go — замер DoD п.8 приёмки
// docs/engineering/acceptance/kaname-derives-the-parent-of-a-registered-object.md
// (задача PRO-Robotech/kaname#982): p50/p95 `RegisterResource` на мире П6 — 200
// регистраций реестров под проектом и 200 репозиториев под контейнером.
//
// Замер — ручная операция (как замеры R7): он исполняется только под ручкой
// `KACHO_DERIVE_PARENT_COST=1` и печатает числа в журнал прогона, вердикта о
// пороге не выносит. До правки и после он гонится ОДНИМ И ТЕМ ЖЕ файлом на одной
// машине кластера: файл не зовёт ничего, чего не было до задачи (мир П6 и
// обработчик с воротами модуля), поэтому сборка до правки его исполняет.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// deriveParentCostEnv — ручка замера.
const deriveParentCostEnv = "KACHO_DERIVE_PARENT_COST"

// costGate — ворота модуля registry для замера.
type costGate struct{}

func (costGate) Authorize(context.Context) (string, error) { return "registry", nil }

// TestDeriveParentCost_RegisterLatency — p50/p95 регистрации, мс.
func TestDeriveParentCost_RegisterLatency(t *testing.T) {
	if os.Getenv(deriveParentCostEnv) == "" {
		t.Skipf("замер не запрошен (%s пуст) — это ручная операция, как и замеры R7", deriveParentCostEnv)
	}
	const n = 200
	p := newPCRWorld(t)
	h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(p.reg, costGate{})
	prj, acc := string(p.prjA), string(p.accA)

	measure := func(what string, req func(i int) *iamv1.RegisterResourceRequest) {
		t.Helper()
		durations := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			r := req(i)
			start := time.Now()
			_, err := h.RegisterResource(p.ctx, r)
			durations = append(durations, time.Since(start))
			require.NoErrorf(t, err, "%s: регистрация %d", what, i)
		}
		sort.Slice(durations, func(a, b int) bool { return durations[a] < durations[b] })
		ms := func(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }
		t.Logf("ЗАМЕР %s: регистраций %d · p50 %s мс · p95 %s мс · max %s мс",
			what, n, ms(durations[n/2]), ms(durations[n*95/100]), ms(durations[n-1]))
	}

	measure("реестр под проектом", func(i int) *iamv1.RegisterResourceRequest {
		return &iamv1.RegisterResourceRequest{
			SubjectId: "project:" + prj, Relation: "project", Object: fmt.Sprintf("%s:cost%04d", pcrRegType, i),
			ParentProjectId: prj, ParentAccountId: acc,
			ParentChain: []string{"project:" + prj, "account:" + acc},
		}
	})
	measure("репозиторий под контейнером", func(i int) *iamv1.RegisterResourceRequest {
		return &iamv1.RegisterResourceRequest{
			SubjectId: pcrRegType + ":" + pcrX, Relation: "parent",
			Object:          fmt.Sprintf("%s:%s/cost%04d", pcrRepoType, pcrX, i),
			ParentProjectId: prj, ParentAccountId: acc,
			ParentChain: []string{pcrRegType + ":" + pcrX, "project:" + prj, "account:" + acc},
		}
	})
}
