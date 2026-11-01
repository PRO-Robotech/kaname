// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// permanent_project_cost_integration_test.go — замер DoD п.8 приёмки
// docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md
// (задача PRO-Robotech/kaname#983): p50/p95 регистрации на мире П6 — 200
// регистраций типа registry (объявленного, когда ключ принимается) и 200
// регистраций типа vpc (необъявленного).
//
// Ручная операция под ручкой `KACHO_PERMANENT_PROJECT_COST=1`: числа печатаются
// в журнал прогона, вердикта о пороге нет. До правки и после гонится ОДИН И ТОТ
// ЖЕ файл: документ с ключом `permanentProject` он собирает правкой текста сам,
// и если загрузчик ключа не знает (сборка до правки), замер идёт без объявления
// и говорит об этом строкой журнала.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// permanentProjectCostEnv — ручка замера.
const permanentProjectCostEnv = "KACHO_PERMANENT_PROJECT_COST"

// permanentCostGate — ворота модуля для замера.
type permanentCostGate struct{ module string }

func (g permanentCostGate) Authorize(context.Context) (string, error) { return g.module, nil }

// TestPermanentProjectCost_RegisterLatency — p50/p95 регистрации, мс.
func TestPermanentProjectCost_RegisterLatency(t *testing.T) {
	if os.Getenv(permanentProjectCostEnv) == "" {
		t.Skipf("замер не запрошен (%s пуст) — это ручная операция, как и замеры R7", permanentProjectCostEnv)
	}
	const n = 200
	p := newPCRWorld(t)

	edition, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(t, err)
	withWrites, err := publicreadfixture.WithWrites(edition)
	require.NoError(t, err)
	const line = "    permanentProject: true\n"
	dk := bytes.Replace(withWrites, []byte("  - name: registries\n"), []byte("  - name: registries\n"+line), 1)
	dk = bytes.Replace(dk, []byte("  - name: repositories\n"), []byte("  - name: repositories\n"+line), 1)
	if m, lerr := manifest.Load(dk); lerr == nil {
		p.applyDelivered("замер: доставка D-K", m)
		t.Logf("ЗАМЕР: тип registry объявлен (permanentProject доставлен)")
	} else {
		m, werr := manifest.Load(withWrites)
		require.NoError(t, werr)
		p.applyDelivered("замер: доставка без ключа", m)
		t.Logf("ЗАМЕР: ключ permanentProject загрузчику неизвестен — тип registry не объявлен (%v)", lerr)
	}

	prj, acc := string(p.prjA), string(p.accA)
	measure := func(what, module string, req func(i int) *iamv1.RegisterResourceRequest) {
		t.Helper()
		h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
			WithResourceRegistrar(p.reg, permanentCostGate{module: module})
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
	chain := []string{"project:" + prj, "account:" + acc}
	measure("registry (объявляемый тип)", "registry", func(i int) *iamv1.RegisterResourceRequest {
		return &iamv1.RegisterResourceRequest{
			SubjectId: "project:" + prj, Relation: "project", Object: fmt.Sprintf("%s:pcost%04d", pcrRegType, i),
			ParentProjectId: prj, ParentAccountId: acc, ParentChain: chain,
		}
	})
	measure("vpc (необъявленный тип)", "vpc", func(i int) *iamv1.RegisterResourceRequest {
		return &iamv1.RegisterResourceRequest{
			SubjectId: "project:" + prj, Relation: "project", Object: fmt.Sprintf("vpc_network:enp%017d", i),
			ParentProjectId: prj, ParentAccountId: acc, ParentChain: chain,
		}
	})
}
