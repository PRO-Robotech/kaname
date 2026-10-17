// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package nesteddepth_test

// testmain_pgtest_test.go — база пакета и МОДЕЛЬ ПРОЦЕССА с тремя уровнями
// родства (kaname#874, П3 приёмки
// `nested-rule-reaches-descendants-of-a-named-container.md`).
//
// План права компилируется у модели ПРОЦЕССА (`authzmodel.Shared()`). Канон не
// знает ни одного типа глубже двух уровней (замер Р2 приёмки), поэтому модель
// здесь СОБИРАЕТСЯ из канона и манифеста фикстуры П3 тем же путём, что на старте
// службы (`modelcompose.Compose` → `authzmodel.Admit` → `authzmodel.Install`), и
// ставится ДО первого чтения. Отдельный пакет — потому что модель процесса
// ставится один раз: в соседнем пакете `relverdict` она — вшитый канон, и его
// пробы на нём стоят.

import (
	"fmt"
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

func TestMain(m *testing.M) {
	if err := installProbemodModel(); err != nil {
		fmt.Fprintln(os.Stderr, "nesteddepth: модель процесса с фикстурой П3 не поставлена:", err)
		os.Exit(1)
	}
	os.Exit(pgtest.Run(m, pgtest.Config{
		SearchPath: "kaname,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}

// probemodManifest — манифест фикстуры П3.
func probemodManifest() (*manifest.Manifest, error) {
	doc, err := publicreadfixture.Read(publicreadfixture.ChildrenProbemodFile)
	if err != nil {
		return nil, err
	}
	return manifest.Load(doc)
}

func installProbemodModel() error {
	m, err := probemodManifest()
	if err != nil {
		return fmt.Errorf("фикстура П3: %w", err)
	}
	composed, _, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	if err != nil {
		return fmt.Errorf("композиция модели: %w", err)
	}
	adm, err := authzmodel.Admit(composed)
	if err != nil {
		return fmt.Errorf("допуск модели: %w", err)
	}
	if len(adm.Findings) > 0 {
		return fmt.Errorf("допуск модели отверг её (%s): %v", adm.Census(), adm.Findings)
	}
	return authzmodel.Install(composed)
}
