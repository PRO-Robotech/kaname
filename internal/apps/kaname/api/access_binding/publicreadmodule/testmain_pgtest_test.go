// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadmodule_test

// testmain_pgtest_test.go — база пакета и МОДЕЛЬ ПРОЦЕССА мира П2 приёмки
// docs/engineering/acceptance/public-read-container-of-a-module-type-is-admitted.md
// (редакция 3, kaname#866).
//
// План права компилируется у модели ПРОЦЕССА (`authzmodel.Shared()`). Канон не
// знает типов модуля `probemod`, поэтому модель здесь СОБИРАЕТСЯ из канона и
// манифеста П1 (`probemod.public-read-fixture.yaml`, С ключом
// `publicReadToChildren` на ящиках) тем же путём, что на старте службы
// (`modelcompose.Compose` → `authzmodel.Admit` с термами ключа → `authzmodel.Install`),
// и ставится ДО первого чтения. Отдельный пакет — потому что модель процесса
// ставится один раз: в соседнем пакете `access_binding` она — вшитый канон, и
// его пробы на нём стоят.
//
// Предпосылка мира проверяется здесь же: собранная модель обязана нести
// контейнер публичного чтения на ящике и его наследование ребёнком. Без этого
// отказ `Check` в PM-03 был бы отказом сломанной фикстуры, а не предмета.

import (
	"fmt"
	"os"
	"strings"
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
		fmt.Fprintln(os.Stderr, "publicreadmodule: модель процесса мира П2 не поставлена:", err)
		os.Exit(1)
	}
	os.Exit(pgtest.Run(m, pgtest.Config{
		SearchPath: "kaname,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}

// probemodManifest — манифест П1 как есть (с ключом).
func probemodManifest() (*manifest.Manifest, error) {
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		return nil, err
	}
	return manifest.Load(doc)
}

// premiseLines — строки собранной модели, без которых мир П2 не о предмете:
// контейнер публичного чтения на ящике и наследование его ребёнком.
var premiseLines = []string{
	"define public_reader: [system_class]",
	"or public_reader from box",
}

func installProbemodModel() error {
	m, err := probemodManifest()
	if err != nil {
		return fmt.Errorf("фикстура П1: %w", err)
	}
	composed, crep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	if err != nil {
		return fmt.Errorf("композиция модели: %w", err)
	}
	adm, err := authzmodel.Admit(composed, crep.KeyTerms...)
	if err != nil {
		return fmt.Errorf("допуск модели: %w", err)
	}
	if len(adm.Findings) > 0 {
		return fmt.Errorf("допуск модели отверг её (%s): %v", adm.Census(), adm.Findings)
	}
	for _, line := range premiseLines {
		if !strings.Contains(composed, line) {
			return fmt.Errorf("предпосылка мира П2: в собранной модели нет строки %q", line)
		}
	}
	fmt.Fprintln(os.Stderr, "publicreadmodule: модель процесса мира П2 поставлена,", adm.Census())
	return authzmodel.Install(composed)
}
