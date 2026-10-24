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
		fmt.Fprintln(os.Stderr, "nesteddepth: модель процесса с фикстурой П3 не поставлена:", err)
		os.Exit(1)
	}
	os.Exit(pgtest.Run(m, pgtest.Config{
		SearchPath: "kaname,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}

// probemodManifest — манифест фикстуры П3 в форме, которую ДОПУСКАЕТ модель
// процесса, с двумя вычисленными правками:
//
//   - ящики указывают на АККАУНТ, а не на проект. Замер: собранная модель с
//     ящиками под проектом допуском отвергается — у ярлыка цепь указателей до
//     кластера `tag → item → box → project → account → cluster` глубже предела
//     обхода 4 (`relverdict.MaxAncestorDepth`), и планы `probemod_tag.v_*`
//     невыразимы (находки Д5′). Три уровня под проектом сегодня не доставляются
//     вовсе; под аккаунтом цепь ярлыка — ровно 4;
//   - без ключа `publicReadToChildren`: публичное чтение здесь не предмет — его
//     держат пробы материализатора
//     (`access_binding/reconcile/public_reader_sc65_test.go`), сборки модели с
//     ключом у типа вне канона (`internal/modelcompose/public_read_module_type_test.go`),
//     цепочки старта (`cmd/kaname/public_read_module_type_test.go`) и мира П2
//     приёмки kaname#866 (`access_binding/publicreadmodule`, PM-03/04). Ключ
//     убран, чтобы модель этого пакета несла ровно тот предмет, о котором его пробы.
//
// Предмет ND-08 — глубина вложенного правила — от обеих правок не зависит:
// контейнер остаётся предком внука на глубине 2.
func probemodManifest() (*manifest.Manifest, error) {
	doc, err := publicreadfixture.Read(publicreadfixture.ChildrenProbemodFile)
	if err != nil {
		return nil, err
	}
	keyless, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		return nil, err
	}
	const underProject = "    objectType: probemod_box\n    parents: [project]\n"
	if strings.Count(string(keyless), underProject) != 1 {
		return nil, fmt.Errorf("фикстура П3: указатель ящиков на проект не найден ровно один раз")
	}
	return manifest.Load([]byte(strings.Replace(string(keyless), underProject,
		"    objectType: probemod_box\n    parents: [account]\n", 1)))
}

func installProbemodModel() error {
	m, err := probemodManifest()
	if err != nil {
		return fmt.Errorf("фикстура П3: %w", err)
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
	return authzmodel.Install(composed)
}
