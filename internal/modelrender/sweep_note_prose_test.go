// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

// sweep_note_prose_test.go — перевод прозы примечаний публичного чтения
// (kaname#855) на стороне СВЕРКИ ДЕРЕВА.
//
// # Почему отдельная проба
//
// [modelrender.RenderForCanon] объявлен единственным входом обоих судей
// совпадения канона с манифестом: сборки модели на старте (`modelcompose`) и
// сверки дерева ([modelrender.Sweep]). Сторону сборки держат пробы
// `modelcompose` (TestSC829_PublicWildcardWordRendersAsTheClassAndEqualsTheCanon
// и SC-70); сторону сверки не держало ничего: подмена вызова в `compareModule`
// на сырой [modelrender.Render] оставляла пакет зелёным, а единственная проба
// реального дерева без названного дерева платформы пропускается. Эта проба
// судит сверку на синтетическом дереве, которое есть всегда.
//
// # Что судится
//
// Канон несёт блоки registry и nlb с НОВОЙ прозой. Манифест прежней прозы и
// манифест новой прозы дают исход [modelrender.SweepOK] с теми же четырьмя
// сверенными блоками (vpc ×2, registry, nlb); манифест прозы, отличной от обеих хоть на слово, — находку,
// названную модулем. Третий случай — дельта ровно в одной строке прозы: без
// него зелёное первых двух было бы неотличимо от сверки, не читающей примечаний.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
)

// nlbProseManifest — манифест модуля балансировки с одной строкой прозы у
// отношения `announce_writer`.
func nlbProseManifest(line string) string {
	return `apiVersion: iam/v1
module: loadbalancer
resources:
  - name: networkLoadBalancers
    objectType: nlb_network_load_balancer
    parents: [project]
    producer: derived
    notes:
      - before: announce_writer
        text: |
          ` + line + `
    relations:
      - name: announce_writer
        definition: '[service_account]'
        position: afterVerbs
    verbs:
      - get
`
}

const (
	nlbPriorProse = "#   * `[service_account]` ONLY — no `user`, no `group#member`, no `user:*`."
	nlbNewProse   = "#   * `[service_account]` ONLY — no `user`, no `group#member`, no `system_class`."
)

// rawBlock — блок единственного ресурса документа сырым [modelrender.Render].
//
// Канон пробы строится БЕЗ перевода: на новой прозе перевод тождествен, и канон,
// порождённый им, судил бы перевод его же собственным результатом.
func rawBlock(t *testing.T, doc string) string {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("загрузчик отверг вход:\n%v\nвход:\n%s", err, doc)
	}
	if len(m.Resources) != 1 {
		t.Fatalf("ресурсов в манифесте %d, ожидался один", len(m.Resources))
	}
	b, err := modelrender.Render(m.Resources[0])
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	return string(b)
}

// proseTree — синтетическое дерево платформы: канон из двух блоков vpc и блоков
// registry и nlb с новой прозой; манифест каждого модуля набора, registry и
// loadbalancer — с прозой, переданной пробой.
func proseTree(t *testing.T, registryProse []string, nlbLine string) string {
	t.Helper()
	registryCanon := rawBlock(t, registryManifestWithProse(registryNewProse))
	nlbCanon := rawBlock(t, nlbProseManifest(nlbNewProse))
	for name, blk := range map[string]string{"registry_repository": registryCanon, "nlb_network_load_balancer": nlbCanon} {
		if strings.Contains(blk, "user:*") {
			t.Fatalf("канон пробы (%s) несёт слово `user:*` — пробе нечего судить:\n%s", name, blk)
		}
	}
	root := helperTree(t, twoBlockCanon+"\n"+registryCanon+"\n"+nlbCanon)

	modules := authzmap.CatalogSeedModules()
	have := map[string]bool{}
	for _, m := range modules {
		have[m] = true
	}
	for _, m := range []string{"vpc", "registry", "loadbalancer"} {
		if !have[m] {
			t.Fatalf("модуль %s вне закрытого набора (%v) — дерево пробы не судит то, что объявляет", m, modules)
		}
	}
	for _, m := range modules {
		var body string
		switch m {
		case "vpc":
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		case "registry":
			body = registryManifestWithProse(registryProse)
		case "loadbalancer":
			body = nlbProseManifest(nlbLine)
		default:
			body = manifestFor(m)
		}
		writeManifest(t, root, m, body)
	}
	return root
}

// TestSweepJudgesPriorAndNewNoteProseAsTheSameCanon — сверка дерева принимает
// манифест прежней прозы так же, как манифест новой: исход 0, четыре сверенных
// блока, ни одного принятого прежней редакцией.
//
// Красный — при сверке, зовущей сырой Render вместо RenderForCanon: блоки
// прежней прозы расходятся с каноном.
func TestSweepJudgesPriorAndNewNoteProseAsTheSameCanon(t *testing.T) {
	cases := []struct {
		name     string
		registry []string
		nlb      string
	}{
		{"прежняя проза registry и nlb", registryPriorProse, nlbPriorProse},
		{"новая проза registry и nlb", registryNewProse, nlbNewProse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := proseTree(t, tc.registry, tc.nlb)

			census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

			if code != modelrender.SweepOK {
				t.Fatalf("исход %d, ожидался %d (SweepOK); находки: %v", code, modelrender.SweepOK, findings)
			}
			if census.BlocksCompared != 4 || census.BlocksPriorEdition != 0 {
				t.Fatalf("сверено блоков %d (ожидалось 4: vpc ×2, registry, nlb), прежней редакцией %d (ожидалось 0): %s",
					census.BlocksCompared, census.BlocksPriorEdition, census)
			}
			t.Logf("перепись: %s", census)
		})
	}
}

// TestSweepFindsNoteProseThatIsNeitherPriorNorNew — законный близнец со сдвигом
// РОВНО в одной строке прозы registry: строка, отличная от прежней и от новой,
// не переводится, и сверка называет модуль registry находкой.
func TestSweepFindsNoteProseThatIsNeitherPriorNorNew(t *testing.T) {
	other := append([]string{}, registryPriorProse...)
	other[0] = "# RG-1 D-7: `user:*` public-read wildcard — a line nobody translated."

	root := proseTree(t, other, nlbPriorProse)

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d (находка): сверка не читает прозу примечаний", code, modelrender.SweepFinding)
	}
	if len(findings) != 1 || findings[0].Module != "registry" || findings[0].Type != "registry_repository" {
		t.Fatalf("находки %v, ожидалась ровно одна: registry / registry_repository", findings)
	}
}
