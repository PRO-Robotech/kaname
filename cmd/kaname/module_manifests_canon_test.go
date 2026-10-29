// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_manifests_canon_test.go — оба пути, читающие каталог доставки, вносят
// загрузчику родство типов канона (kaname#951): манифест модуля без раздела
// `resources`, чьи роли с `children` называют типы канона, проходит доставку и
// на старте, и при перечитывании по запросу.
//
// Близнец — тот же документ, где вложенное правило называет тип вне канона: оба
// пути его отвергают. Без близнеца проба не отличила бы внесённый канон от
// читателя, принимающего всякий документ.

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const canonOnlyRegistryManifest = `apiVersion: iam/v1
module: registry

roles:
  - id: registry.reader
    description: >
      Чтение реестра и каждого его репозитория, включая созданные позже.
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [registries]
        classes: [get, list]
        children:
          - resources: [repositories]
            classes: [get, list]
`

func TestBootDeliveryJudgesChildrenOfAnUndeclaredTypeByTheCanon(t *testing.T) {
	cases := map[string]struct {
		doc    string
		refuse string
	}{
		"тип канона": {doc: canonOnlyRegistryManifest},
		"тип вне канона": {
			doc:    strings.Replace(canonOnlyRegistryManifest, "          - resources: [repositories]", "          - resources: [images]", 1),
			refuse: `тип "registry.images" не объявлен ни разделом resources этого манифеста, ни каноном модели прав`,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.refuse != "" && c.doc == canonOnlyRegistryManifest {
				t.Fatalf("правка близнеца не применилась — проба судила бы тот же документ")
			}
			root := writeDelivery(t, map[string]string{"registry/manifest.yaml": c.doc})
			cfg := config.ManifestsConfig{Dir: root, Required: true}

			logger, _ := captureBoot()
			_, bootErr := loadDeliveredManifests(logger, cfg)
			_, readErr := newManifestDeliverySource(cfg).Read(context.Background())

			for path, err := range map[string]error{"старт": bootErr, "перечитывание": readErr} {
				switch {
				case c.refuse == "" && err != nil:
					t.Errorf("%s: манифест без resources над типами канона отвергнут: %v", path, err)
				case c.refuse != "" && err == nil:
					t.Errorf("%s: манифест с вложенным правилом над типом вне канона принят", path)
				case c.refuse != "" && !strings.Contains(err.Error(), c.refuse):
					t.Errorf("%s: отказ не о том\n ждали  %q\n получено %v", path, c.refuse, err)
				}
			}
		})
	}
}
