// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifest_test

// producerdelivery_test.go — ПРОБА СКВОЗЬ ОБЕ СТОРОНЫ доставки (задача #1901).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ОНА, КОГДА ОБЕ ПОЛОВИНЫ УЖЕ ПРОВЕРЕНЫ ПОРОЗНЬ
//
// Половин у доставки три, и каждая проверяется своим: производитель — гейтом в
// `deploy` (объект собирается, имя одно с чартом), читатель — пробами рядом
// (каталог читается, пустой отвергается), чарт — гейтом объявлений. Все три
// зелены по отдельности ровно так же и тогда, когда СТЫК между ними разорван:
// производитель кладёт ключи, которых читатель не видит, — и это в точности тот
// дефект, ради которого задача заведена.
//
// Поэтому здесь вопрос ставится сквозь обе стороны: то, что производитель
// собрал из дерева, раскладывается ТАК ЖЕ, как это делает kubelet, и читается
// ТЕМ ЖЕ кодом, которым читает старт службы.
//
// Единственное звено, оставшееся за пробой, — сам kubelet: раскладка тома здесь
// воспроизведена, а не смонтирована. Это названо прямо, чтобы «зелено» не
// читалось шире сделанного.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/tools/modulemanifests"
)

// standProfile — профиль стенда, объявляющий доставку. Профиль, а не копия
// имени: имя ConfigMap живёт в одном месте, и проба читает его оттуда же.
const standProfile = "deploy/helm/umbrella/values.dev.yaml"

// repoRootFromTest — корень дерева, найденный подъёмом до go.mod.
//
// Выведен, а не выписан числом «..»: количество уровней меняется вместе с
// раскладкой пакета и разошлось бы молча.
func repoRootFromTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не прочитан: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("корень дерева не найден подъёмом от %s — предпосылка пробы исчезла", dir)
		}
		dir = parent
	}
}

// TestProducedConfigMapIsReadableByTheDeliveryReader — то, что положил
// производитель, служба ПРОЧИТЫВАЕТ целиком.
func TestProducedConfigMapIsReadableByTheDeliveryReader(t *testing.T) {
	root := repoRootFromTest(t)

	delivery, err := modulemanifests.Collect(root, []string{filepath.Join(root, standProfile)})
	if err != nil {
		t.Fatalf("производитель не собрал объект для %s: %v (%s) — предпосылка пробы "+
			"исчезла: доставку объявляет другой профиль либо не объявляет никто",
			standProfile, err, delivery.Census.Summary())
	}
	rendered, err := modulemanifests.Render(delivery)
	if err != nil {
		t.Fatalf("объект не напечатан: %v", err)
	}

	var object struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(rendered, &object); err != nil {
		t.Fatalf("напечатанный объект не разбирается: %v", err)
	}
	if len(object.Data) == 0 {
		t.Fatal("в объекте нет ни одного ключа — вердикт беспредметен")
	}

	// Раскладка ТА ЖЕ, что кладёт kubelet: служебные записи тома на месте, ключи
	// — символьными ссылками. Собери проба обычные файлы — она утверждала бы о
	// раскладке, которой на стенде не бывает.
	mount := configMapMount(t, object.Data)

	report, err := manifest.LoadDelivered(mount)
	if err != nil {
		t.Fatalf("служба отвергла то, что положил производитель: %v\n"+
			"перепись доставки: %s\nперепись производителя: %s",
			err, report.Summary(), delivery.Census.Summary())
	}
	if report.ManifestsRead != len(object.Data) {
		t.Fatalf("положено ключей %d, прочитано манифестов %d — доставленный и невидимый "+
			"читателю файл есть тот самый класс, ради которого доставка заводилась",
			len(object.Data), report.ManifestsRead)
	}
	if len(report.Manifests) != report.ManifestsRead {
		t.Fatalf("разобрано %d при прочитанных %d — потребителю пришлось бы читать "+
			"каталог вторым проходом", len(report.Manifests), report.ManifestsRead)
	}

	modules := append([]string(nil), report.Modules()...)
	sort.Strings(modules)
	t.Logf("осмотрено: ключей объекта %d · манифестов прочитано %d · байт %d · модули: %s",
		len(object.Data), report.ManifestsRead, delivery.Census.Bytes, strings.Join(modules, ", "))
}
