// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// delivery_test.go — чтение КАТАЛОГА ДОСТАВКИ на старте службы (задача #1875).
//
// Утверждаются все три исхода обхода в том виде, в каком их видит старт: годно —
// пускаем и знаем, что доставлено; пусто — отказ, потому что отсутствие манифеста
// снятием модуля НЕ является; негодно — отказ, называющий манифест.
//
// Отрицания стоят В ПАРЕ с положительным: без него «отказ есть» неотличимо от
// «читатель отвергает всё».

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// deliveryDir — каталог доставки с названными манифестами.
func deliveryDir(t *testing.T, docs map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range docs {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("каталог %s не заведён: %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("манифест %s не записан: %v", p, err)
		}
	}
	return root
}

func TestLoadDeliveredReadsEveryManifestAndNamesTheModules(t *testing.T) {
	// Раскладка РЕАЛЬНЫМИ подкаталогами остаётся законной: так выглядит корень,
	// под которым посадка смонтировала несколько томов. Раскладку одного тома
	// ConfigMap читает deliverymount_test.go — она другая, и там же замерено,
	// почему.
	//
	// ЗДЕСЬ СТОЯЛ чужой файл рядом («доставка судит имя, а не совпадение слова»),
	// и это утверждение снято вместе со своим основанием (задача #1901): каталог
	// доставки — ЗАКРЫТЫЙ НАБОР, чужих документов в нём не бывает, а требование
	// имени `manifest.yaml` делало доставку неисполнимой — ключа с таким именем в
	// одном ConfigMap может быть только один. Посторонний ключ теперь находка, и
	// об этом отдельная проба.
	root := deliveryDir(t, map[string]string{
		"vpc/manifest.yaml": compactManifest,
		"iam/manifest.yaml": "apiVersion: iam/v1\nmodule: iam\n",
	})

	report, err := manifest.LoadDelivered(root)
	if err != nil {
		t.Fatalf("годная доставка отвергнута: %v", err)
	}
	if report.ManifestsRead != 2 {
		t.Fatalf("манифестов прочитано %d, ожидалось 2 (осмотрено файлов %d) — "+
			"«ноль находок» обязано быть отличимо от «ноль прочитанного»",
			report.ManifestsRead, report.PathsSeen)
	}
	got := strings.Join(report.Modules(), ",")
	if !strings.Contains(got, "vpc") || !strings.Contains(got, "iam") {
		t.Fatalf("перепись модулей %q не называет доставленных — "+
			"«доставлено два манифеста» не отличается от «доставлено две копии одного»", got)
	}
	if len(report.Manifests) != report.ManifestsRead {
		t.Fatalf("разобранных манифестов %d при прочитанных %d — потребителю доставки "+
			"пришлось бы читать дерево вторым проходом",
			len(report.Manifests), report.ManifestsRead)
	}
}

func TestLoadDeliveredRefusesAnEmptyDirectoryBecauseAbsenceIsNotWithdrawal(t *testing.T) {
	// Пустой ConfigMap, а не пустой каталог: том всё равно кладёт свои служебные
	// записи, и перепись обязана их назвать — иначе «доставка сорвана» не
	// отличается от «каталога нет вовсе».
	root := configMapMount(t, nil)

	report, err := manifest.LoadDelivered(root)
	if err == nil {
		t.Fatal("пустой каталог доставки принят — сорванное монтирование стало бы " +
			"неотличимо от снятия всех модулей разом")
	}
	if report.PathsSeen == 0 {
		t.Fatal("отчёт не называет объёма осмотренного — отказ неотличим от нечитаемого каталога")
	}
	if !strings.Contains(err.Error(), "снятием модуля НЕ является") {
		t.Errorf("отказ не называет ПРИЧИНЫ — оператор прочтёт его как «модулей нет»: %v", err)
	}
}

func TestLoadDeliveredRefusesAnUnreadableRoot(t *testing.T) {
	// Опечатка в пути обязана быть НАХОДКОЙ, а не успокоительным «проверять
	// нечего»: иначе неверно названный каталог поднимает службу молча.
	_, err := manifest.LoadDelivered(filepath.Join(t.TempDir(), "нет-такого"))
	if err == nil {
		t.Fatal("нечитаемый каталог доставки принят")
	}
}

func TestLoadDeliveredRefusesABrokenManifestAndNamesIt(t *testing.T) {
	// Модуль у второго документа ДРУГОЙ, и это не косметика: с тех пор как имя,
	// объявленное дважды одним обходом, стало находкой (moduleset.go), прежняя
	// фикстура несла ВТОРОЙ дефект и проба судила бы уже не свой предмет.
	root := deliveryDir(t, map[string]string{
		"vpc/manifest.yaml":    compactManifest,
		"broken/manifest.yaml": "apiVersion: iam/v1\nmodule: compute\nunknownSection: 1\n",
	})

	report, err := manifest.LoadDelivered(root)
	if err == nil {
		t.Fatal("негодный манифест принят доставкой")
	}
	if !strings.Contains(err.Error(), "broken/manifest.yaml") {
		t.Errorf("отказ не называет манифеста — чинить придётся перебором: %v", err)
	}
	if report.ManifestsRead != 2 {
		t.Errorf("перепись при отказе называет %d прочитанных, ожидалось 2 — "+
			"обход обрывается на первой находке", report.ManifestsRead)
	}
}
