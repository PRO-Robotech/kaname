// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// deliverymount_test.go — доставка читается в ТОЙ РАСКЛАДКЕ, которую производит
// том ConfigMap, а не в той, которую удобно собрать пробе (задача #1901).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Путь доставки заведён целиком (#1875): чарт монтирует именованный ConfigMap,
// процесс читает смонтированный каталог, страж старта отказывает на сорванной
// доставке. Наполнить этот ConfigMap было НЕЧЕМ — производителя нет, — и вместе
// с производителем выяснилось, что раскладка, в которой пробы доставки читали
// манифесты, том ConfigMap ПОРОДИТЬ НЕ МОЖЕТ. То есть возможность объявлена и
// неисполнима (`api-conventions.md` §«Неисполнимая возможность»): исполнимого
// входа не существует ни в какой форме.
//
// # Что именно измерено, а не предположено
//
// (1) Ключ ConfigMap слэша не содержит — значит подкаталога `<модуль>/` внутри
//     одного ConfigMap не бывает:
//
//	$ kubectl create configmap probe \
//	    --from-file=iam/manifest.yaml=services/iam/manifest.yaml --dry-run=client -o yaml
//	error: "iam/manifest.yaml" is not a valid key name for a ConfigMap:
//	  a valid config key must consist of alphanumeric characters, '-', '_' or '.'
//
// (2) Значит все шесть манифестов дерева легли бы в ОДИН ключ `manifest.yaml`, а
//     двух одинаковых ключей не бывает:
//
//	$ kubectl create configmap probe --from-file=services/iam/manifest.yaml \
//	    --from-file=services/vpc/manifest.yaml --dry-run=client -o yaml
//	error: cannot add key "manifest.yaml", another key by that name already
//	  exists in Data for ConfigMap "probe"
//
// (3) Подкаталог, заданный через `items[].path`, тоже не спасает: том раскладывает
//     полезную нагрузку в каталог с отметкой времени, а на верхнем уровне кладёт
//     СИМВОЛЬНУЮ ССЫЛКУ на её первый сегмент. Обход символьные ссылки не
//     разыменовывает, поэтому вглубь он не заходит — замерено обходом настоящей
//     раскладки:
//
//	..2026_09_02_00_00_00.000000000          IsDir=true   ← каталог с ведущей точкой, обход в него не заходит
//	..2026_09_02_00_00_00.000000000/iam      IsDir=true
//	..data                                   IsDir=false  ← ссылка
//	iam                                      IsDir=false  ← ССЫЛКА НА КАТАЛОГ: вглубь обход не идёт
//	vpc.manifest.yaml                        IsDir=false  ← ссылка на файл: видна
//
// # Что из этого следует и что здесь утверждается
//
// Каталог доставки — ЗАКРЫТЫЙ НАБОР: всё, что в нём лежит, положила посадка, и
// имя файла в нём есть ключ ConfigMap, а не имя из дерева разработки. Поэтому
// доставка читает КАЖДЫЙ доставленный файл и судит его как манифест, а не ищет
// одно имя: файл, доставленный и невидимый читателю, — это ровно тот класс, ради
// которого доставка заводилась.
//
// Служебные записи тома (`..data`, `..<отметка времени>`) исключены по ведущему
// `..` — это соглашение самого Kubernetes, а не наша догадка о его внутренностях.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/modulemanifest"
	"github.com/PRO-Robotech/kacho/pkg/platformmodules"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// configMapMountTimestampDir — имя каталога полезной нагрузки, как его кладёт том
// ConfigMap. Ведущие точки существенны: по ним раскладка и отличает служебное.
const configMapMountTimestampDir = "..2026_09_02_00_00_00.000000000"

// configMapMount собирает каталог ровно той формы, которую монтирует kubelet:
// полезная нагрузка в каталоге с отметкой времени, `..data` — ссылка на него,
// и по ссылке на каждый ключ верхнего уровня.
//
// Проба, собирающая обычные файлы, утверждала бы о раскладке, которой на стенде
// не бывает, — и зеленела бы при неработающей доставке.
func configMapMount(t *testing.T, data map[string]string) string {
	t.Helper()
	root := t.TempDir()
	payload := filepath.Join(root, configMapMountTimestampDir)
	if err := os.MkdirAll(payload, 0o755); err != nil {
		t.Fatalf("каталог полезной нагрузки %s не заведён: %v", payload, err)
	}
	for key, body := range data {
		if err := os.WriteFile(filepath.Join(payload, key), []byte(body), 0o600); err != nil {
			t.Fatalf("ключ %s не записан: %v", key, err)
		}
		if err := os.Symlink(filepath.Join("..data", key), filepath.Join(root, key)); err != nil {
			t.Fatalf("ссылка на ключ %s не заведена: %v", key, err)
		}
	}
	if err := os.Symlink(configMapMountTimestampDir, filepath.Join(root, "..data")); err != nil {
		t.Fatalf("ссылка ..data не заведена: %v", err)
	}
	return root
}

// deliveredModules — шесть записей закрытого набора дерева: ключ ConfigMap →
// тело манифеста. Имя `manifest.yaml` в одном ConfigMap может быть только одно
// (замер (2) в шапке), поэтому ключ несёт КАТАЛОГ СЛУЖБЫ, из которого манифест
// взят, а не имя модуля.
//
// Различие не умозрительное: каталог `nlb` объявляет модуль `loadbalancer`.
// Ключ, названный по каталогу, есть прямая координата источника
// (`services/<ключ>/manifest.yaml`) — по ней оператор чинит находку, не держа
// это соответствие в голове.
// ПЕРЕЧЕНЬ каталогов выписан, а СООТВЕТСТВИЕ «каталог службы → модуль каталога»
// берётся у единственного объявления (`pkg/platformmodules`). Это разные
// предметы, и путать их нельзя: манифест несут ШЕСТЬ служб из семи объявленных
// (у geo его нет вовсе), поэтому перечень словарём не выводится — а вот
// написание модуля выписывать здесь было бы второй копией соглашения, которая
// разошлась бы с деревом молча (#1885).
func deliveredModules() map[string]string {
	out := map[string]string{}
	for _, dir := range []string{"compute", "iam", "nlb", "registry", "storage", "vpc"} {
		module, ok := platformmodules.CatalogModuleOfService(dir)
		if !ok {
			panic("служба " + dir + " словарём написаний не объявлена")
		}
		out[modulemanifest.DeliveryKey(dir)] = "apiVersion: iam/v1\nmodule: " + module + "\n"
	}
	return out
}

// TestLoadDeliveredReadsEveryKeyOfAConfigMapMount — ПОЛОЖИТЕЛЬНЫЙ контроль всей
// доставки: шесть ключей одного ConfigMap доезжают до службы все шесть.
func TestLoadDeliveredReadsEveryKeyOfAConfigMapMount(t *testing.T) {
	root := configMapMount(t, deliveredModules())

	report, err := manifest.LoadDelivered(root)
	if err != nil {
		t.Fatalf("годная доставка отвергнута: %v (осмотрено файлов %d, прочитано %d)",
			err, report.PathsSeen, report.ManifestsRead)
	}
	if report.ManifestsRead != 6 {
		t.Fatalf("манифестов прочитано %d, ожидалось 6 (осмотрено файлов %d) — "+
			"доставленный и невидимый читателю файл есть тот самый класс, ради "+
			"которого доставка заводилась", report.ManifestsRead, report.PathsSeen)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("служебные записи тома стали находками %v — исключение по ведущему `..` "+
			"есть соглашение самого Kubernetes", report.Findings)
	}
	if report.DirsSkipped == 0 {
		t.Fatal("каталог полезной нагрузки не назван пропущенным — слепая зона " +
			"обязана называться числом, а не подразумеваться")
	}
	got := append([]string(nil), report.Modules()...)
	sort.Strings(got)
	if strings.Join(got, ",") != "compute,iam,loadbalancer,registry,storage,vpc" {
		t.Fatalf("перепись модулей %v не называет доставленных — «доставлено шесть "+
			"манифестов» не отличается от «доставлено шесть копий одного»", got)
	}
}

// TestLoadDeliveredRefusesAKeyThatIsNotAManifest — ОТРИЦАНИЕ в паре с
// положительным выше: каталог доставки закрыт, и посторонний ключ в нём есть
// находка, а не то, что читатель вправе молча пропустить.
func TestLoadDeliveredRefusesAKeyThatIsNotAManifest(t *testing.T) {
	data := deliveredModules()
	data["README.md"] = "# это не манифест"
	root := configMapMount(t, data)

	report, err := manifest.LoadDelivered(root)
	if err == nil {
		t.Fatal("посторонний ключ доставки принят молча — тогда «ключ положили не тот» " +
			"неотличимо от «ключ доехал»")
	}
	if !strings.Contains(err.Error(), "README.md") {
		t.Errorf("отказ не называет ключа — чинить придётся перебором: %v", err)
	}
	// Семь, а не шесть: посторонний ключ ПРОЧИТАН — именно поэтому о нём есть
	// что сказать (см. godoc CheckReport.ManifestsRead). Обход при этом не
	// оборвался: шесть годных разобраны.
	if report.ManifestsRead != 7 {
		t.Errorf("перепись при отказе называет %d прочитанных, ожидалось 7 — "+
			"обход обрывается на первой находке", report.ManifestsRead)
	}
	if len(report.Manifests) != 6 {
		t.Errorf("разобранных манифестов %d при семи прочитанных — годные обязаны "+
			"доехать до потребителя и при находке рядом", len(report.Manifests))
	}
}
