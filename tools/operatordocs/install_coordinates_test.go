// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package operatordocs_test

// install_coordinates_test.go — координата, которую руководство НАЗЫВАЕТ
// оператору, обязана существовать в дереве (задача продукта #2077).
//
// # Предмет
//
// Руководство говорит оператору чужого облака, куда смотреть, когда служба
// отвергла предъявленное удостоверение: имя ряда измерителей и имя настройки.
// Обе координаты — обещание, и обещание это стареет МОЛЧА: переименование ряда
// не роняет ни сборку, ни одну пробу, а оператор идёт по имени, которого нет, и
// заключает, что измерителей не существует. Это тот же класс, что «ручка,
// объявленная и никем не читаемая», только с другой стороны: читатель есть,
// координата — нет.
//
// # Почему проба здесь, а не в пакете измерителей
//
// Предмет — СОГЛАСИЕ двух мест: текста руководства и объявления в коде. Проба,
// живущая у одного из них, утверждала бы о нём одном.
//
// # Перепись печатается всегда
//
// «ноль находок» обязано быть отличимо от «ноль прочитанного»: разбор, не
// нашедший в руководстве ни одной координаты, означает, что проба потеряла цель,
// а не что руководство чисто.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// metricInGuide / settingInGuide — координаты, которые руководство называет
// внутри обратных кавычек. Судится ИМЕННО заключённое в кавычки: то же слово в
// прозе координатой не является, и требовать от него существования значило бы
// краснеть на объяснении.
var (
	metricInGuide  = regexp.MustCompile("`(kaname_[a-z0-9_]+_total)`")
	settingInGuide = regexp.MustCompile("`(authn\\.[a-z0-9.-]+)`")
)

// declaredMetrics — ряды, которые дерево действительно объявляет.
//
// Перечень ВЫВОДИТСЯ из объявлений пакета измерителей, а не выписывается: второй
// рукописный перечень разошёлся бы с первым молча — и разошёлся бы там, где
// расхождение не видно, потому что обе стороны по отдельности выглядят полными.
func declaredMetrics() map[string]bool {
	return map[string]bool{
		metrics.PresentedCredentialOutcomesMetric: true,
		metrics.IntrospectOutcomesMetric:          true,
		metrics.SigningKeyEventsMetric:            true,
	}
}

// declaredSettings — ключи настройки, которые процесс ДЕЙСТВИТЕЛЬНО читает.
//
// Выводятся обходом самой структуры настройки по её разметке, а не из таблицы
// обязательных величин: руководство законно называет и НЕобязательные ключи, и
// предикат, знающий только обязательные, объявил бы находкой каждый из них.
// Ошибся бы при этом разборщик, а не дерево, — и починка «расширить таблицу»
// завела бы обязательность там, где её никто не объявлял.
func declaredSettings() map[string]bool {
	out := map[string]bool{}
	collectKeys(reflect.TypeOf(config.Config{}), "", out)
	return out
}

// collectKeys складывает точечные пути из разметки полей.
func collectKeys(t reflect.Type, prefix string, out map[string]bool) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("mapstructure"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		out[key] = true
		collectKeys(f.Type, key, out)
	}
}

func TestInstallGuideNamesOnlyCoordinatesThatExist(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "INSTALL.md"))
	if err != nil {
		t.Fatalf("руководство установки не прочитано: %v", err)
	}
	guide := string(raw)

	knownMetrics := declaredMetrics()
	knownSettings := declaredSettings()

	var (
		metricHits, settingHits int
		findings                []string
	)
	for _, m := range metricInGuide.FindAllStringSubmatch(guide, -1) {
		metricHits++
		if !knownMetrics[m[1]] {
			findings = append(findings, "ряд измерителей "+m[1]+" руководство называет, а дерево не объявляет")
		}
	}
	for _, m := range settingInGuide.FindAllStringSubmatch(guide, -1) {
		settingHits++
		if !knownSettings[m[1]] {
			findings = append(findings, "настройку "+m[1]+" руководство называет, а разметка настройки такого ключа не несёт")
		}
	}

	if metricHits == 0 && settingHits == 0 {
		t.Fatal("обход пуст: в руководстве не найдено ни одной координаты — проба потеряла " +
			"цель, обнови её вместе с руководством")
	}
	t.Logf("перепись: координат осмотрено %d (рядов %d · настроек %d) · объявлено рядов %d · "+
		"объявлено настроек %d · находок %d",
		metricHits+settingHits, metricHits, settingHits,
		len(knownMetrics), len(knownSettings), len(findings))

	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("руководство обещает оператору координаты, которых нет:\n  %s",
			strings.Join(findings, "\n  "))
	}
}
