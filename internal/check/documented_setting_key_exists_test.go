// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Прогон одной командой:
//
//	go test ./internal/check/ -run TestDocumentedSettingKeysExistInTheSettingsTree -count=1 -v
//
// Печатает перепись (документов прочитано · описей · строк · ключей сошлось ·
// ключей в настройке) и находки с координатой.

// settingKeysFromProducer — множество ключей настройки, взятое У ПРОИЗВОДИТЕЛЯ:
// разметка `mapstructure` структуры `config.Config`, обойдённая отражением.
//
// Почему отражение, а не разбор `defaults.go`: умолчание объявлено НЕ у каждого
// ключа (`authn.hydra-admin-url` живёт разметкой и умолчания не имеет), и
// перечень из `SetDefault` объявил бы существующий ключ несуществующим —
// находка, рождённая способом смотреть, а не деревом.
func settingKeysFromProducer(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	var walk func(rt reflect.Type, prefix string)
	walk = func(rt reflect.Type, prefix string) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := strings.Split(f.Tag.Get("mapstructure"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			key := tag
			if prefix != "" {
				key = prefix + "." + tag
			}
			keys[key] = true
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft, key)
			}
		}
	}
	walk(reflect.TypeOf(config.Config{}), "")
	require.NotEmpty(t, keys, "предпосылка: разметка настройки не прочитана — "+
		"проверка НЕ ИСПОЛНЯЛАСЬ, а не «находок ноль»")
	return keys
}

// docCorpus — проза дерева: `.md` и `.mdx` каталога документации.
func docCorpus(t *testing.T) check.TreeCorpus {
	t.Helper()
	root := platformtree.Require(t)
	tree, err := treecorpus.NewTree(root)
	require.NoError(t, err, "состав дерева не установлен — «находок ноль» означало бы "+
		"«прочитано ноль»")
	corpus, err := check.CorpusFrom(tree, func(rel string) bool {
		return strings.HasPrefix(rel, "docs/") &&
			(strings.HasSuffix(rel, ".md") || strings.HasSuffix(rel, ".mdx"))
	})
	require.NoError(t, err)
	return corpus
}

// TestDocumentedSettingKeysExistInTheSettingsTree — гейт: всякий ключ настройки,
// названный описью инженерной документации, существует в дереве настроек.
func TestDocumentedSettingKeysExistInTheSettingsTree(t *testing.T) {
	t.Parallel()

	findings, census, err := check.JudgeDocumentedSettingKeys(docCorpus(t), settingKeysFromProducer(t))
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ")
	t.Logf("перепись: %s", census)
	if census.Tables == 0 {
		t.Logf("описей настроек в инженерной прозе не осталось ни одной — это ЦЕЛЬ, "+
			"а не пустой обход: документов прочитано %d, справочник посадки остаётся "+
			"единственным домом описи", census.Files)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestDocumentedSettingKeysPremiseHolds — предпосылка гейта: производитель
// отдаёт НЕПУСТОЕ множество ключей, и у него есть вложенность.
//
// Без неё «ключ не найден» означало бы «искать не в чем», и гейт печатал бы
// находку на каждой законной строке описи.
func TestDocumentedSettingKeysPremiseHolds(t *testing.T) {
	t.Parallel()

	keys := settingKeysFromProducer(t)
	var nested, top int
	for k := range keys {
		if strings.Contains(k, ".") {
			nested++
			continue
		}
		top++
	}
	t.Logf("предпосылка: ключей %d (секций верхнего уровня %d · вложенных %d)", len(keys), top, nested)
	require.Positive(t, top, "секций верхнего уровня ноль: разметка настройки не прочитана")
	require.Positive(t, nested, "вложенных ключей ноль: обход разметки не спускается в секции, "+
		"и всякий составной ключ описи был бы находкой")
}
