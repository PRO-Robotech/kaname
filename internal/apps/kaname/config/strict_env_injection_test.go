// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// strict_env_injection_test.go — СУЖДЕНИЕ о пространстве `__` на синтетическом
// множестве: способность падать доказывается отдельно от живого объявления.
//
// Каждый отрицательный кейс меняет против законного близнеца РОВНО ОДИН факт —
// имя переменной; множество и прочее окружение общие.
package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnknownNestedEnvJudgeFindsAndStaysSilent(t *testing.T) {
	known := map[string]struct{}{
		"KANAME_INVITE__TTL":               {},
		"KANAME_AUTHN__LOGIN__SESSION_TTL": {},
	}
	base := []string{
		"KANAME_INVITE__TTL=72h",
		"KANAME_GRPC_PORT=9090",
		"KANAME_INTERNAL_SERVICE_HOST=10.0.0.7",
		"KANAMECTL__ENDPOINT=x",
		"OTHER__THING=x",
		"PATH=/usr/bin",
	}

	t.Run("близнец: известное имя, плоские имена, чужие приставки — находок 0", func(t *testing.T) {
		require.Empty(t, unknownNestedEnvNames(base, known))
	})

	t.Run("неизвестное имя пространства `__` — находка с именем", func(t *testing.T) {
		env := append(append([]string(nil), base...), "KANAME_INVITE__TTLS=72h")
		require.Equal(t, []string{"KANAME_INVITE__TTLS"}, unknownNestedEnvNames(env, known))
	})

	t.Run("пустое значение тоже объявление — находка", func(t *testing.T) {
		env := append(append([]string(nil), base...), "KANAME_MAIL_NODE__RELAY=")
		require.Equal(t, []string{"KANAME_MAIL_NODE__RELAY"}, unknownNestedEnvNames(env, known))
	})

	t.Run("несколько — все, по порядку имени", func(t *testing.T) {
		env := append(append([]string(nil), base...), "KANAME_Z__B=1", "KANAME_A__B=1")
		require.Equal(t, []string{"KANAME_A__B", "KANAME_Z__B"}, unknownNestedEnvNames(env, known))
	})
}

// Обход ключей декодера знает все формы записи поля, которые декодер судит:
// тег, поле без тега (имя поля в нижнем регистре), `squash`, `-`, указатель,
// вложенная структура, неэкспортируемое поле.
func TestDecoderKeyWalkKnowsEveryFieldForm(t *testing.T) {
	type inner struct {
		Leaf string `mapstructure:"leaf-key"`
	}
	type squashed struct {
		Flat int `mapstructure:"flat"`
	}
	type root struct {
		Tagged   string   `mapstructure:"tagged"`
		Untagged string   // mapstructure сопоставляет по имени поля
		Skipped  string   `mapstructure:"-"`
		Ptr      *int64   `mapstructure:"ptr"`
		Nested   inner    `mapstructure:"nested"`
		NestedP  *inner   `mapstructure:"nested-p"`
		Squashed squashed `mapstructure:",squash"`
		Opts     string   `mapstructure:"opts,omitempty"`
		private  string   //nolint:unused // форма поля, которую декодер не видит
		List     []string `mapstructure:"list"`
	}
	_ = root{}.private

	got := decoderKeysOf(reflect.TypeOf(root{}))
	require.Equal(t, []string{
		"flat", "list", "nested-p.leaf-key", "nested.leaf-key", "opts", "ptr", "tagged", "untagged",
	}, got)
}

// Открытая форма — поле, чьи подключи задаёт оператор, а не тип: отображение
// и интерфейс. Декодер принимает под ней ЛЮБОЙ подключ, и обход, принявший её
// за лист, отверг бы каждый такой подключ файла как неизвестный, а пространству
// `__` выдал бы имя, которого не читает никто. Листом она не является.
func TestDecoderKeyWalkDoesNotTakeAnOpenFormForALeaf(t *testing.T) {
	type inner struct {
		Leaf string `mapstructure:"leaf"`
	}
	for _, tc := range []struct {
		name string
		tp   reflect.Type
		open string
	}{
		{"отображение", reflect.TypeOf(struct {
			Kept string         `mapstructure:"kept"`
			Lim  map[string]int `mapstructure:"lim"`
		}{}), "lim"},
		{"отображение структур под указателем", reflect.TypeOf(struct {
			Kept string            `mapstructure:"kept"`
			Lim  *map[string]inner `mapstructure:"lim"`
		}{}), "lim"},
		{"интерфейс", reflect.TypeOf(struct {
			Kept string `mapstructure:"kept"`
			Lim  any    `mapstructure:"lim"`
		}{}), "lim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decoderKeysOf(tc.tp)
			require.NotContains(t, got, tc.open, "открытая форма принята за лист")
			require.Equal(t, []string{"kept"}, got, "законный лист рядом обязан остаться")
			require.Equal(t, []string{tc.open}, openKeyForms(tc.tp), "открытая форма не названа путём")
		})
	}

	t.Run("открытая форма под squash и во вложенной секции — полный путь", func(t *testing.T) {
		type sec struct {
			Lim map[string]string `mapstructure:"lim"`
		}
		type flat struct {
			Any any `mapstructure:"any"`
		}
		type root struct {
			Sec  sec  `mapstructure:"sec"`
			Flat flat `mapstructure:",squash"`
		}
		require.Equal(t, []string{"any", "sec.lim"}, openKeyForms(reflect.TypeOf(root{})))
	})

	t.Run("близнец: список, список структур, вложенная структура — открытых форм 0", func(t *testing.T) {
		type item struct {
			Name string `mapstructure:"name"`
		}
		type root struct {
			List  []string `mapstructure:"list"`
			Items []item   `mapstructure:"items"`
			Sec   item     `mapstructure:"sec"`
		}
		require.Empty(t, openKeyForms(reflect.TypeOf(root{})))
		require.Equal(t, []string{"items", "list", "sec.name"}, decoderKeysOf(reflect.TypeOf(root{})))
	})
}

// Config не несёт ни одного поля открытой формы: множество ключей файла и
// имён пространства `__` выводится из типа целиком (strict_env.go,
// openKeyForms). Перепись осмотренных полей печатается отдельно от находок, и
// пустой обход — отказ, а не «находок 0».
func TestConfigCarriesNoOpenKeyForm(t *testing.T) {
	w := walkDecoder(reflect.TypeOf(Config{}))
	t.Logf("перепись: полей Config осмотрено %d · ключей %d · открытых форм %d",
		w.fields, len(w.keys), len(w.open))
	require.Greater(t, w.fields, len(w.keys), "обход не осмотрел секций — предпосылка не выполнена")
	require.NotEmpty(t, w.keys, "обход не нашёл ни одного ключа — проба не выполнилась")
	require.Empty(t, w.open, "поле открытой формы в Config: его подключи не выводятся из типа, "+
		"и строгий файл отверг бы каждый из них — объявите поле структурой с перечисленными полями либо списком")
}

// Предпосылка живого объявления: декодер Config знает ключи, и множество
// пространства `__` не пусто — пустое отвергало бы каждую переменную `__`.
func TestDecoderKeysOfConfigPremise(t *testing.T) {
	keys := DecoderKeys()
	require.Greater(t, len(keys), 100, "перепись ключей декодера подозрительно мала")
	require.Contains(t, keys, "repository.postgres.url")
	t.Logf("перепись: ключей декодера Config %d", len(keys))
}
