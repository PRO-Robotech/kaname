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
		Tagged   string         `mapstructure:"tagged"`
		Untagged string         // mapstructure сопоставляет по имени поля
		Skipped  string         `mapstructure:"-"`
		Ptr      *int64         `mapstructure:"ptr"`
		Nested   inner          `mapstructure:"nested"`
		NestedP  *inner         `mapstructure:"nested-p"`
		Squashed squashed       `mapstructure:",squash"`
		Opts     string         `mapstructure:"opts,omitempty"`
		private  string         //nolint:unused // форма поля, которую декодер не видит
		List     []string       `mapstructure:"list"`
		Map      map[string]int `mapstructure:"map"`
	}
	_ = root{}.private

	got := decoderKeysOf(reflect.TypeOf(root{}))
	require.Equal(t, []string{
		"flat", "list", "map", "nested-p.leaf-key", "nested.leaf-key", "opts", "ptr", "tagged", "untagged",
	}, got)
}

// Предпосылка живого объявления: декодер Config знает ключи, и множество
// пространства `__` не пусто — пустое отвергало бы каждую переменную `__`.
func TestDecoderKeysOfConfigPremise(t *testing.T) {
	keys := DecoderKeys()
	require.Greater(t, len(keys), 100, "перепись ключей декодера подозрительно мала")
	require.Contains(t, keys, "repository.postgres.url")
	t.Logf("перепись: ключей декодера Config %d", len(keys))
}
