// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
)

// Счётчик обязан нести ВСЕ ТРИ исхода, и это не педантизм: каждый отвечает на
// свой вопрос оператора, и ни один не выводится из двух других.
//
//	basic_accepted                  — знаменатель: полоса вообще жива?
//	key_material_refused            — нужно ли окно: кого обновление уже ломает?
//	key_material_accepted_in_window — можно ли окно закрыть: кто ещё не переведён?
//
// Без знаменателя ноль по обоим прочим означает и «никого не сломали», и
// «полоса не обслужила ни одного входа», а это противоположные состояния.
func TestRegistryTokenCredentialKindRecorder_AllThreeOutcomesAreLive(t *testing.T) {
	reg := NewRegistry()
	rec := reg.NewRegistryTokenCredentialKindRecorder()

	// Набор меток берётся ИЗ КОНСТАНТ USE-CASE'а, а не из литералов здесь:
	// вторая копия разошлась бы с первой молча, и разошлась бы именно в имени,
	// на которое оператор настроит тревогу.
	outcomes := []string{
		registrytokenuc.OutcomeBasicAccepted,
		registrytokenuc.OutcomeKeyMaterialRefused,
		registrytokenuc.OutcomeKeyMaterialAcceptedInWindow,
	}

	// Каждый исход обязан ПРИСУТСТВОВАТЬ после первого же наблюдения:
	// отсутствующая серия и серия со значением ноль читаются приборами
	// одинаково лишь до тех пор, пока их не различили.
	for _, o := range outcomes {
		_, present := labelledCounter(t, reg,
			"kacho_iam_registry_token_credential_kind_total", map[string]string{"outcome": o})
		require.False(t, present,
			"до первого наблюдения серии %q быть не должно — иначе проба ниже ничего не утверждает", o)
	}

	rec.ObserveCredentialKind(registrytokenuc.OutcomeBasicAccepted)
	rec.ObserveCredentialKind(registrytokenuc.OutcomeKeyMaterialRefused)
	rec.ObserveCredentialKind(registrytokenuc.OutcomeKeyMaterialRefused)
	rec.ObserveCredentialKind(registrytokenuc.OutcomeKeyMaterialAcceptedInWindow)

	for o, want := range map[string]float64{
		registrytokenuc.OutcomeBasicAccepted:               1,
		registrytokenuc.OutcomeKeyMaterialRefused:          2,
		registrytokenuc.OutcomeKeyMaterialAcceptedInWindow: 1,
	} {
		got, present := labelledCounter(t, reg,
			"kacho_iam_registry_token_credential_kind_total", map[string]string{"outcome": o})
		require.True(t, present, "серия исхода %q обязана существовать после наблюдения", o)
		require.Equal(t, want, got, "исход %q посчитан неверно", o)
	}
}

// Реализация ОБЯЗАНА удовлетворять порту use-case'а: адаптер, не подходящий по
// форме, обнаружился бы только в композиционном корне — то есть на сборке
// процесса, а не здесь.
func TestRegistryTokenCredentialKindRecorder_SatisfiesTheUseCasePort(t *testing.T) {
	reg := NewRegistry()
	var _ registrytokenuc.CredentialKindObserver = reg.NewRegistryTokenCredentialKindRecorder()
}

// Единственность экземпляра: потребитель один, но реестр падает на повторной
// регистрации, а собирается полоса в композиционном корне, где второй вызов
// стоит одной строки невнимательности.
func TestRegistryTokenCredentialKindRecorder_IsASingleInstance(t *testing.T) {
	reg := NewRegistry()
	require.Same(t,
		reg.RegistryTokenCredentialKindRecorder(),
		reg.RegistryTokenCredentialKindRecorder(),
		"экземпляр обязан быть один: повторная регистрация коллектора роняет старт")
}
