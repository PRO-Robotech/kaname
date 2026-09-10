// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_link_collision_test.go — НИ ОДНО ИМЯ, КОТОРОЕ ЧИТАЕТ ЗАГРУЗКА, НЕ
// ПРИНИМАЕТ ЗНАЧЕНИЕ ОТ КЛАСТЕРА ВМЕСТО ЗНАЧЕНИЯ ОПЕРАТОРА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
//	Р1  ОПЫТ ПО НАБЛЮДАВШЕМУСЯ ЗНАЧЕНИЮ: подстановка кластера даёт ОТКАЗ
//	    РАЗБОРА, называющий ручку, а не падение на открытии слушателя;
//	Р2  ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: голый номер порта по-прежнему двигает
//	    слушатель — без него отказ мог бы отвергать всё;
//	Р3  ГЕЙТ КЛАССА: перечень имён ВЫВЕДЕН оттуда же, откуда его выводит
//	    процесс, и у каждого совпавшего с формой кластера объявлена ФОРМА
//	    значения, а отказ доказан вызовом;
//	Р4  перепись печатается величинами по каждой оси: «ноль находок» обязано
//	    быть отличимо от «ноль прочитанного».
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ БЕХАВИОРАЛЬНЫЙ, А НЕ ТЕКСТОВЫЙ
//
// Спрашивать «объявлена ли форма» — значит судить объявление. Спрашивается
// другое: ЧТО СДЕЛАЕТ загрузка, если подать ей то, что подставит кластер.
// Производитель входа — сама `Load`, вердикт выносится по её исходу.
package config_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// clusterInjectedValueFor — значение, которое подставил бы кластер переменной
// этой формы. Собирается по грамматике, а не выписывается одной строкой:
// у формы адреса значение не порт, и обратное дало бы опыт не о том входе.
func clusterInjectedValueFor(form string) string {
	switch {
	case strings.HasSuffix(form, "_ADDR"), strings.HasSuffix(form, "_SERVICE_HOST"):
		return "10.96.66.181"
	case strings.HasSuffix(form, "_PROTO"):
		return "tcp"
	case strings.HasSuffix(form, "_SERVICE_PORT"), strings.HasSuffix(form, "_<ПОРТ>"):
		return "9091"
	default:
		return "tcp://10.96.66.181:9091"
	}
}

// Р1 — ОПЫТ ПО НАБЛЮДАВШЕМУСЯ ЗНАЧЕНИЮ.
//
// Значение взято дословно из отказа поставки: служба `kaname-internal` дала
// поду `KANAME_INTERNAL_PORT=tcp://10.96.66.181:9091`, сборка адреса склеила из
// него `tcp://0.0.0.0:tcp://10.96.66.181:9091`, и процесс упал на ОТКРЫТИИ
// слушателя — последним шагом старта, после отчёта о всей посадке.
//
// Утверждается НАБЛЮДАЕМОЕ: отказ приходит от РАЗБОРА НАСТРОЕК и называет
// ручку. Не «адрес получился другой» — адрес не должен получиться вовсе.
func TestClusterInjectedPortRefusesTheLoadAndNamesTheKnob(t *testing.T) {
	t.Setenv("KANAME_INTERNAL_PORT", "tcp://10.96.66.181:9091")

	_, err := config.Load("")

	require.Error(t, err, "подстановка кластера обязана ОТВЕРГАТЬ разбор настроек: "+
		"иначе адрес слушателя собирается из неё и отказ приходит от библиотеки "+
		"на открытии слушателя — последним шагом, без имени ручки")
	require.Contains(t, err.Error(), "KANAME_INTERNAL_PORT",
		"отказ обязан называть РУЧКУ: оператор видит адрес, которого не задавал, "+
			"и без имени ручки следующего шага у него нет")
	require.Contains(t, err.Error(), "tcp://10.96.66.181:9091",
		"отказ обязан называть ПОЛУЧЕННОЕ значение: оператор его не задавал и "+
			"обязан увидеть, что именно пришло")
}

// Р2 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ отказа.
//
// Без него отказ Р1 зеленел бы на страже, отвергающем ЛЮБОЕ значение: ручка
// перестала бы работать, а проба этого не показала бы.
func TestBarePortStillMovesTheListener(t *testing.T) {
	t.Setenv("KANAME_INTERNAL_PORT", "19091")

	cfg, err := config.Load("")
	require.NoError(t, err, "голый номер порта — законное значение ручки")
	require.Equal(t, "0.0.0.0:19091", cfg.APIServer.InternalListenAddress(),
		"ручка обязана двигать слушатель: страж формы её не отменяет")
}

// Р2' — тот же контроль для публичного слушателя и для порта базы: страж
// объявлен по ФОРМЕ значения, а не по одной ручке, и обязан пропускать
// законное на каждой.
func TestBarePortStillMovesThePublicListenerAndTheDatabasePort(t *testing.T) {
	t.Setenv("KANAME_GRPC_PORT", "19090")
	t.Setenv("KANAME_DB_HOST", "db.example")
	t.Setenv("KANAME_DB_PORT", "6432")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0:19090", cfg.APIServer.ListenAddress())
	require.Contains(t, cfg.Repository.Postgres.URL, "db.example:6432")
}

// Р3+Р4 — ГЕЙТ КЛАССА.
//
// Перечень имён выводится ТЕМ ЖЕ способом, каким его выводит процесс: ключи
// viper (умолчания + привязки) плюс плоские легаси-псевдонимы из объявления
// службы. Второй, выписанный от руки список разошёлся бы с процессом молча.
func TestNoEnvNameTheProcessReadsTakesItsValueFromTheCluster(t *testing.T) {
	names := map[string]string{}

	v := viper.New()
	config.RegisterDefaults(v)
	for _, k := range v.AllKeys() {
		names[config.EnvNameOfKey(k)] = "ключ настроек " + k
	}
	derivedFromKeys := len(names)
	for _, n := range config.MTLSEnvNames() {
		names[n] = "поле посадки транспорта"
	}
	derivedFromMTLS := len(names) - derivedFromKeys
	for _, n := range config.FlatEnvKnobNames() {
		names[n] = "плоский псевдоним"
	}

	// ЯКОРЬ ВЫВОДА ИМЁН ПОСАДКИ ТРАНСПОРТА. Правило вывода принадлежит общему
	// фундаменту, здесь оно повторено (см. MTLSEnvNames) — значит может
	// разойтись. Одно выведенное имя обязано ДОЕЗЖАТЬ до своего поля: без якоря
	// перепись считала бы имена, которых процесс не читает, и «ноль совпадений»
	// означало бы «считал не то».
	t.Run("якорь: выведенное имя посадки транспорта доезжает до поля", func(t *testing.T) {
		const anchor = "KANAME_PUBLIC_SERVER_MTLS_ENABLE"
		require.Contains(t, config.MTLSEnvNames(), anchor,
			"вывод имён посадки транспорта разошёлся с фундаментом: якорное имя не выведено")
		t.Setenv(anchor, "true")
		m, err := config.LoadMTLS()
		require.NoError(t, err)
		require.True(t, m.PublicServerMTLS.Enable,
			"%s не доезжает до поля — правило вывода имён разошлось с фундаментом, и "+
				"перепись считает имена, которых процесс не читает", anchor)
	})

	all := make([]string, 0, len(names))
	for n := range names {
		all = append(all, n)
	}
	sort.Strings(all)

	var flat, colliding, guarded int
	for _, n := range all {
		if !strings.Contains(n, "__") {
			flat++
		}
		form, collides := config.ClusterServiceLinkForm(n)
		if !collides {
			continue
		}
		colliding++

		declared, hasShape := config.FlatEnvKnobGuardsItsValue(n)
		if !declared {
			t.Errorf("%s (%s): имя читается загрузкой и совпадает с формой %s, которой "+
				"кластер сам объявляет поду адреса служб, — но формы значения у ручки НЕ "+
				"ОБЪЯВЛЕНО. Подстановка кластера перебьёт величину оператора молча. "+
				"Исходы: объявить форму значения в flatEnvKnobs либо перевести ручку на "+
				"путь ключа (его имя viper выводит с `__`, а кластер двойного "+
				"подчёркивания не производит)", n, names[n], form)
			continue
		}
		if !hasShape {
			t.Errorf("%s (%s): совпадает с формой %s, форма значения объявлена "+
				"произвольной — то есть страж пропустит подстановку кластера", n, names[n], form)
			continue
		}

		// Вердикт по ИСХОДУ, а не по объявлению: подаём то, что подставит
		// кластер, и требуем отказа, называющего ручку.
		//
		// Каждое имя — в СВОЁМ подтесте: `t.Setenv` живёт до конца теста, поэтому
		// в общем цикле вторая итерация меняла бы ДВА факта разом, и отказ
		// приходил бы от ручки, заданной предыдущей. Наблюдалось на этом же гейте:
		// отказ на `KANAME_INTERNAL_PORT` называл `KANAME_GRPC_PORT`.
		name, form := n, form
		ok := t.Run(name, func(t *testing.T) {
			t.Setenv(name, clusterInjectedValueFor(form))
			_, err := config.Load("")
			if err == nil {
				t.Errorf("%s: подстановка кластера формы %s ПРИНЯТА разбором настроек — "+
					"значение оператора перебито молча", name, form)
				return
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("%s: отказ есть, но имени ручки не называет: %v — оператор не "+
					"узнает, что именно править", name, err)
			}
		})
		if ok {
			guarded++
		}
	}

	if derivedFromKeys == 0 {
		t.Fatalf("обход пуст: ключей настроек выведено 0 — «находок ноль» здесь неотличимо " +
			"от «ноль прочитанного», и вердикт беспредметен")
	}
	if colliding == 0 {
		t.Fatalf("с формой кластера не совпало НИ ОДНО имя из %d при %d плоских: "+
			"распознаватель перестал их видеть, и молчание меры ничего не означает "+
			"(форм у кластера восемь, и хотя бы одна ручка порта у службы есть)",
			len(all), flat)
	}

	t.Logf("перепись: имён осмотрено %d (из ключей настроек %d · полей посадки транспорта %d · "+
		"плоских псевдонимов %d) · плоских имён %d · совпало с формой кластера %d · "+
		"из них отказ доказан вызовом %d",
		len(all), derivedFromKeys, derivedFromMTLS, len(config.FlatEnvKnobNames()),
		flat, colliding, guarded)
}
