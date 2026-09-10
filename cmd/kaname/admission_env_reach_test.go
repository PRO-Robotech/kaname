// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// admission_env_reach_test.go — величины допуска ДОСЯГАЕМЫ переменной окружения,
// и неполный набор, поданный ею же, РОНЯЕТ СТАРТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТОГО НЕ ЗАКРЫВАЕТ СОСЕДНЯЯ ПРОБА ФАЙЛА
//
// Рядом живёт проба, подающая те же восемь ключей ФАЙЛОМ настроек. Она зелена и
// о переменных окружения не утверждает ничего: viper разрешает переменную
// только для ключа, который он УЖЕ знает, а знает он ключ по умолчанию либо по
// привязке. Ключ, объявленный одним лишь тегом структуры, файлом читается
// (`Unmarshal` идёт по тегам) и переменной — НЕТ.
//
// Для службы, поставляемой ОТДЕЛЬНО от платформы, переменная окружения и есть
// путь профиля: чарта монорепо у такой установки нет. Значит недосягаемость
// ручки здесь равна её отсутствию.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ УТВЕРЖДАЮТСЯ ОБЕ ПОЛОВИНЫ, А НЕ ОДНА
//
// Половина «величина доехала» зеленела бы при сломанной второй: набор из одной
// оси прошёл бы молча, процесс остался бы на полу платформы, и оператор считал
// бы предел выставленным. Половина «неполный набор отвергнут» зеленела бы при
// сломанной первой: незадействованная переменная даёт пустой набор, а пустой
// набор законен — это молчание посадки.
//
// Обе половины спрашиваются на ТОМ ЖЕ пути, которым идёт старт: загрузка
// настроек плюс [admissionLimits]. Проба, зовущая `Resolve` напрямую, закрепила
// бы ОТВЕТ механизма, а не досягаемость ручки, — и осталась бы зелёной ровно на
// том дефекте, ради которого написана.
package main

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Имена переменных НЕ выводятся здесь из ключа кодом — они выписаны так, как их
// набирает оператор. Вывод повторил бы правило преобразования viper и оказался
// бы верен по построению: проба зеленела бы на любом правиле, включая неверное.
const (
	envPublicReadPerSec     = "KANAME_API_SERVER__RATE_LIMIT__PUBLIC__READ_PER_SEC"
	envPublicMutationPerSec = "KANAME_API_SERVER__RATE_LIMIT__PUBLIC__MUTATION_PER_SEC"
	envPublicBurstFactor    = "KANAME_API_SERVER__RATE_LIMIT__PUBLIC__BURST_FACTOR"
	envPublicInFlight       = "KANAME_API_SERVER__RATE_LIMIT__PUBLIC__IN_FLIGHT"

	envInternalReadPerSec     = "KANAME_API_SERVER__RATE_LIMIT__INTERNAL__READ_PER_SEC"
	envInternalMutationPerSec = "KANAME_API_SERVER__RATE_LIMIT__INTERNAL__MUTATION_PER_SEC"
	envInternalBurstFactor    = "KANAME_API_SERVER__RATE_LIMIT__INTERNAL__BURST_FACTOR"
	envInternalInFlight       = "KANAME_API_SERVER__RATE_LIMIT__INTERNAL__IN_FLIGHT"
)

// TestAdmissionKnobsReachTheProcessThroughEnv — ПЕРВАЯ половина: величины,
// поданные переменными окружения, доезжают до обоих слушателей.
//
// Значения выбраны заведомо не равными полу платформы: совпадение сделало бы
// утверждение тождественно истинным — оно проходило бы и тогда, когда ни одна
// переменная не прочитана.
func TestAdmissionKnobsReachTheProcessThroughEnv(t *testing.T) {
	t.Setenv(envPublicReadPerSec, "7")
	t.Setenv(envPublicMutationPerSec, "3")
	t.Setenv(envPublicBurstFactor, "2")
	t.Setenv(envPublicInFlight, "5")
	t.Setenv(envInternalReadPerSec, "70")
	t.Setenv(envInternalMutationPerSec, "30")
	t.Setenv(envInternalBurstFactor, "4")
	t.Setenv(envInternalInFlight, "50")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("загрузка настроек: %v", err)
	}

	public, internal, err := admissionLimits(cfg)
	if err != nil {
		t.Fatalf("полный набор, поданный переменными окружения, отвергнут: %v", err)
	}

	wantPublic := grpcsrv.AdmissionLimits{ReadPerSec: 7, MutationPerSec: 3, BurstFactor: 2, InFlight: 5}
	if public != wantPublic {
		t.Errorf("публичный слушатель: получено %s, объявлено %s\n\n"+
			"Ручка принимается профилем и не читается процессом: viper разрешает "+
			"переменную только для ИЗВЕСТНОГО ключа, а ключ известен ему по "+
			"умолчанию либо по привязке. Восемь ключей секции не имеют ни того, "+
			"ни другого — и у отдельно поставленной службы другого пути профиля нет",
			public.String(), wantPublic.String())
	}

	wantInternal := grpcsrv.AdmissionLimits{ReadPerSec: 70, MutationPerSec: 30, BurstFactor: 4, InFlight: 50}
	if internal != wantInternal {
		t.Errorf("внутренний слушатель: получено %s, объявлено %s",
			internal.String(), wantInternal.String())
	}

	if public == internal {
		t.Errorf("оба слушателя прочитали одно и то же (%s) — значит переменные "+
			"совпали, и посадка не может задать им разные величины", public.String())
	}
}

// TestPartialAdmissionKnobsFromEnvRefuseTheStart — ВТОРАЯ половина: неполный
// набор, поданный переменными окружения, отвергается с именем слушателя.
//
// Обещание отказа стоит в комментарии самой структуры настроек; файлом оно
// исполняется. Пока ключ переменной неизвестен viper'у, тот же вход через
// окружение даёт ПУСТОЙ набор — то есть законное молчание посадки, — и отказ не
// приходит НИКОГДА: процесс остаётся на полу платформы, а оператор считает, что
// назвал свои величины.
func TestPartialAdmissionKnobsFromEnvRefuseTheStart(t *testing.T) {
	t.Setenv(envPublicReadPerSec, "7")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("загрузка настроек: %v", err)
	}

	_, _, err = admissionLimits(cfg)
	if err == nil {
		t.Fatalf("неполный набор, поданный переменной окружения, ПРИНЯТ молча — " +
			"старт не отвергнут. Именно этот вход опаснее всех прочих: он " +
			"выглядит настройкой и не ограничивает по незаполненным осям")
	}
	if !strings.Contains(err.Error(), "api-server.rate-limit.public") {
		t.Errorf("отказ не называет слушателя: %v\n\n"+
			"Искать ось оператор пойдёт в профиль, где, по его мнению, всё "+
			"написано верно, — поэтому отказ обязан назвать, ЧЕЙ набор неполон",
			err)
	}
}

// TestAdmissionKnobsSilentEnvTakesThePlatformFloor — ЗАКОННЫЙ БЛИЗНЕЦ обеих
// половин: без единой переменной ручки молчат, и это НЕ отказ, а пол платформы.
//
// Без этой пробы отрицание выше зеленело бы на реализации, отвергающей всякий
// вход, а утверждение о досягаемости — на реализации, подставляющей числа
// откуда угодно.
func TestAdmissionKnobsSilentEnvTakesThePlatformFloor(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("загрузка настроек: %v", err)
	}

	public, internal, err := admissionLimits(cfg)
	if err != nil {
		t.Fatalf("молчание посадки отвергнуто как негодный набор: %v", err)
	}
	if public != grpcsrv.PlatformPublicAdmission() {
		t.Errorf("публичный слушатель без объявленных величин получил %s, а не пол платформы %s",
			public.String(), grpcsrv.PlatformPublicAdmission().String())
	}
	if internal != grpcsrv.PlatformInternalAdmission() {
		t.Errorf("внутренний слушатель без объявленных величин получил %s, а не пол платформы %s",
			internal.String(), grpcsrv.PlatformInternalAdmission().String())
	}
	if !cfg.APIServer.RateLimit.Public.IsSilent() || !cfg.APIServer.RateLimit.Internal.IsSilent() {
		t.Errorf("незаданные ручки не молчат (public=%+v internal=%+v) — журнал напечатает "+
			"from_posture=true там, где посадка не называла ничего",
			cfg.APIServer.RateLimit.Public, cfg.APIServer.RateLimit.Internal)
	}
}
