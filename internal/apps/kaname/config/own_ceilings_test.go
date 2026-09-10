// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// own_ceilings_test.go — ТРИ СОБСТВЕННЫХ ПОТОЛКА ОБЪЯВЛЯЕТ ПОСАДКА, и незаданная
// величина роняет старт (приёмка `KAN-QUOTA-1`, `П25`, сценарий `KAN-Q3-06`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТИ ТРИ ВЕЛИЧИНЫ НЕ МОГУТ ИМЕТЬ УМОЛЧАНИЯ
//
// Служба доступа перестаёт быть авторитетом величин, но три её собственных
// потолка остаются действующими: сколько аккаунтов заводит одна личность и
// сколько путей входа держит человек и машина. В самостоятельной установке
// внешнего авторитета нет **by construction**, поэтому спросить величину не у
// кого — её объявляет посадка.
//
// Умолчание здесь было бы не удобством, а ВЫБОРОМ ЗА ОПЕРАТОРА, сделанным
// молча: величина, которую подставляет построение, предметом стража быть не
// может — он зелен при любом входе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ ИСХОДА ОДНОЙ ВЕЛИЧИНЫ РАЗЛИЧИМЫ, И ЭТО НЕСУЩЕЕ
//
//	величина отсутствует  → отказ старта, назван вид
//	величина отрицательна → отказ старта, назван вид И значение
//	величина равна нулю   → СТАРТ ПРОХОДИТ; ноль означает «этого вида не заводить»
//
// Без третьей строки ноль был бы неотличим от отсутствия, и оператор, желающий
// запретить вид, не смог бы этого выразить ни при каком вводе. Именно поэтому
// поле — указатель, а не число: отсутствие представимо ОТДЕЛЬНО от значения.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ownCeilingsShapedConfig — форма YAML, которой посадка объявляет три величины.
// Ноль стоит намеренно: он законная величина, и проба обязана его пронести.
const ownCeilingsShapedConfig = `
own-ceilings:
  accounts-per-identity: 1
  credentials-per-user: 2
  credentials-per-service-account: 0
`

// TestOwnCeilingFileKeysArmTheFields — ключи файла ДОЕЗЖАЮТ до полей, включая
// явный ноль.
//
// Без этой пробы опечатка в ключе (`own-ceiling` вместо `own-ceilings`) выглядит
// В ТОЧНОСТИ как «посадка величину не объявила»: viper незнакомый ключ
// игнорирует, поле остаётся незаданным, страж отказывает — и оператор, задавший
// ровно названное, получает тот же отказ, не имея способа отличить свою ошибку
// от нашей.
func TestOwnCeilingFileKeysArmTheFields(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, ownCeilingsShapedConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	oc := cfg.OwnCeilings
	if oc.AccountsPerIdentity == nil || *oc.AccountsPerIdentity != 1 {
		t.Fatalf("accounts-per-identity не доехал до поля: %v", oc.AccountsPerIdentity)
	}
	if oc.CredentialsPerUser == nil || *oc.CredentialsPerUser != 2 {
		t.Fatalf("credentials-per-user не доехал до поля: %v", oc.CredentialsPerUser)
	}
	// ЯВНЫЙ НОЛЬ — отдельное утверждение, а не частный случай: он и есть та
	// величина, которую теряет всякий, кто читает «не задано» как «ноль».
	if oc.CredentialsPerServiceAccount == nil {
		t.Fatal("явный ноль потерян: поле осталось незаданным, то есть " +
			"«запретить вид» невыразимо ни при каком вводе")
	}
	if *oc.CredentialsPerServiceAccount != 0 {
		t.Fatalf("credentials-per-service-account: ждали 0, получили %d",
			*oc.CredentialsPerServiceAccount)
	}
}

// TestOwnCeilingEnvVarsArmTheFields — ПЕРЕМЕННЫЕ, названные текстом отказа,
// доезжают до полей.
//
// `AutomaticEnv` разрешает переменную только для ключа, который viper УЖЕ знает:
// у этих трёх умолчания нет намеренно, поэтому без явной привязки в `load.go`
// документированное имя не доехало бы до поля ВООБЩЕ. Отказ называл бы ровно ту
// переменную, которую оператор как раз задал.
func TestOwnCeilingEnvVarsArmTheFields(t *testing.T) {
	t.Setenv("KANAME_OWN_CEILINGS__ACCOUNTS_PER_IDENTITY", "7")
	t.Setenv("KANAME_OWN_CEILINGS__CREDENTIALS_PER_USER", "0")
	t.Setenv("KANAME_OWN_CEILINGS__CREDENTIALS_PER_SERVICE_ACCOUNT", "9")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	oc := cfg.OwnCeilings
	if oc.AccountsPerIdentity == nil || *oc.AccountsPerIdentity != 7 {
		t.Fatalf("переменная accounts-per-identity не доехала: %v", oc.AccountsPerIdentity)
	}
	if oc.CredentialsPerUser == nil || *oc.CredentialsPerUser != 0 {
		t.Fatalf("переменная credentials-per-user не доехала (ноль!): %v", oc.CredentialsPerUser)
	}
	if oc.CredentialsPerServiceAccount == nil || *oc.CredentialsPerServiceAccount != 9 {
		t.Fatalf("переменная credentials-per-service-account не доехала: %v",
			oc.CredentialsPerServiceAccount)
	}
}

// TestOwnCeilingsHaveNoDefault — ЗАКОННЫЙ БЛИЗНЕЦ обеих проб выше и предпосылка
// стража: без объявления величины остаются НЕЗАДАННЫМИ.
//
// Проба существует затем, чтобы «страж отказывает» не оказалось вакуумным
// утверждением: появись у ключей умолчание — отказ стал бы недостижим, а обе
// пробы выше остались бы зелёными.
func TestOwnCeilingsHaveNoDefault(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	oc := cfg.OwnCeilings
	if oc.AccountsPerIdentity != nil || oc.CredentialsPerUser != nil ||
		oc.CredentialsPerServiceAccount != nil {
		t.Fatalf("у величины появилось умолчание — страж стал недостижим: %+v", oc)
	}
}

// TestOwnCeilingRefusalNamesTheKind — незаданная величина роняет старт, и отказ
// называет ВИД, а не «квоту».
func TestOwnCeilingRefusalNamesTheKind(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("пустая посадка принята: страж трёх собственных потолков не сработал")
	}
	msg := err.Error()
	for _, want := range []string{
		"iam.account",
		"iam.user.credential",
		"iam.serviceAccount.credential",
		"own-ceilings.accounts-per-identity",
		"KANAME_OWN_CEILINGS__ACCOUNTS_PER_IDENTITY",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("текст отказа не называет %q; получено:\n%s", want, msg)
		}
	}
}

// TestOwnCeilingRefusalNamesTheNegativeValue — отрицательная величина роняет
// старт и называет ВИД И ЗНАЧЕНИЕ.
//
// Отрицательное НЕ означает «без ограничения»: такое прочтение сняло бы потолок
// значением, которое выглядит опечаткой.
func TestOwnCeilingRefusalNamesTheNegativeValue(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, `
own-ceilings:
  accounts-per-identity: -1
  credentials-per-user: 2
  credentials-per-service-account: 2
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	msg := ""
	if verr := cfg.OwnCeilings.Validate(); verr != nil {
		msg = verr.Error()
	}
	if msg == "" {
		t.Fatal("отрицательная величина принята")
	}
	for _, want := range []string{"iam.account", "-1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("текст отказа не называет %q; получено:\n%s", want, msg)
		}
	}
}

// TestOwnCeilingZeroPassesTheGuard — ЗАКОННЫЙ БЛИЗНЕЦ отрицания: явный ноль
// стражем не отвергается.
//
// Без этой пробы страж, отвергающий ВСЁ, был бы зелёным по обеим отрицательным.
func TestOwnCeilingZeroPassesTheGuard(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, `
own-ceilings:
  accounts-per-identity: 0
  credentials-per-user: 0
  credentials-per-service-account: 0
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if verr := cfg.OwnCeilings.Validate(); verr != nil {
		t.Fatalf("явный ноль отвергнут стражем: %v", verr)
	}
}

// TestOwnCeilingKnobsAllHaveARequiredSettingRow — СОГЛАСИЕ ДВУХ ОБЪЯВЛЕНИЙ, в
// обе стороны.
//
// Таблица величин (`own_ceilings.go`) объявляет ключ, переменную и вид; таблица
// обязательных величин (`required_settings.go`) порождает из неё строку документа
// оператора. Расхождение молчаливо by construction: одну правят коммитом в один
// файл, другую — в другой, и увидит его только тот, кто в этот день ставит службу.
//
// Проверяется ОБЕ разности множеств. Одной было бы мало: «каждый потолок имеет
// строку» зеленеет на таблице с лишней строкой, а «каждая строка имеет потолок» —
// на таблице, где потолка нет вовсе.
func TestOwnCeilingKnobsAllHaveARequiredSettingRow(t *testing.T) {
	const prefix = "own-ceilings."

	fromKnobs := map[string]bool{}
	for _, k := range config.OwnCeilingKnobs {
		fromKnobs[k.Key] = true
	}
	fromTable := map[string]bool{}
	for _, s := range config.RequiredSettings {
		if strings.HasPrefix(s.Key, prefix) {
			fromTable[s.Key] = true
		}
	}

	t.Logf("перепись: величин посадки %d, строк документа с приставкой %q %d",
		len(fromKnobs), prefix, len(fromTable))

	if len(fromKnobs) == 0 {
		t.Fatal("величин посадки ноль — обе разности пусты тривиально, " +
			"и проба ничего не утверждает")
	}
	for key := range fromKnobs {
		if !fromTable[key] {
			t.Errorf("величина %s объявлена стражем и НЕ НАЗВАНА документом оператора: "+
				"он узнает о ней из текста отказа, по одной за перезапуск", key)
		}
	}
	for key := range fromTable {
		if !fromKnobs[key] {
			t.Errorf("документ называет %s, а стража у неё нет: строка обещает "+
				"величину, которой процесс не требует", key)
		}
	}
}

// TestOwnCeilingKnobEnvNamesAreDerivedFromTheirKeys — имя переменной ВЫВОДИТСЯ
// из ключа тем же правилом, каким его выводит viper.
//
// Второе написание — самый дешёвый способ получить документированную ручку без
// читателя: отказ называет одно имя, привязка регистрирует другое, и оператор
// упирается в цикл, не имея способа отличить свою ошибку от нашей.
func TestOwnCeilingKnobEnvNamesAreDerivedFromTheirKeys(t *testing.T) {
	for _, k := range config.OwnCeilingKnobs {
		want := "KANAME_" + strings.ToUpper(
			strings.NewReplacer(".", "__", "-", "_").Replace(k.Key))
		if k.Env != want {
			t.Errorf("ключ %s: переменная объявлена %q, а viper выведет %q — "+
				"документированная ручка не доедет до поля", k.Key, k.Env, want)
		}
	}
}
