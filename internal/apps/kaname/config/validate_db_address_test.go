// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// validate_db_address_test.go — незаданный адрес базы обязан быть ОТКАЗОМ СТАРТА,
// а не бессрочным молчаливым ожиданием.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Страж уже отвергал строку подключения — но только ЦЕЛИКОМ пустую. Чарт же
// собирает её из частей (`postgres://<user>@<host>:<port>/<db>`), поэтому при
// незаданном адресе базы она выходит НЕПУСТОЙ и с пустым хостом:
//
//	postgres://iam@:5432/kaname
//
// То есть по пути чарта прежний предикат не мог сработать НИ ПРИ КАКОМ входе:
// величина, которую он судит, непуста by construction. Предикат оказался уже
// своего предмета, и настоящий отказ оператора проходил мимо него.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ПРОИСХОДИЛО ВМЕСТО ОТКАЗА — наблюдалось в кластере
//
// Установка с незаданным адресом базы (единственный изменённый факт) не давала
// ни отказа, ни текста: контейнер миграций оставался в `running` с НУЛЁМ байт
// журнала больше двух с половиной минут, ожидая базу, которой не будет никогда.
// Оператор видит под, застрявший в `Init:0/1`, и ни одного слова о причине.
//
// Ожидание базы само по себе законно и нужно: база поднимается рядом и может
// быть ещё не готова. Незаконно — НЕ РАЗЛИЧАТЬ «база ещё не поднялась»
// (временное, ожидание уместно) и «адрес не задан» (постоянное, ожидание
// бессмысленно). Это тот же класс, что мягкий проход, не отличающий сбой от
// настройки: контроль присутствует, исполняется на каждом старте и не отказывает
// никогда.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СУДИТСЯ ХОСТ, А НЕ ПУСТОТА СТРОКИ
//
// Предмет — адрес, по которому процесс пойдёт. Строка непуста ровно тогда, когда
// её собрал шаблон, и о достижимости базы это не говорит ничего. Судить надо ту
// величину, ОТСУТСТВИЕ которой делает посадку неисполнимой.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestValidate_RefusesDSNWithoutAHost — отрицание: адрес не задан, отказ обязан
// назвать ручку и причину.
//
// Форма строки — ДОСЛОВНО та, что рендерит `templates/configmap.yaml` при
// незаданном `db.host`: проба судит вход, который производит поставка, а не
// придуманный.
func TestValidate_RefusesDSNWithoutAHost(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.Repository.Postgres.URL = "postgres://iam@:5432/kaname"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal: адрес базы не задан, и ожидание её никогда не сойдётся")
	}
	if !strings.Contains(err.Error(), "repository.postgres.url") {
		t.Fatalf("отказ обязан называть ручку repository.postgres.url, получено: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "host") {
		t.Fatalf("отказ обязан называть причину (отсутствующий хост), получено: %q", err.Error())
	}
}

// TestValidate_AcceptsDSNWithAHost — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию выше.
//
// Без него отрицание зеленело бы на страже, отвергающем любую строку подключения,
// — то есть на сломанной поставке.
func TestValidate_AcceptsDSNWithAHost(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.Repository.Postgres.URL = "postgres://iam@pg:5432/kaname"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %q, want nil: адрес базы задан, отвергать нечего", err.Error())
	}
}

// TestValidate_StillRefusesAWhollyEmptyDSN — прежнее свойство не отозвано.
//
// Расширение предиката обязано ДОБАВЛЯТЬ, а не замещать: строка, пустая целиком,
// остаётся отказом, и отказ по-прежнему называет ручку.
func TestValidate_StillRefusesAWhollyEmptyDSN(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.Repository.Postgres.URL = "   "

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal for a wholly empty DSN")
	}
	if !strings.Contains(err.Error(), "repository.postgres.url") {
		t.Fatalf("отказ обязан называть ручку repository.postgres.url, получено: %q", err.Error())
	}
}

// TestValidate_RefusalDoesNotEchoTheDBPassword — зеркало пробы точки наката:
// текст отказа стража службы тоже не несёт пароля.
//
// По пути чарта строка подключения в конфигурации пароля НЕ содержит (он
// приезжает переменной окружения и подставляется позже), но страж принимает
// строку из любого источника, а «сегодня она без пароля» — свойство сегодняшнего
// шаблона, а не стража. Обеззараживание судится здесь, чтобы оно не зависело от
// того, кто именно собрал величину.
func TestValidate_RefusalDoesNotEchoTheDBPassword(t *testing.T) {
	const password = "s3cret-never-in-a-log"
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.Repository.Postgres.URL = "postgres://iam:" + password + "@:5432/kaname"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal for a hostless DSN")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("текст отказа несёт пароль базы — он уезжает в журнал пода: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "repository.postgres.url") {
		t.Fatalf("обеззараживание не должно съедать имя ручки, получено: %q", err.Error())
	}
}
