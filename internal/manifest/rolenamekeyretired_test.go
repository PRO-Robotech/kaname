// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// rolenamekeyretired_test.go — у роли манифеста НЕТ ключа `name`
// (задача PRO-Robotech/kacho#1906).
//
// # Предмет
//
// Ключ был ОБЯЗАТЕЛЕН и не читался ничем, кроме собственного валидатора. Автор
// манифеста был обязан его заполнить, получал успех — и написанное им не
// доезжало ни до базы, ни до арендатора: применитель кладёт в строку роли
// ИДЕНТИФИКАТОР (`domain.RoleName(mr.ID)`), а колонки под человекочитаемое имя у
// роли нет вовсе. Это «принято-и-проигнорировано» (`api-conventions.md`) в худшей
// его форме: пустым поле оставить было нельзя.
//
// # Три оси, и третья — сторона КОНТРАКТА
//
//  1. ключ в документе — отказ формы, называющий сам ключ;
//  2. тот же документ без ключа — законный близнец, проходит (без него отрицание
//     зеленело бы на загрузчике, отвергающем всякую роль);
//  3. опубликованная схема ключа не объявляет и не требует — иначе снятие
//     осталось бы половинчатым: инструмент говорил бы «манифест годен», а
//     продукт отвечал бы отказом, то есть два правила об одном поле.
package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// retiredRoleProseKey — снятый ключ. Отдельным значением, а не строкой в
// литерале: см. `roleWithNameKey`.
const retiredRoleProseKey = "na" + "me"

// roleWithoutNameKey — роль манифеста в её нынешней форме: идентификатор,
// назначение, ярус, выдачи. Человекочитаемого имени здесь нет.
const roleWithoutNameKey = "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
	"  - id: vpc.viewer\n    description: Читает топологию проекта.\n" +
	"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
	"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n"

// roleWithNameKey — тот же документ плюс снятый ключ.
//
// Ключ собирается ИЗ ЧАСТЕЙ намеренно: сплошной литерал `\n    name: …`
// вычищается всякой переписью, которая ищет снятый ключ по дереву проб, — и
// испорченный документ стал бы дословно равен годному, а отрицание проверяло бы
// законный вход.
const roleWithNameKey = "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
	"  - id: vpc.viewer\n    " + retiredRoleProseKey + ": Наблюдатель\n" +
	"    description: Читает топологию проекта.\n" +
	"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
	"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n"

// TestRoleNameKeyIsRetiredFromTheContract — снятый ключ отвергается формой, а
// документ без него проходит.
func TestRoleNameKeyIsRetiredFromTheContract(t *testing.T) {
	// Законный близнец ПЕРВЫМ: отрицание ниже иначе зеленело бы на загрузчике,
	// который отвергает документ по любой другой причине.
	if _, err := Load([]byte(roleWithoutNameKey)); err != nil {
		t.Fatalf("роль без снятого ключа отвергнута: %v", err)
	}

	_, err := Load([]byte(roleWithNameKey))
	if err == nil {
		t.Fatalf("снятый ключ roles[].name принят")
	}
	if !errors.Is(err, ErrShape) {
		t.Errorf("отказ не отнесён к форме документа: %v", err)
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("отказ не называет ключа: %v", err)
	}

	t.Logf("перепись: осей формы две — снятый ключ отвергнут, документ без него прочитан")
}

// TestPublishedSchemaDoesNotDeclareRoleName — сторона КОНТРАКТА: схема ключа не
// объявляет и не требует.
//
// Без этой оси снятие осталось бы половинчатым, и расхождение было бы тихим:
// инструмент по схеме говорил бы «манифест годен», а продукт отвечал бы отказом
// формы — два правила об одном поле, из которых действует одно.
func TestPublishedSchemaDoesNotDeclareRoleName(t *testing.T) {
	raw, err := os.ReadFile(publishedSchemaPath)
	if err != nil {
		t.Fatalf("опубликованная схема не прочитана: %v", err)
	}
	var doc map[string]any
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		t.Fatalf("опубликованная схема не разбирается: %v", uerr)
	}

	items := roleItemsSchema(t, doc)

	props, ok := items["properties"].(map[string]any)
	if !ok || len(props) == 0 {
		t.Fatalf("свойств у роли в схеме не найдено — обход пуст, и молчание пробы "+
			"было бы неотличимо от снятия ключа: %v", items["properties"])
	}
	if _, declared := props["name"]; declared {
		t.Errorf("схема объявляет roles[].name — ключ снят с загрузчика, и контракт " +
			"обещал бы то, чего разбор не принимает")
	}

	required, ok := items["required"].([]any)
	if !ok || len(required) == 0 {
		t.Fatalf("обязательных ключей у роли в схеме не найдено — перепись пуста: %v",
			items["required"])
	}
	for _, r := range required {
		if r == "name" {
			t.Errorf("схема ТРЕБУЕТ roles[].name — исполнимого входа у неё нет ни одного")
		}
	}

	_, stillDeclared := props["name"]
	t.Logf("перепись: свойств роли в схеме %d · обязательных %d · ключ name объявлен: %v",
		len(props), len(required), stillDeclared)
}

// roleItemsSchema — узел `properties.roles.items` опубликованной схемы.
func roleItemsSchema(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	props, ok := doc["properties"].(map[string]any)
	if !ok {
		t.Fatalf("у схемы нет properties верхнего уровня")
	}
	roles, ok := props["roles"].(map[string]any)
	if !ok {
		t.Fatalf("у схемы нет properties.roles")
	}
	items, ok := roles["items"].(map[string]any)
	if !ok {
		t.Fatalf("у схемы нет properties.roles.items")
	}
	return items
}
