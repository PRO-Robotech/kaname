// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// schema_guard_test.go — состав отказа стража прежней схемы, в ОБЕ стороны.
//
// Предмет здесь — СОСТАВЛЕНИЕ отказа: называет ли он обнаруженную схему, базу,
// ручку и следующий шаг оператора. Способность увидеть схему у настоящего
// Postgres проверена рядом, на живой базе
// (`schema_guard_integration_test.go`), — тот же разрез, что у соседнего
// стража бюджета соединений.
//
// Отрицание идёт В ПАРЕ с положительным контролем: чистая установка обязана
// проходить. Без этой половины «отвергнуто» было бы неотличимо от
// «отвергается всё», и страж, ломающий каждый старт, выглядел бы работающим.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Прежняя установка: схема отставленного имени есть, схемы продукта нет.
func TestRetiredSchemaComplaint_RefusesAPreviousInstall(t *testing.T) {
	err := retiredSchemaComplaint("kacho_iam_prod", true, false)
	if err == nil {
		t.Fatal("база несёт схему прежней установки — старт разрешён. Служба создала бы " +
			"пустую схему продукта и начала бы работать поверх пустого, а прежние строки " +
			"остались бы рядом невидимыми: арендатор потерял бы данные молча")
	}
	// Отказ читает ОПЕРАТОР в три часа ночи. Он обязан назвать: что найдено,
	// где найдено, почему это не дефект продукта, и что делать дальше.
	for _, want := range []string{
		retiredSchemaName,     // что найдено
		"kacho_iam_prod",      // где найдено — база названа поимённо
		canonicalSchemaName,   // с чем служба работает
		postgresURLEnvName,    // ручка, которой меняют базу
		migratorUpCommand,     // чем накатывают схему на чистую
		installDocPath,        // где написан порядок установки
		"состояние окружения", // это НЕ дефект продукта
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в отказе нет %q — отказ, не восстанавливающий следующий шаг, "+
				"есть находка, а не строгость:\n%v", want, err)
		}
	}
}

// Обе схемы рядом: отказ обязан назвать ОБЕ. Молчание об одной из них оставило
// бы оператора выбирать вслепую, а служба читала бы ту, которую выберет порядок
// search_path.
func TestRetiredSchemaComplaint_RefusesBothSchemasSideBySide(t *testing.T) {
	err := retiredSchemaComplaint("kacho_iam_prod", true, true)
	if err == nil {
		t.Fatal("обе схемы рядом — старт разрешён. Какую из них читает служба, решал бы " +
			"порядок search_path: данные выбирались бы молча")
	}
	for _, want := range []string{retiredSchemaName, canonicalSchemaName, "kacho_iam_prod", postgresURLEnvName} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в отказе на две схемы рядом нет %q:\n%v", want, err)
		}
	}
	// Тексты двух состояний обязаны РАЗЛИЧАТЬСЯ: «прежняя установка» и «две
	// схемы рядом» чинятся по-разному, и один текст на оба вернул бы оператора
	// к угадыванию.
	prev := retiredSchemaComplaint("kacho_iam_prod", true, false)
	if prev != nil && prev.Error() == err.Error() {
		t.Error("отказ на прежнюю установку и отказ на две схемы рядом дословно совпали: " +
			"состояния разные, и чинятся они разными действиями")
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: чистая установка стартовать не мешает.
func TestRetiredSchemaComplaint_LetsACleanInstallStart(t *testing.T) {
	if err := retiredSchemaComplaint("kaname_prod", false, true); err != nil {
		t.Fatalf("чистая установка отвергнута — страж ломает штатный старт: %v", err)
	}
}

// Второй законный близнец: схемы продукта ещё нет, отставленной — тоже.
// Ось этого стража — ОТСТАВЛЕННАЯ схема, и о ненакаченной цепи миграций он не
// утверждает ничего. Граница названа здесь, чтобы молчание не приняли за
// покрытие: отсутствие схемы продукта — предмет другого стража.
func TestRetiredSchemaComplaint_SaysNothingAboutAMissingCanonicalSchema(t *testing.T) {
	if err := retiredSchemaComplaint("fresh_db", false, false); err != nil {
		t.Fatalf("страж прежней схемы отверг базу, где отставленной схемы НЕТ: %v", err)
	}
}

// Координата, названная отказом, обязана существовать. Без этой пробы ссылка
// на инструкцию установки пережила бы её переезд и отсылала бы в никуда —
// ровно тот класс, ради которого отказ и пишется.
func TestRetiredSchemaComplaint_CitesADocumentThatExists(t *testing.T) {
	// Пакет лежит в `cmd/kaname`, корень модуля — двумя уровнями выше.
	path := filepath.Join("..", "..", installDocPath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("отказ отсылает к %q, а документа в дереве нет (%v): ссылка в место, "+
			"которого не существует, хуже отсутствия ссылки", installDocPath, err)
	}
	// Мало того, что документ есть: он обязан нести КОМАНДУ, которую отказ велит
	// выполнить. Переименуют бинарь миграций — покраснеет здесь, а не у оператора.
	if !strings.Contains(string(body), migratorUpCommand) {
		t.Errorf("отказ велит выполнить %q, а инструкция установки %q этой команды не "+
			"называет: оператор пойдёт по ссылке и не найдёт того, что ему сказали",
			migratorUpCommand, installDocPath)
	}
	// И документ обязан знать САМО ПОЛОЖЕНИЕ, из-за которого оператор в него
	// пришёл. Ссылка на страницу, где о его случае не сказано, отсылает к
	// порядку установки вообще — а он пришёл с базой прежней установки.
	if !strings.Contains(string(body), schemaOfThePreviousInstall) {
		t.Errorf("инструкция установки %q не называет схему %q: оператор, пришедший по "+
			"ссылке из отказа, своего случая на странице не найдёт",
			installDocPath, schemaOfThePreviousInstall)
	}
}

// Ручка, названная отказом, обязана быть той, которой оператор меняет базу.
// Что она доезжает до поля, доказано опытом в разборе настройки
// (`config.TestDocumentedEnvName_PostgresURL`); здесь — что отказ называет
// именно её, а не соседнюю.
func TestRetiredSchemaComplaint_NamesTheKnobThatChangesTheDatabase(t *testing.T) {
	if postgresURLEnvName != "KANAME_REPOSITORY__POSTGRES__URL" {
		t.Fatalf("отказ называет ручкой базы %q — оператор задаст её и не изменит ничего",
			postgresURLEnvName)
	}
}
