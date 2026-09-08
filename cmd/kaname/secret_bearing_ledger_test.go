// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// secret_bearing_ledger_test.go — ПОМЕЧЕННОЕ ПОЛЕ-НОСИТЕЛЬ ОБЯЗАНО СТОЯТЬ В
// ПЕРЕЧНЕ ПОДМЕТАЛЬЩИКА (задача #1142, приёмка BAT-1 §4.3.2–§4.3.3,
// сценарий BAT-1-73).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОИЗВОДИТЕЛЬ ВХОДА — ОПЦИЯ КОНТРАКТА, А НЕ ПЕРЕЧЕНЬ ИМЁН РЯДОМ С ГЕЙТОМ
//
// Гейт, чей вход выписан там же, где проверяемое, сравнивает перечень САМ С
// СОБОЙ: новое непомеченное поле-носитель не краснит его никогда. Здесь вход
// приходит из ДЕСКРИПТОРОВ — из опции `kacho.cloud.api.secret_bearing`,
// поставленной в самом контракте, — и перечень подметальщика проверяется
// против него.
//
// ЧИТАЮТСЯ ДЕСКРИПТОРЫ, А НЕ ТЕКСТ. Поиск по образцу над исходником не
// отличает объявление поля от строкового литерала и от комментария, который эту
// же пометку объясняет, и остаётся зелёным при СНЯТОЙ пометке.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ СУЖЕНА ПЕРЕСЕЧЕНИЕМ, И ЭТО НЕ КОСМЕТИКА
//
// Требование адресовано помеченному полю сообщения, КОТОРОЕ НАЗВАНО ответом
// операции. Помеченное поле синхронного ответа в перечне стоять НЕ ОБЯЗАНО:
// перечень ключуется типом ответа, а синхронный ответ в таблицу операций не
// попадает вовсе. Без сужения гейт требовал бы вносить в перечень то, чего
// подметальщик увидеть не может, — и был бы снят первым же ложным срабатом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЭТО ОСЬ 1 ИЗ ДВУХ; ОСЬ 2 ЖИВЁТ В ДРУГОМ ПАКЕТЕ, И ЭТО НЕ СЛУЧАЙНО
//
// Ось 1 сверяет ПОМЕЧЕННЫЕ поля с перечнем подметальщика. На НЕПОМЕЧЕННОМ поле
// она молчит by construction — то есть случай «завели поле-носитель и забыли
// пометить» она не ловит ВОВСЕ. Его ловит ось 2 (имя выглядит секретом ⇒
// помечено либо названо в ведомости исключений):
// `internal/repohygiene` `TestBAT1_73_Axis2_NoUnmarkedSecretOnTheSurface`
// (задача #1217).
//
// Оси разведены по пакетам потому, что судят РАЗНЫЕ множества: оси 1 нужен
// перечень подметальщика — он живёт здесь, в композиционном корне; оси 2 нужен
// ВЕСЬ контракт, а набор дескрипторов ЭТОГО прогона покрывает только то, что
// слинковано в этот бинарь. Содержание оси 2 здесь не пересказывается: два
// места об одном предмете расходятся молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ ДЕРЖИТ — НАЗВАНО, ЧТОБЫ ЕГО НЕ СОЧЛИ ПОЛНЫМ ПОКРЫТИЕМ
//
//	поле-носитель, ЧЬЁ ИМЯ НИ НА ЧТО НЕ ПОХОЖЕ и которое не пометили — не ловится
//	ничем механическим; держит обзор изменения контракта;
//	ПРАВИЛЬНОСТЬ пометки — помеченное поле, секретом не являющееся, даёт лишнюю
//	запись; последствие безвредно, и различить это гейт не может;
//	ПОВЕДЕНИЕ подметальщика в рантайме — гейт утверждает согласие ОБЪЯВЛЕНИЯ с
//	перечнем, а не то, что стирание происходит.

package main

import (
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	apiv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/api"
)

// secretBearingFields — все поля дерева контрактов, помеченные носителем
// секрета. Перечислимы ИЗ ДЕСКРИПТОРОВ; сегодня их немного, и число печатается.
func secretBearingFields(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		msgs := fd.Messages()
		for i := 0; i < msgs.Len(); i++ {
			md := msgs.Get(i)
			fields := md.Fields()
			for j := 0; j < fields.Len(); j++ {
				f := fields.Get(j)
				if isSecretBearing(f) {
					name := string(md.FullName())
					out[name] = append(out[name], string(f.Name()))
				}
			}
		}
		return true
	})
	return out
}

// marked читает саму опцию расширения. Именно ЧТЕНИЕ ОПЦИИ, а не совпадение
// имени: имя — это ось 2, и она про другое.
func isSecretBearing(f protoreflect.FieldDescriptor) bool {
	v := proto.GetExtension(f.Options(), apiv1.E_SecretBearing)
	b, ok := v.(bool)
	return ok && b
}

// operationResponseTypes — сообщения, НАЗВАННЫЕ ответом операции. Второй
// производитель входа, и он тоже уже существующее соглашение контракта:
// аннотация операции у RPC несёт поле `response`, называющее тип.
func operationResponseTypes(t *testing.T) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			methods := svcs.Get(i).Methods()
			for j := 0; j < methods.Len(); j++ {
				m := methods.Get(j)
				ext := proto.GetExtension(m.Options(), apiv1.E_Operation)
				op, ok := ext.(*apiv1.Operation)
				if !ok || op == nil || op.GetResponse() == "" {
					continue
				}
				// Имя в аннотации — короткое, в пакете своего сервиса.
				out[string(fd.Package())+"."+op.GetResponse()] = struct{}{}
			}
		}
		return true
	})
	return out
}

// TestBAT1_73_EverySecretBearingOperationResponseFieldIsInTheSweeperLedger —
// сам гейт.
func TestBAT1_73_EverySecretBearingOperationResponseFieldIsInTheSweeperLedger(t *testing.T) {
	marked := secretBearingFields(t)
	responses := operationResponseTypes(t)

	// ПЕРЕПИСЬ: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	t.Logf("осмотрено: сообщений с помеченными полями %d, типов-ответов операции %d",
		len(marked), len(responses))
	if len(responses) == 0 {
		t.Fatal("типов-ответов операции ноль — предпосылка гейта отсутствует, он молчал бы " +
			"и тогда, когда предмет исчез")
	}
	if len(marked) == 0 {
		t.Fatal("помеченных полей ноль — производителя входа нет, и гейт беспредметен")
	}

	// Перечень подметальщика — тот же, что исполняется в рантайме. Второй копии
	// здесь не заводится: копия разошлась бы молча.
	ledger := map[string]map[string]struct{}{}
	for _, tgt := range secretSweepTargets(
		"type.googleapis.com/kaname.cloud.iam.v1.IssueSAKeyResponse",
		"type.googleapis.com/kaname.cloud.iam.v1.IssueUserTokenResponse",
	) {
		full := strings.TrimPrefix(tgt.ResponseType, "type.googleapis.com/")
		set := map[string]struct{}{}
		for _, f := range tgt.Fields {
			set[f] = struct{}{}
		}
		ledger[full] = set
	}

	// ТОТ ЖЕ предикат, что прогоняет инъекция. Второй копии не заводится:
	// доказанной оказалась бы копия, а исполнялся бы оригинал.
	findings, checked := ledgerFindings(marked, responses, ledger)
	t.Logf("осмотрено: помеченных полей в ответах операций %d", checked)
	if checked == 0 {
		t.Fatal("пересечение пусто — гейт отработал на ПУСТОМ множестве и покраснеть не мог")
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("поля-носители секрета, не названные в перечне подметальщика: %v.\n"+
			"Поле, которого перечень не называет, подметальщик ПРОПУСКАЕТ, и таблица "+
			"операций читается чистой навсегда — отсутствие записи неотличимо от "+
			"«поле проверено и чисто».", findings)
	}
}
