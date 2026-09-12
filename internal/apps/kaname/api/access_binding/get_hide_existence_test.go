// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// get_hide_existence_test.go — скрытие существования у ЧТЕНИЯ одной привязки
// закреплено на уровне Go.
//
// # Предмет: асимметрия трёх глаголов, которую никто не решал
//
// Промах чтения привязки отвечает отказом в правах, а не «не найдено»: иначе по
// различимому ответу отличают «нет доступа» от «не существует», то есть ровно то,
// что скрытие и должно закрыть. У правки и удаления это утверждение стоит рядом с
// кодом (`get_error_mapping_test.go`), у чтения его не было НИ НА КАКОМ уровне,
// доступном модульному прогону.
//
// Замер, из которого выведена проба (задача `PRO-Robotech/kacho#2561`): дефект
// продукта — промах чтения отображается общим переводчиком ошибок
// (`shared.MapRepoErr`) вместо `authzguard.PermissionDenied()` — оставлял
// `go test ./... -short` службы доступа ЗЕЛЁНЫМ: 112 пакетов `ok`, ноль красных
// проб, код возврата 0. Тот же дефект в соседних глаголах краснит их пробу
// перевода ошибок немедленно.
//
// # Утверждается СООБЩЕНИЕ, а не только код
//
// Различимый ТЕКСТ и есть оракул существования: два ответа с одним кодом и
// разными словами разделяют «нет такой строки» и «строка есть, доступа нет» так
// же надёжно, как разные коды. Поэтому проба сверяет ответ промаха с ответом
// НАСТОЯЩЕГО отказа в правах — дословно, включая перечень подробностей: одна
// лишняя подробность у одной из полос вернула бы оракул при совпадающем тексте.
//
// # Положительный контроль обязателен
//
// Утверждение «обе полосы отвечают одинаковым отказом» истинно на use-case,
// который отказывает ВСЕМ. Поэтому рядом стоит чтение той же привязки её
// субъектом — оно обязано пройти. Без него проба зеленела бы на сломанном
// продукте.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// hideExistenceAbsentID — well-formed идентификатор привязки, которой нет.
// Форма годная (префикс `acb` + 17 знаков): иначе синхронная проверка формы
// отвергла бы вход ДО чтения, и полоса промаха осталась бы непройденной.
const hideExistenceAbsentID domain.AccessBindingID = "acb0000000000000hide"

// TestGetAccessBinding_MissAnswersByteIdenticallyToARealDenial — промах чтения и
// настоящий отказ в правах неразличимы для вызывающего.
func TestGetAccessBinding_MissAnswersByteIdenticallyToARealDenial(t *testing.T) {
	const (
		ownerID   = "usr0000000000000ownr"
		accountID = "acc00000000000ba01ab"
		projectID = "prj0000000000000proj"
		roleID    = "rol0000000000000view"
		subjectID = "usr000000000000grant"
	)

	repo := newABFakeRepo(ownerID, accountID, projectID, roleID, "kaname.view", nil)
	existing := seedClusterBinding(repo, subjectID)

	// Обе полосы читает ОДИН И ТОТ ЖЕ use-case с ОДНИМ И ТЕМ ЖЕ вызывающим:
	// различие миров ровно одно — существует ли спрошенная привязка.
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(&denyingFGA{}, nil)
	stranger := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000outsidr"})

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ──────────────────────────────────────────────
	// Субъект привязки читает её успешно. Без этой половины утверждение ниже
	// было бы истинно и на чтении, отказывающем всем.
	subject := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: subjectID})
	got, err := uc.Execute(subject, existing)
	require.NoErrorf(t, err, "субъект привязки обязан её читать: без этого сравнение "+
		"двух отказов ниже истинно на чтении, отказывающем ВСЕМ")
	require.Equal(t, existing, got.ID)

	// ── НАСТОЯЩИЙ ОТКАЗ: привязка ЕСТЬ, прав нет ────────────────────────────
	_, denyErr := uc.Execute(stranger, existing)
	require.Error(t, denyErr, "посторонний обязан получить отказ на существующей привязке")
	denial := status.Convert(denyErr)

	// ── ПРОМАХ: привязки НЕТ ────────────────────────────────────────────────
	_, missErr := uc.Execute(stranger, hideExistenceAbsentID)
	require.Error(t, missErr, "чтение отсутствующей привязки обязано отказывать")
	miss := status.Convert(missErr)

	// ── ТОГДА: ответы неразличимы ───────────────────────────────────────────
	canonical := status.Convert(authzguard.PermissionDenied())

	require.Equalf(t, codes.PermissionDenied, miss.Code(),
		"промах чтения ответил кодом %s: по нему отличают «не существует» от «нет доступа», "+
			"то есть ответ стал оракулом существования", miss.Code())
	require.Equalf(t, denial.Code(), miss.Code(),
		"коды разошлись: настоящий отказ %s, промах %s", denial.Code(), miss.Code())
	require.Equalf(t, denial.Message(), miss.Message(),
		"ТЕКСТЫ разошлись при совпавшем коде — различимый текст и есть оракул: "+
			"настоящий отказ говорит %q, промах %q", denial.Message(), miss.Message())
	require.Equalf(t, canonical.Message(), miss.Message(),
		"промах отвечает не каноническим текстом отказа (%q вместо %q): вторая редакция "+
			"одного отказа разойдётся с первой молча", miss.Message(), canonical.Message())
	require.Lenf(t, miss.Details(), len(denial.Details()),
		"перечни подробностей разной длины (%d против %d): подробность, приложенная к одной "+
			"полосе, возвращает оракул при совпавшем тексте",
		len(miss.Details()), len(denial.Details()))
	require.Emptyf(t, miss.Details(),
		"отказ несёт подробности: скрытие существования обязано отвечать least-info")

	t.Logf("перепись: полос сравнено 2 (промах, настоящий отказ), положительный контроль 1; "+
		"код %s, текст %q, подробностей %d", miss.Code(), miss.Message(), len(miss.Details()))
}
