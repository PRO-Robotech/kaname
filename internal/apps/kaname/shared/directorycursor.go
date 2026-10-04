// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// directorycursor.go — курсор списков справочника адресов (приёмка NTF-3 Р7;
// замысел З27, CX3B-48).
//
// # Почему форма — параметр одной функции
//
// У списков справочника порядок выдачи разный: `ListProjectAudience` выдаёт
// пользователей по id (своего `created_at` у элемента нет — он выведен из
// одной или нескольких привязок), список истекающих учётных данных — по паре
// «момент истечения, id». Курсор у каждого — позиция последнего выданного
// элемента, но позиция разной формы. Два кодека разошлись бы молча на
// мусорном входе, поэтому кодек один, а форма позиции — его параметр
// ([DirectoryCursorForm]).
//
// Тело — каноническая форма фундамента (`corelib/pagetoken`), перед ним —
// метка формы: токен одного списка не разбирается другим, и токен прежней
// формы не принимается за этот. Точка не входит в алфавит base64, поэтому
// метка отделяется структурно.
//
// # Кто зовёт
//
// Проверка формата и путь чтения зовут ОДНУ функцию разбора: сценарий
// использования разбирает курсор первым стейтментом и отдаёт репозиторию уже
// разобранную позицию, второго разбора ниже нет.

import (
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/pagetoken"
)

// DirectoryCursorForm — форма позиции курсора списка справочника.
type DirectoryCursorForm struct {
	// tag — метка формы на проводе; часть значения: смена ломает выданные
	// курсоры и потому — смена контракта, а не рефакторинг.
	tag string
	// keyed — позиция несёт ключ времени перед id; без ключа момент времени
	// в теле обязан быть нулевым.
	keyed bool
}

// AudienceCursor — курсор `ListProjectAudience`: позиция — id последнего
// выданного пользователя.
var AudienceCursor = DirectoryCursorForm{tag: "rda1.", keyed: false}

// DirectoryPosition — позиция последнего выданного элемента.
type DirectoryPosition struct {
	// Key — ключ порядка перед id; нулевой у формы без ключа.
	Key time.Time
	// ID — идентификатор элемента.
	ID string
}

// EncodeDirectoryPageToken — токен позиции p формы f.
func EncodeDirectoryPageToken(f DirectoryCursorForm, p DirectoryPosition) string {
	key := p.Key
	if !f.keyed {
		key = time.Time{}
	}
	return f.tag + pagetoken.Encode(pagetoken.Cursor{CreatedAt: key, ID: p.ID})
}

// DecodeDirectoryPageToken — позиция токена формы f. Пустой токен — первая
// страница: (nil, nil). Всё прочее, что не токен этой формы, —
// INVALID_ARGUMENT с именем поля field.
func DecodeDirectoryPageToken(f DirectoryCursorForm, field, token string) (*DirectoryPosition, error) {
	if token == "" {
		return nil, nil
	}
	refusal := InvalidArg(field, field+": malformed page token")
	body, ok := strings.CutPrefix(token, f.tag)
	if !ok {
		return nil, refusal
	}
	c, ok := pagetoken.Decode(body)
	if !ok || c == nil {
		return nil, refusal
	}
	if !f.keyed && !c.CreatedAt.IsZero() {
		return nil, refusal
	}
	return &DirectoryPosition{Key: c.CreatedAt, ID: c.ID}, nil
}
