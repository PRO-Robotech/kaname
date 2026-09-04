// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// catalog_type_reader.go — pg-адаптер: точечное имя КАТАЛОГА по имени типа
// МОДЕЛИ, из строк `kacho_iam.catalog_resource` (kacho#1990).
//
// Обратное направление того же перехода, что читает зеркало у себя
// (`pg/resource_mirror/model_dictionary.go`, #1982). Второго словаря от этого не
// заводится: соответствие нигде не вычисляется — оно ЧИТАЕТСЯ из строки, куда
// его положил манифест модуля.
//
// Оператор исполняется на транзакции вызывающего и НИКОГДА на соединении пула:
// перевод обязан лежать в одном снимке с записью зеркала, иначе между «спросил»
// и «вставил» помещается снятие типа.
package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// CatalogTypeReader — адаптер порта чтения словаря каталога. Без состояния.
type CatalogTypeReader struct{}

// NewCatalogTypeReader — конструктор композиционного корня.
func NewCatalogTypeReader() *CatalogTypeReader { return &CatalogTypeReader{} }

// DottedTypeTx отдаёт точечное имя каталога по имени типа модели.
//
// ПОРЯДОК `live DESC` НЕСУЩИЙ, А НЕ КОСМЕТИЧЕСКИЙ. Строк по имени типа не более
// двух: ключ `catalog_resource_object_type_live_uk UNIQUE (object_type, live)`
// допускает по одной на каждое значение `live`. Живая отвечает на вопрос
// «каким именем регистрировать сейчас», снятая — «каким именем лежит то, что
// зарегистрировали раньше». Читай только живую — и объект, переживший снятие
// своего типа, стал бы неудаляемым; читай без порядка — исход решал бы план
// запроса.
//
// `ok=false` означает «строки нет вовсе». Пустая строка при этом НЕ
// возвращается как значение: пустая подстановка совпала бы с пустым значением
// колонки и превратила бы «типа не знаем» в «совпало».
func (r *CatalogTypeReader) DottedTypeTx(
	ctx context.Context, tx service.Tx, modelType string,
) (string, bool, error) {
	var dotted string
	err := txAsPgx(tx).QueryRow(ctx,
		`SELECT dotted
		   FROM kacho_iam.catalog_resource
		  WHERE object_type = $1
		  ORDER BY live DESC
		  LIMIT 1`,
		modelType).Scan(&dotted)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("catalog_resource: точечное имя типа %q: %w", modelType, err)
	}
	return dotted, true, nil
}
