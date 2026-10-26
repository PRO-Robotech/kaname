// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_type_reader.go — pg-адаптер: точечное имя КАТАЛОГА по имени типа
// МОДЕЛИ, из строк `kaname.catalog_resource` (kacho#1990).
//
// Обратное направление того же перехода, что читает зеркало у себя
// (`pg/resource_mirror/model_dictionary.go`, kacho#1982). Второго словаря от этого не
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

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
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
		   FROM kaname.catalog_resource
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

// WritePolicyTx — политика записи модуля на тип (kaname#982, Р1) и точечное имя
// каталога из ЖИВОЙ строки, одним чтением в транзакции регистрации.
//
// `typeName` — имя типа, каким его назвал кортеж: словарь модели либо уже
// каталога (у имён словарей пересечения нет — точка у каталога есть всегда, у
// модели никогда, поэтому одно условие выбирает не больше одной живой строки).
//
// `live=false` — живой строки нет: тип не известен платформе либо снят. Такой
// тип политика и вывод не судят — его отвергает строка зеркала, как и прежде
// (Р3), поэтому промах здесь не отказ, а «судить нечем».
//
// Читается ТОЛЬКО живая строка: политика снятого типа не действует, а снятие
// объекта такого типа ей и не подлежит (Р11).
func (r *CatalogTypeReader) WritePolicyTx(
	ctx context.Context, tx service.Tx, typeName string,
) (string, domain.WritePolicy, bool, error) {
	var (
		dotted, objectType   string
		names, types, writes []string
		permanent            bool
	)
	err := txAsPgx(tx).QueryRow(ctx,
		`SELECT dotted, object_type, parent_names, parent_types, writes, permanent_project
		   FROM kaname.catalog_resource
		  WHERE (object_type = $1 OR dotted = $1) AND live`,
		typeName).Scan(&dotted, &objectType, &names, &types, &writes, &permanent)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", domain.WritePolicy{}, false, nil
	case err != nil:
		return "", domain.WritePolicy{}, false, fmt.Errorf("catalog_resource: политика записи типа %q: %w", typeName, err)
	}
	// Парность имён и типов держит проверка колонки
	// (`catalog_resource_parent_names_form`); расхождение здесь — повреждённая
	// строка, и судить по ней регистрацию нельзя ни в одну сторону.
	if len(names) != len(types) {
		return "", domain.WritePolicy{}, false, fmt.Errorf(
			"catalog_resource: у типа %q имён указателей %d при типах %d", typeName, len(names), len(types))
	}
	policy := domain.WritePolicy{ObjectType: objectType, PermanentProject: permanent}
	for i := range names {
		policy.Pointers = append(policy.Pointers, domain.ParentPointer{Name: names[i], Type: types[i]})
	}
	for _, tok := range writes {
		g, ok := domain.ParseWriteGrant(tok)
		if !ok {
			return "", domain.WritePolicy{}, false, fmt.Errorf(
				"catalog_resource: у типа %q запись writes %q не той формы", typeName, tok)
		}
		policy.Writes = append(policy.Writes, g)
	}
	return dotted, policy, true, nil
}
