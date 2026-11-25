// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listfilter

import (
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/filter"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Label — точное совпадение пары из обычных меток ресурса.
type Label struct {
	Key   domain.LabelKey
	Value string
}

type Expression struct {
	*filter.FilterAST
	Label *Label
}

// Parse разбирает одно сравнение по разрешённому полю или по labels.<ключ>.
func Parse(expr string, fields []string) (*Expression, error) {
	const prefix = "labels."
	input := strings.TrimSpace(expr)
	if !strings.HasPrefix(input, prefix) {
		ast, err := filter.Parse(input, fields)
		if err != nil || ast == nil {
			return nil, err
		}
		return &Expression{FilterAST: ast}, nil
	}

	field, remainder := input, ""
	if end := strings.IndexAny(input, "= \t\r\n"); end >= 0 {
		field, remainder = input[:end], input[end:]
	}
	key := domain.LabelKey(strings.TrimPrefix(field, prefix))
	if err := key.Validate(); err != nil {
		return nil, &filter.ParseError{Column: len(prefix) + 1, Message: err.Error()}
	}

	// Парсер corelib принимает идентификаторы колонок. Подставляем допустимый
	// идентификатор той же длины, чтобы сохранить позиции ошибок в выражении.
	parserField := strings.Repeat("x", len(field))
	ast, err := filter.Parse(parserField+remainder, []string{parserField})
	if err != nil {
		if parseErr, ok := err.(*filter.ParseError); ok {
			parseErr.Message = strings.ReplaceAll(parseErr.Message, fmt.Sprintf("%q", parserField), fmt.Sprintf("%q", field))
		}
		return nil, err
	}
	if ast.Op != filter.OpEquals {
		return nil, &filter.ParseError{
			Column:  len(field) + len(remainder) - len(strings.TrimLeft(remainder, " ")) + 1,
			Message: fmt.Sprintf("Operator %s is not supported for filter field %q. Label filters accept only =", ast.Op, field),
		}
	}
	ast.Field = field
	return &Expression{FilterAST: ast, Label: &Label{Key: key, Value: ast.Value}}, nil
}
