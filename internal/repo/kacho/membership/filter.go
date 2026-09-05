// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// filter.go — белый список терма и объявленный оператор, В ОДНОМ МЕСТЕ.
//
// Мест, которым нужен этот разбор, ДВА: use-case отвергает негодный терм ДО
// обращения к хранилищу (отказ обязан быть синхронным и не оплачиваться
// запросом), а адаптер остаётся авторитетным — он строит предикат и обязан
// отвечать одинаково независимо от того, кто его позвал. Две копии правила
// разошлись бы молча: обе отвечают «годно» на годном входе, и расхождение
// проявилось бы только на негодном, то есть там, где его никто не смотрит.

import (
	"github.com/PRO-Robotech/kacho/pkg/filter"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// FilterFieldUserID — единственный терм белого списка.
//
// Имя КОНТРАКТНОЕ (camelCase, как все JSON-поля продукта); колонка называется
// иначе, поэтому предикат строится на колонке явно, а не на имени поля: `userId`
// свернулся бы в SQL в несуществующий `userid` и падал бы на каждом вызове.
const FilterFieldUserID = "userId"

// FilterColumnUserID — колонка, на которой строится предикат.
const FilterColumnUserID = "m.user_id"

// ParseListFilter разбирает выражение фильтра и отвергает всё, что эта
// поверхность не заводила.
//
// Пустое выражение — (nil, nil): фильтра нет, условие не добавляется.
//
// ОПЕРАТОР ЧИТАЕТСЯ ЯВНО. Грамматика продукта знает два: равенство и подстрочный
// поиск. Здесь заведено только равенство — подстрочный поиск по идентификатору
// человека никто не решал заводить, у него нет ни кейса, ни индекса, и
// обслуживался бы он последовательным обходом аккаунта. Из трёх законных исходов
// («реализовать · отвергнуть явно · снять с контракта») выбран второй; свести
// молча к равенству — не исход: вызывающий получил бы уверенный и неверный ответ
// на запрос поиска.
func ParseListFilter(expr string) (*filter.FilterAST, error) {
	ast, err := filter.Parse(expr, []string{FilterFieldUserID})
	if err != nil {
		return nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if ast == nil {
		return nil, nil
	}
	if ast.Op != filter.OpEquals {
		return nil, iamerr.Wrapf(iamerr.ErrInvalidArg,
			"Bad expression. Unsupported operator for field %q: only equality is supported",
			FilterFieldUserID)
	}
	return ast, nil
}
