// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// connbudget_guard_test.go — страж пропускной способности пула в ОБЕ стороны.
//
// Предмет здесь — состав отказа этой службы: сходятся ли предел пула, бюджет
// реплик и предел базы в одно утверждение и называет ли отказ ручки, которые
// оператор пойдёт править. Способность прочитать предел у настоящей базы
// проверена там, где она живёт (`pkg/db`, на живом Postgres).

import (
	"strings"
	"testing"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// Ровно та посадка, на которой это и намерили: пул 100 на реплику, пять реплик,
// база принимает 200.
func TestConnBudgetComplaint_RefusesTheMeasuredPosture(t *testing.T) {
	err := connBudgetComplaint(100, 5, coredb.ConnCeiling{MaxConnections: 200, SuperuserReserved: 3})
	if err == nil {
		t.Fatal("500 обещанных соединений против 197 принимаемых — старт разрешён. Служба " +
			"обещает себе больше, чем база готова дать, и узнаёт об этом отказом ровно " +
			"тогда, когда соединения понадобились")
	}
	// Отказ читает ОПЕРАТОР: он обязан называть ручки и числа.
	for _, want := range []string{
		"KANAME_REPOSITORY__POSTGRES__MAX_CONNS",
		"KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET",
		"max_connections", "100", "5", "500",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в отказе нет %q — отказ, не сказавший что чинить, стенд не поднимет:\n%v",
				want, err)
		}
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: посадка, которая помещается, стартовать не мешает. Без него
// «отвергнуто» было бы неотличимо от «отвергается всё».
func TestConnBudgetComplaint_LetsAFittingPostureStart(t *testing.T) {
	if err := connBudgetComplaint(30, 5, coredb.ConnCeiling{MaxConnections: 200, SuperuserReserved: 3}); err != nil {
		t.Fatalf("150 обещанных против 197 доступных отвергнуты: %v", err)
	}
}

// Необъявленный бюджет — отказ, а не пропуск: ноль обращает произведение в ноль.
func TestConnBudgetComplaint_UndeclaredBudgetIsRefused(t *testing.T) {
	if err := connBudgetComplaint(100, 0, coredb.ConnCeiling{MaxConnections: 200, SuperuserReserved: 3}); err == nil {
		t.Error("бюджет реплик не объявлен — старт разрешён: «не объявлено» стало бы " +
			"означать «не ограничиваем»")
	}
}
