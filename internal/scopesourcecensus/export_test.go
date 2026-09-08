// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scopesourcecensus_test

import "github.com/PRO-Robotech/kaname/internal/scopesourcecensus"

// PlansForTest — перечень типов, о которых перепись обязана высказаться.
//
// Проба берёт его У ВЛАДЕЛЬЦА, а не выписывает: выписанный не сдвинулся бы от
// нового типа и продолжал бы сторожить прежние — то есть проба перестала бы
// проверять ровно то свойство, ради которого написана.
func PlansForTest() ([]scopesourcecensus.TypePlan, error) { return scopesourcecensus.Plans() }
