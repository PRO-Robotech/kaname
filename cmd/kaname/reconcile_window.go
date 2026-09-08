// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/authz"
)

// Вторая ступень цепочки отзыва гранта — пересчёт производного пообъектного
// доступа у владельца прав.
//
// # Что здесь ступень, а что нет
//
// Отзыв выдачи снимает строку в базе iam немедленно. Производный пообъектный
// доступ в хранилище прав снимает реконсайлер, и путей у него три: ускоритель
// сразу после коммита (в пределе — ноль), очередь сверки, будимая уведомлением,
// и внешний backstop — периодический обход. Первые два быстры и оба зависят от
// доставки сигнала; ступенью в худшем случае служит ТРЕТИЙ, и его величину
// назначает ручка посадки.
//
// # Почему ручка обязана судиться при старте
//
// Ровно по тому же доводу, что и окно кэша вердиктов на крае: величина, которую
// при старте никто не судит, означает, что посадка вправе назначить окно любой
// длины, и отзыв не будет действовать всё это время. Разница между «видно» и
// «оценивается» — это `security.md` §«Кто вправе ГОВОРИТЬ ЗА пользователя»,
// п. (г): три части контроля без четвёртой дают контроль, которого не видно
// либо который не работает.
//
// # Почему потолок не объявлен ЗДЕСЬ
//
// Потолок принадлежит цепочке, а не одной её ступени: сумма трёх слагаемых и
// есть «столько действует отозванная выдача». Объявленный рядом с ручкой, он
// стал бы вторым местом об одном предмете и разошёлся бы с политикой молча —
// поэтому он читается из `pkg/authz.RevocationPolicy`, где объявлены все три.
const (
	reconcileSweepKnob = "KANAME_RECONCILE_SWEEP_INTERVAL_MS"
	reconcileDrainKnob = "KANAME_RECONCILE_DRAIN_INTERVAL_MS"
)

// reconcileWindows — величины второй ступени, с которыми процесс БУДЕТ работать.
type reconcileWindows struct {
	// Sweep — полный периодический обход (backstop). Он и есть ступень в худшем
	// случае: сюда полоса приходит, когда уведомление потеряно.
	Sweep time.Duration
	// Drain — poll-fallback очереди сверки на пропущенное уведомление. Судится
	// тем же потолком: он лежит ВНУТРИ ступени, и обогнать её не вправе.
	Drain time.Duration
}

// readReconcileWindows читает обе ручки один раз.
//
// Читается ЗДЕСЬ, а не на месте сборки воркера, потому что судить и применять
// обязана одна и та же пара величин: прочтя ручку дважды, страж и воркер
// разошлись бы на посадке, где переменную меняли между вызовами.
func readReconcileWindows() reconcileWindows {
	return reconcileWindows{
		Sweep: envDurationMS(reconcileSweepKnob, 30*time.Second),
		Drain: envDurationMS(reconcileDrainKnob, 1*time.Second),
	}
}

// validate отвергает старт, когда объявленная величина шире потолка ступени.
//
// Отказ, а не предупреждение и не молчаливое приведение: приведение сделало бы
// величину, которую оператор объявил, отличной от той, с которой процесс
// работает, — и оператор узнал бы об этом никогда.
//
// Потолок приходит АРГУМЕНТОМ, а не читается здесь: величина посадки сводится в
// композиционном корне, и корень обязан назвать её вслух — иначе «у iam есть
// потолок» проверяется чтением чужого файла, а не строкой самого корня.
func (w reconcileWindows) validate(ceiling time.Duration) error {
	for _, k := range []struct {
		knob  string
		value time.Duration
		what  string
	}{
		{reconcileSweepKnob, w.Sweep, "periodic sweep"},
		{reconcileDrainKnob, w.Drain, "queue poll-fallback"},
	} {
		if k.value > ceiling {
			return fmt.Errorf(
				"rsab reconciler config invalid: %s = %v exceeds the declared ceiling %v "+
					"(%s — this is the SECOND step of the grant-revocation chain, i.e. how long "+
					"a withdrawn binding keeps being honoured once the notification is lost; "+
					"the ceiling is declared once in pkg/authz.RevocationPolicy, whose "+
					"ChainCeiling is %v) (refuse to start)",
				k.knob, k.value, ceiling, k.what, authz.RevocationPolicy.ChainCeiling(),
			)
		}
	}
	return nil
}
