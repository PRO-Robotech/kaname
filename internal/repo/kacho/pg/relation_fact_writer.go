// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// relation_fact_writer.go — запись прямых фактов отношения в собственную БД.
//
// # Предмет
//
// Пока движок отношений жив, каждый прямой факт живёт ДВАЖДЫ: намерением в
// очереди доставки наружу и строкой здесь. Записывать их обязательно в ОДНОЙ
// транзакции — откат, оставивший одно без другого, разводит свою БД с чужой
// молча, и расхождение обнаружится не отказом, а неверным вердиктом.
//
// # Почему форма имени субъекта не разбирается
//
// Субъект хранится целиком (`"user:usr-1"`, `"group:grp-1#member"`, `"user:*"`).
// Разложить последние две формы на пару «тип и идентификатор» можно только
// выдумав правило разложения, которого в самом имени нет: у одной есть
// отношение-хвост, у другой вместо идентификатора подстановочный знак. Правило,
// выдуманное здесь, стало бы вторым местом, знающим форму имени, — и разошлось
// бы с тем, кто её производит.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// RelationFactWriter — адаптер порта service.RelationFactWriter.
type RelationFactWriter struct{}

// NewRelationFactWriter собирает адаптер.
func NewRelationFactWriter() *RelationFactWriter { return &RelationFactWriter{} }

// WriteFactsTx записывает факты идемпотентно: повторная доставка того же
// намерения не должна быть отказом, а более СТАРАЯ не должна воскрешать снятое.
func (w *RelationFactWriter) WriteFactsTx(
	ctx context.Context, tx service.Tx, tuples []service.RelationTuple, version time.Time,
) error {
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		objType, objID, ok := splitFactObject(t.Object)
		if !ok {
			// Непонятая форма — отказ, а не пропуск: пропущенный факт означает
			// доступ, которого своя БД не знает, при том что чужая его получила.
			return fmt.Errorf("relation_fact: непонятая форма объекта %q "+
				"(ожидается \"<type>:<id>\")", t.Object)
		}
		if _, err := txAsPgx(tx).Exec(ctx,
			`INSERT INTO kacho_iam.relation_fact
			   (object_type, object_id, relation, subject, source_version, created_at)
			 VALUES ($1, $2, $3, $4, $5, now())
			 ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
			    SET source_version = EXCLUDED.source_version
			  WHERE relation_fact.source_version < EXCLUDED.source_version`,
			objType, objID, t.Relation, t.User, factVersion(version),
		); err != nil {
			return fmt.Errorf("relation_fact: insert: %w", err)
		}
	}
	return nil
}

// DeleteFactsTx снимает факты под тем же условием монотонности, что и зеркало:
// устаревшее надгробие не сносит более свежую запись.
func (w *RelationFactWriter) DeleteFactsTx(
	ctx context.Context, tx service.Tx, tuples []service.RelationTuple, tombstone time.Time,
) error {
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		objType, objID, ok := splitFactObject(t.Object)
		if !ok {
			return fmt.Errorf("relation_fact: непонятая форма объекта %q "+
				"(ожидается \"<type>:<id>\")", t.Object)
		}
		if _, err := txAsPgx(tx).Exec(ctx,
			`DELETE FROM kacho_iam.relation_fact
			  WHERE object_type = $1 AND object_id = $2
			    AND relation = $3 AND subject = $4
			    AND source_version <= $5`,
			objType, objID, t.Relation, t.User, factVersion(tombstone),
		); err != nil {
			return fmt.Errorf("relation_fact: delete: %w", err)
		}
	}
	return nil
}

// factVersion нормализует нулевое время к '-infinity' — тем же способом, что
// зеркало: вызывающий без версии остаётся законным (back-compat), и его запись
// применяется безусловно.
func factVersion(t time.Time) any {
	if t.IsZero() {
		return "-infinity"
	}
	return t
}

// splitFactObject разбирает `"<type>:<id>"` по ПЕРВОМУ двоеточию.
func splitFactObject(ref string) (typ, id string, ok bool) {
	i := strings.IndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// Compile-time check: адаптер удовлетворяет порту use-case.
var _ service.RelationFactWriter = (*RelationFactWriter)(nil)
