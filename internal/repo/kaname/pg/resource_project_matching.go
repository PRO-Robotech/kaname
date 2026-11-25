// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// Вложенный ребёнок выбирается по сохранённому графу, как в DescendantsOf.
// Ветка anchor ограничивает область по контейнеру. Чужая область самого
// ребёнка остаётся в переписи для последующего REJECTED. Пообъектная цель
// выдачи сужает результат в компиляторе, а не в этом запросе.
const projectNestedBindingConditionSQL = `(rrs.container_type='iam.account' AND EXISTS (
    SELECT 1
    FROM kaname.resource_mirror m
    JOIN kaname.catalog_resource child ON child.dotted=m.object_type AND child.live
    JOIN kaname.resource_parent_edge edge ON edge.object_type=child.object_type AND edge.object_id=m.object_id
    JOIN kaname.catalog_resource owner ON owner.object_type=edge.parent_type AND owner.dotted='iam.account' AND owner.live
    JOIN ONLY kaname.accounts a ON a.id=edge.parent_id
    WHERE m.object_type=$1 AND m.object_id=$2
     AND (b.resource_type NOT IN ('account','project') OR (b.resource_type='account' AND b.resource_id=a.id))
     AND (rrs.container_arm='anchor'
      OR (rrs.container_arm='names' AND a.id=ANY(rrs.container_resource_names))
      OR (rrs.container_arm='labels' AND a.labels @> rrs.container_match_labels)
      OR (rrs.container_arm='access_labels' AND a.access_labels @> rrs.container_match_access_labels))
     AND (rrs.arm='anchor'
      OR (rrs.arm='names' AND $2=ANY(rrs.resource_names))
      OR (rrs.arm='labels' AND m.labels @> rrs.match_labels)
      OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels))
   ))`
