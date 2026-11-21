// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package outboxtypes

import "time"

// ResourceMirrorRow — нейтральная нагрузка регистрации. Порты репозитория
// и service используют один тип без зависимости repo от сценариев service.
type ResourceMirrorRow struct {
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	ParentAccountID string
	// ParentChain — цепь предков от ближайшего к дальнему, каждый элемент
	// `"<type>:<id>"`. Двух колонок выше хватает не всякому объекту: модель
	// требует цепи произвольной формы, а объект без предка молча выпадает из
	// области выдачи и из каскада.
	ParentChain []string
	Labels      map[string]string
	// SourceVersion — монотонный маркер объекта от владельца.
	// UPSERT зеркала применяет регистрацию лишь при строго большем значении,
	// чем сохранённая версия (побеждает последнее состояние источника). Ноль → '-infinity' (старый формат).
	SourceVersion time.Time
}
