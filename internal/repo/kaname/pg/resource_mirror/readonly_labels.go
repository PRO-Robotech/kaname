// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror

import "encoding/json"

const readOnlyLabelsMaxEntries = 256
const readOnlyLabelsMaxRawBytes = 1 << 20
const readOnlyLabelsMaxLabelEntries = 8192

// NewReadOnlyLabelDecoder принадлежит одному расчёту rule members. Результаты
// разделяются по точным JSON bytes: их нельзя изменять или передавать изменяемому
// потребителю. Это не кеш решений/объектов: каждое SQL-чтение остаётся свежим.
func NewReadOnlyLabelDecoder() func([]byte) (map[string]string, error) {
	cache := &readOnlyLabelCache{values: make(map[string]map[string]string)}
	return cache.decode
}

type readOnlyLabelCache struct {
	values       map[string]map[string]string
	rawBytes     int
	labelEntries int
}

func decodeLabels(raw []byte) (map[string]string, error) {
	var labels map[string]string
	if err := json.Unmarshal(raw, &labels); err != nil {
		return nil, err
	}
	return labels, nil
}

func (c *readOnlyLabelCache) decode(raw []byte) (map[string]string, error) {
	if labels, found := c.values[string(raw)]; found {
		return labels, nil
	}
	labels, err := decodeLabels(raw)
	if err != nil {
		return nil, err
	}
	// Переполнение выключает только сохранение нового значения, не его чтение.
	// Отдельные лимиты ограничивают payload, число maps и число их элементов.
	if len(c.values) < readOnlyLabelsMaxEntries &&
		len(raw) <= readOnlyLabelsMaxRawBytes-c.rawBytes &&
		len(labels) <= readOnlyLabelsMaxLabelEntries-c.labelEntries {
		// string(raw) копирует bytes: следующий Scan вправе переиспользовать raw.
		c.values[string(raw)] = labels
		c.rawBytes += len(raw)
		c.labelEntries += len(labels)
	}
	return labels, nil
}
