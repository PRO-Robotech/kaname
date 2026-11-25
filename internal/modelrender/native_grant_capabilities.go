// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender

import (
	"bytes"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/grantcapability"
)

// NativeGrantCapabilityBlocks — закрытый производитель внутренних координат.
// Это не manifest resources: у них нет parents, tier, cascade либо v_*.
// Каждый вызов возвращает собственные байты, не изменяемый общий шаблон.
func NativeGrantCapabilityBlocks() []Block {
	slots := [][2]string{
		{grantcapability.ScopeObjectType, grantcapability.CreateRelation},
		{grantcapability.RoleObjectType, grantcapability.BindRelation},
		{grantcapability.AccessLabelObjectType, grantcapability.ApplyAccessLabelRelation},
	}
	blocks := make([]Block, 0, len(slots))
	for _, slot := range slots {
		body := fmt.Sprintf("type %s\n  relations\n    define %s: [user, service_account, group#member]\n", slot[0], slot[1])
		blocks = append(blocks, Block{Type: slot[0], Body: []byte(body)})
	}
	return blocks
}

// ValidateNativeGrantCapabilityBlocks судит полный канон продукта. Все три
// блока обязательны ровно по одному; ни расширение, ни усечение не являются
// совместимой редакцией. Остальные блоки судятся обычным manifest verifier.
func ValidateNativeGrantCapabilityBlocks(dsl []byte) error {
	expected := make(map[string][]byte)
	for _, block := range NativeGrantCapabilityBlocks() {
		expected[block.Type] = block.Body
	}
	seen := make(map[string]bool)
	for _, block := range SplitCanon(dsl) {
		body, native := expected[block.Type]
		if !native {
			continue
		}
		if seen[block.Type] {
			return fmt.Errorf("native capability %s declared more than once", block.Type)
		}
		seen[block.Type] = true
		if !bytes.Equal(block.Body, body) {
			return fmt.Errorf("native capability %s differs from its closed producer", block.Type)
		}
	}
	for _, block := range NativeGrantCapabilityBlocks() {
		if !seen[block.Type] {
			return fmt.Errorf("native capability %s is absent", block.Type)
		}
	}
	return nil
}
