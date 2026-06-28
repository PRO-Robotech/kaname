// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// ids_extended.go — IAM-style id generator.
//
// Формат: `<prefix>_<17-char crockford-base32>` (lowercase, без I/L/O/U).
// Отличается от corelib `ids.NewID` тем, что префикс может быть длиннее
// 3-х символов (DB CHECK constraints в миграциях
// 0011..0014).
//
// Источник энтропии — crypto/rand. 17 символов crockford × 5 бит = 85 бит.
package domain

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
)

const (
	crockfordAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	idBodyLen         = 17
)

// NewKac127ID возвращает идентификатор формата `<prefix>_<17-char crockford>`.
// Panic если prefix пустой (programmer error: префикс приходит из package-level
// константы).
func NewKac127ID(prefix string) string {
	if prefix == "" {
		panic("domain.NewKac127ID: empty prefix")
	}

	var raw [11]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand.Read не должен fail-ить на linux/macOS;
		// если он fail-ит — система сломана, panic корректно.
		panic("domain.NewKac127ID: crypto/rand failed: " + err.Error())
	}

	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := uint64(raw[8])<<16 | uint64(raw[9])<<8 | uint64(raw[10])

	body := make([]byte, idBodyLen)
	for i := 0; i < idBodyLen; i++ {
		bitOff := uint(i * 5) // #nosec G115 -- i is the bounded loop index [0,idBodyLen); i*5 cannot overflow uint.
		var val uint64
		switch {
		case bitOff+5 <= 64:
			val = (hi >> (64 - bitOff - 5)) & 0x1f
		case bitOff >= 64:
			loOff := bitOff - 64
			val = (lo >> (24 - loOff - 5)) & 0x1f
		default:
			used := 64 - bitOff
			rest := 5 - used
			highPart := (hi & ((1 << used) - 1)) << rest
			lowPart := lo >> (24 - rest)
			val = (highPart | lowPart) & 0x1f
		}
		body[i] = crockfordAlphabet[val]
	}

	var sb strings.Builder
	sb.Grow(len(prefix) + 1 + idBodyLen)
	sb.WriteString(prefix)
	sb.WriteByte('_')
	sb.Write(body)
	return sb.String()
}
