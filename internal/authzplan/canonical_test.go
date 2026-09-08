// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// canonical_test.go — резолв канона ОГРАНИЧЕН деревом, о котором он говорит
// (задача PRO-Robotech/kacho#2159).
//
// # Предмет
//
// Резолв искал канон подъёмом вверх до корня файловой системы. Существенно не
// то, что он может не найти файл, а то, что он НАХОДИТ ЧУЖОЙ и не сомневается:
// перепись печатается по тому дереву, которое НАЗВАЛ вызывающий, а байты — по
// тому файлу, который НАШЁЛСЯ, и отличить такой зелёный от настоящего нечем.
//
// Предмет линии — служба, устанавливаемая в чужом облаке. Значит подъём «до
// корня файловой системы» из модуля есть подъём в дерево оператора.
//
// # Отказы РАЗЛИЧАЮТСЯ, и это несущее
//
// «Канон лежит ВЫШЕ дерева» и «канона нет нигде» — разные состояния, и слить их
// в один текст значило бы вернуть предмет другой стороной: оператор, у которого
// канон лежит над деревом, прочитал бы «его нет» и завёл бы второй, вместо того
// чтобы понять, что читалось чужое.

// canonAt кладёт канон по каноническому относительному пути под root.
func canonAt(t *testing.T, root, body string) string {
	t.Helper()
	p := filepath.Join(root, fgaModelRelPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// treeUnder заводит каталог дерева под root и возвращает его путь.
func treeUnder(t *testing.T, root string) string {
	t.Helper()
	tree := filepath.Join(root, "tree")
	require.NoError(t, os.MkdirAll(tree, 0o750))
	return tree
}

// TestCanonAboveTheTreeIsRefusedNotRead — ОТРИЦАНИЕ. Канон лежит ВЫШЕ названного
// дерева; резолв обязан отказать, НАЗВАВ предпосылку, а не прочитать чужой файл.
func TestCanonAboveTheTreeIsRefusedNotRead(t *testing.T) {
	outer := t.TempDir()
	foreign := canonAt(t, outer, "type foreign\n  relations\n")
	tree := treeUnder(t, outer)

	path, dsl, err := ResolveCanonicalModelFrom(tree)

	require.Error(t, err, "канон лежит ВЫШЕ дерева %s (%s) — резолв обязан отказать, а не прочитать его", tree, foreign)
	require.Nil(t, dsl, "байты чужого канона не имеют права доехать до вызывающего")
	require.Empty(t, path)

	msg := err.Error()
	require.Contains(t, msg, tree, "отказ обязан назвать дерево, которое осмотрено")
	require.Contains(t, msg, fgaModelRelPath, "отказ обязан назвать ожидаемый относительный путь")
	require.Contains(t, msg, foreign, "отказ обязан назвать НАЙДЕННЫЙ выше дерева канон — иначе оператор не поймёт, что читалось чужое")
}

// TestCanonInsideTheTreeResolves — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ. Тот же мир, отличается
// РОВНО ОДНИМ фактом: канон лежит ВНУТРИ дерева. Резолв обязан молчать.
func TestCanonInsideTheTreeResolves(t *testing.T) {
	outer := t.TempDir()
	canonAt(t, outer, "type foreign\n  relations\n")
	tree := treeUnder(t, outer)
	own := canonAt(t, tree, "type own\n  relations\n")

	path, dsl, err := ResolveCanonicalModelFrom(tree)

	require.NoError(t, err)
	require.Equal(t, own, path, "прочитан обязан быть канон ДЕРЕВА, а не тот, что выше него")
	require.Equal(t, "type own\n  relations\n", string(dsl))
}

// TestNoCanonAnywhereIsRefusedWithItsOwnText — КОНТРОЛЬ. Канона нет ни в дереве,
// ни выше него: отказ обязан быть, и его текст обязан ОТЛИЧАТЬСЯ от отказа
// «канон лежит выше».
func TestNoCanonAnywhereIsRefusedWithItsOwnText(t *testing.T) {
	tree := t.TempDir()

	path, dsl, err := ResolveCanonicalModelFrom(tree)

	require.Error(t, err)
	require.Nil(t, dsl)
	require.Empty(t, path)

	msg := err.Error()
	require.Contains(t, msg, tree)
	require.Contains(t, msg, fgaModelRelPath)
	require.NotContains(t, strings.ToLower(msg), "выше",
		"«канона нет нигде» не вправе говорить о каноне выше дерева — его там нет")
}

// TestTheTwoRefusalsAreDistinguishable — два отказа не сливаются. Без этого
// «нашёл чужой» и «не нашёл ничего» неотличимы, и предмет возвращается другой
// стороной.
func TestTheTwoRefusalsAreDistinguishable(t *testing.T) {
	outer := t.TempDir()
	canonAt(t, outer, "type foreign\n  relations\n")
	above := treeUnder(t, outer)
	_, _, errAbove := ResolveCanonicalModelFrom(above)

	_, _, errNone := ResolveCanonicalModelFrom(t.TempDir())

	require.Error(t, errAbove)
	require.Error(t, errNone)
	require.NotEqual(t, errAbove.Error(), errNone.Error(),
		"тексты обязаны различаться: иначе оператор, у которого канон над деревом, прочитает «его нет»")
}
