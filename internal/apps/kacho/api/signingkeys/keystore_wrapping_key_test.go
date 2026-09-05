// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keystore_wrapping_key_test.go — ключ обёртки, сменившийся под уже записанной
// ключницей (задача #1062).
//
// ПРЕДМЕТ. Приватная половина подписного ключа лежит в базе ОБЁРНУТОЙ, и
// разворачивает её ровно один ключ. Если этот ключ сменился, записанное
// перестаёт разворачиваться НАВСЕГДА. Пока ключница молча заводила новый ключ
// вместо нечитаемых, «пересоздали стенд» и «потеряли все подписи» выглядели
// одинаково: служба поднималась, набор отвечал, и узнавалось это у клиента.
//
// Пробы утверждают ИСХОД СТАРТА, а не «функция позвана»: отказ обязан прийти
// при старте и назвать ключ, а число строк в ключнице обязано остаться прежним
// — иначе «отказ» был бы отказом ПОСЛЕ порождения, то есть потерей плюс шумом.
package signingkeys_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/signingkeys"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/keywrap"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// keystoreWrappedWith строит ключницу НАД ТЕМ ЖЕ хранилищем, но с названным
// ключом обёртки. Так выражается пересоздание стенда: база остаётся, ключ
// обёртки приезжает новый.
func keystoreWrappedWith(t *testing.T, store *memStore, keyByte byte, logBuf *bytes.Buffer) *signingkeys.Keystore {
	t.Helper()
	wrapper, err := keywrap.New(bytes.Repeat([]byte{keyByte}, keywrap.KeySize))
	require.NoError(t, err)
	var logger *slog.Logger
	if logBuf != nil {
		logger = slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgRS256,
		KeyLifetime:  90 * 24 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        fixedClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)),
		Logger:       logger,
	}, store, store, wrapper)
	require.NoError(t, err)
	return ks
}

// TestEnsureSigningKeyRefusesWhenTheWrappingKeyChanged — смена ключа обёртки
// над непустой ключницей даёт НАЗВАННЫЙ отказ старта, а не новый ключ.
func TestEnsureSigningKeyRefusesWhenTheWrappingKeyChanged(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()

	// Given — стенд, поднятый однажды: ключ порождён и подписывает.
	first := keystoreWrappedWith(t, store, 7, nil)
	require.NoError(t, first.EnsureSigningKey(ctx))
	require.Len(t, store.rows, 1, "предпосылка: в ключнице ровно один ключ")
	var kid domain.KeyID
	for k := range store.rows {
		kid = k
	}

	// When — стенд пересоздан, и посев привёз ДРУГОЙ ключ обёртки.
	var logBuf bytes.Buffer
	second := keystoreWrappedWith(t, store, 9, &logBuf)
	err := second.EnsureSigningKey(ctx)

	// Then — отказ, и он опознаётся машинно, а не по прозе.
	require.Error(t, err, "смена ключа обёртки над непустой ключницей обязана быть отказом старта")
	require.ErrorIs(t, err, signingkeys.ErrWrappingKeyMismatch)

	// And — отказ НАЗЫВАЕТ ключ, который не разворачивается: без имени
	// оператору нечего искать, а текст отказа при старте есть рантайм-диагностика.
	require.Contains(t, err.Error(), string(kid), "отказ обязан назвать ключ")

	// And — НИ ОДНОГО нового ключа не заведено. Отказ ПОСЛЕ порождения был бы
	// той же потерей, только с сообщением.
	require.Len(t, store.rows, 1, "поверх нечитаемого ключа заведён новый")
	require.Equal(t, uint64(0), second.Stats().Generated, "порождение при смене ключа обёртки")

	// And — приватного материала в тексте отказа нет: отказ о ключе обёртки, а
	// не о том, что он оборачивал.
	require.NotContains(t, err.Error(), "PRIVATE KEY")
	require.NotContains(t, logBuf.String(), "PRIVATE KEY")
}

// TestEnsureSigningKeyAcceptsTheSameWrappingKey — положительный контроль к
// пробе выше. Без него отказ был бы зелен на ключнице, отвергающей ЛЮБОЙ
// повторный старт.
func TestEnsureSigningKeyAcceptsTheSameWrappingKey(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()

	first := keystoreWrappedWith(t, store, 7, nil)
	require.NoError(t, first.EnsureSigningKey(ctx))
	require.Len(t, store.rows, 1)
	var kid domain.KeyID
	for k := range store.rows {
		kid = k
	}

	// When — стенд поднят снова С ТЕМ ЖЕ ключом обёртки.
	second := keystoreWrappedWith(t, store, 7, nil)
	require.NoError(t, second.EnsureSigningKey(ctx), "тот же ключ обёртки обязан открывать записанное")

	// Then — ключ ПЕРЕИСПОЛЬЗОВАН, а не заведён заново.
	require.Len(t, store.rows, 1)
	require.Contains(t, store.rows, kid, "прежний ключ обязан остаться подписывающим")
	require.Equal(t, uint64(0), second.Stats().Generated)

	// And — приватная половина по-прежнему разворачивается: старт «прошёл»
	// ничего не значит, если подписать всё равно нечем.
	mat, err := second.ActiveSigningKey(ctx)
	require.NoError(t, err)
	require.Contains(t, string(mat.PrivateKeyPEM), "PRIVATE KEY")
}

// TestEnsureSigningKeyBootstrapsAnEmptyKeystore — пустая ключница заводит
// первый ключ ЛЮБЫМ ключом обёртки: разворачивать там нечего, и отказ здесь
// означал бы, что стенд не поднимается никогда.
func TestEnsureSigningKeyBootstrapsAnEmptyKeystore(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	ks := keystoreWrappedWith(t, store, 3, nil)

	require.NoError(t, ks.EnsureSigningKey(ctx))
	require.Len(t, store.rows, 1)
	require.Equal(t, uint64(1), ks.Stats().Generated)
}

// TestEnsureSigningKeyRotatesWhenTheKeyIsReadableButNoneSigns — ключница
// непуста, ключ обёртки ТОТ, а подписывающего нет (прежний объявлен утёкшим).
// Это законное порождение, и запрет здесь остановил бы восстановление.
func TestEnsureSigningKeyRotatesWhenTheKeyIsReadableButNoneSigns(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	ks := keystoreWrappedWith(t, store, 7, nil)

	require.NoError(t, ks.EnsureSigningKey(ctx))
	var kid domain.KeyID
	for k := range store.rows {
		kid = k
	}
	require.NoError(t, ks.Retire(ctx, kid))

	// When — старт над ключницей, где есть читаемый ключ, но подписывающего нет.
	next := keystoreWrappedWith(t, store, 7, nil)
	require.NoError(t, next.EnsureSigningKey(ctx))

	// Then — порождён новый подписывающий, прежний остался в наборе.
	require.Len(t, store.rows, 2)
	require.Equal(t, uint64(1), next.Stats().Generated)
	active, err := store.Active(ctx)
	require.NoError(t, err)
	require.NotEqual(t, kid, active.KID)
}

// TestEnsureSigningKeyRefusesWhenAKeyOfTheSetIsUnreadable — нечитаемым может
// оказаться не подписывающий, а ЛЮБОЙ ключ набора: опубликованный вступит в
// подпись позже, и отложить отказ значит перенести его на ротацию, когда
// оператора рядом уже нет.
func TestEnsureSigningKeyRefusesWhenAKeyOfTheSetIsUnreadable(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()

	// Given — набор из двух ключей: подписывающий и опубликованный.
	old := keystoreWrappedWith(t, store, 7, nil)
	require.NoError(t, old.EnsureSigningKey(ctx))
	stale, err := old.Generate(ctx)
	require.NoError(t, err)
	require.Len(t, store.rows, 2)

	// When — подписывающий переобёрнут НОВЫМ ключом (так выглядело бы «починили
	// по одному»), а опубликованный остался под прежним.
	rewrapActive(t, store, 9)

	next := keystoreWrappedWith(t, store, 9, nil)
	errStart := next.EnsureSigningKey(ctx)

	// Then — отказ, и он называет именно нечитаемый ключ.
	require.ErrorIs(t, errStart, signingkeys.ErrWrappingKeyMismatch)
	require.Contains(t, errStart.Error(), string(stale.KID))
	require.Len(t, store.rows, 2, "поверх нечитаемого ключа заведён новый")
}

// rewrapActive переобёртывает приватную половину ПОДПИСЫВАЮЩЕГО ключа
// названным ключом обёртки. Ход дублирует то, что сделал бы оператор, чинящий
// ключницу по одному ключу; прод-кода такой операции нет.
func rewrapActive(t *testing.T, store *memStore, keyByte byte) {
	t.Helper()
	from, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)
	to, err := keywrap.New(bytes.Repeat([]byte{keyByte}, keywrap.KeySize))
	require.NoError(t, err)
	rec, err := store.Active(context.Background())
	require.NoError(t, err)
	plain, err := from.Unwrap(rec.PrivateKeyWrapped)
	require.NoError(t, err)
	wrapped, err := to.Wrap(plain)
	require.NoError(t, err)
	rec.PrivateKeyWrapped = wrapped
	store.rows[rec.KID] = rec
}

// TestEnsureSigningKeyRefusalNamesTheSubjectNotTheValue — текст отказа обязан
// называть ПРЕДМЕТ (ключ обёртки), а не значение. Отказ при старте — та самая
// рантайм-диагностика, без которой стенд не поднять, поэтому он обязан быть
// понятен оператору и при этом не нести материала.
func TestEnsureSigningKeyRefusalNamesTheSubjectNotTheValue(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	require.NoError(t, keystoreWrappedWith(t, store, 7, nil).EnsureSigningKey(ctx))

	err := keystoreWrappedWith(t, store, 9, nil).EnsureSigningKey(ctx)
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	require.Contains(t, msg, "wrapping key", "отказ обязан назвать предмет — ключ обёртки")

	// Значения ключа обёртки в тексте нет ни в каком виде.
	require.NotContains(t, msg, strings.Repeat("07", keywrap.KeySize))
	require.NotContains(t, msg, strings.Repeat("09", keywrap.KeySize))

	// Сентинел отделён от прочих отказов ключницы: вызывающий обязан отличать
	// «ключ обёртки не тот» от «хранилище недоступно».
	store.err = errors.New("store is unavailable")
	other := keystoreWrappedWith(t, store, 9, nil).EnsureSigningKey(ctx)
	require.Error(t, other)
	require.NotErrorIs(t, other, signingkeys.ErrWrappingKeyMismatch)
}
