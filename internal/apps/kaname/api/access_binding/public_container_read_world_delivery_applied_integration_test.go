// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// public_container_read_world_delivery_applied_integration_test.go — проба
// помощника доставки мира П6 (`pcrWorld.applyDelivered`, kaname#1023).
//
// # Предмет
//
// «Дано» сцены, заведённое доставкой манифеста, держится, лишь если доставка
// ПРИМЕНЕНА. Применитель каталога пропускает модуль младшей редакции и
// отвергает модуль с конфликтом содержимого ИСХОДОМ, а не отказом
// (`modulecatalog.Census.NotApplied`, Д3): ошибки нет, каталог прежний. Помощник,
// судивший одну ошибку, отдавал сцене прежний мир молча, и сцена судила не то,
// что назвала. Теперь непустой `NotApplied` — провал сцены с именем модуля и
// видом пропуска.
//
// # Обе стороны
//
// Одна сцена, одна база, редакции одного модуля `registry` по порядку:
//   - близнец: редакция 2 поверх неприменённой — применяется, сцена зелёная;
//   - младшая редакция 1 поверх 2 — сцена падает, текст называет модуль и
//     «младшая редакция»;
//   - конфликт: редакция 2 с иным содержимым — сцена падает, текст называет
//     модуль и «конфликт содержимого»;
//   - близнец после отказов: редакция 3 — применяется, сцена зелёная.
//
// Пропущенная доставка каталог не трогает, поэтому отказы посреди сцены мир не
// портят, и второй близнец судит ту же базу.
//
// Провал сцены ловит приёмник (`deliveryFail`), а помощник исполняется в своей
// горутине: `FailNow` приёмника завершает её, как `FailNow` пробы завершает
// пробу, и шаги помощника после провала не исполняются.

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

func TestPCRWorldDeliveryThatIsNotAppliedFailsTheScene(t *testing.T) {
	p := newPCRWorld(t)

	prior, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	require.NoError(t, err, "фикстура: прежняя редакция")
	next, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(t, err, "фикстура: новая редакция")

	p.applyDelivered("близнец: редакция 2 поверх неприменённой", deliveredEdition(t, prior, 2))

	got := p.deliverExpectingFailure("младшая редакция 1 поверх 2", deliveredEdition(t, prior, 1))
	require.NotEmpty(t, got, "младшая редакция 1 поверх 2: сцена не упала — модуль пропущен молча")
	require.Contains(t, got, `"registry"`, "провал младшей редакции не называет модуль")
	require.Contains(t, got, "младшая редакция", "провал младшей редакции не называет вид пропуска")

	got = p.deliverExpectingFailure("конфликт: редакция 2 с иным содержимым", deliveredEdition(t, next, 2))
	require.NotEmpty(t, got, "конфликт содержимого: сцена не упала — модуль отвергнут молча")
	require.Contains(t, got, `"registry"`, "провал конфликта не называет модуль")
	require.Contains(t, got, "конфликт содержимого", "провал конфликта не называет вид пропуска")

	p.applyDelivered("близнец после отказов: редакция 3", deliveredEdition(t, next, 3))
}

// deliveredEdition — документ с объявленной редакцией n, загруженный читателем
// доставки.
func deliveredEdition(t *testing.T, doc []byte, n int64) *manifest.Manifest {
	t.Helper()
	d, err := publicreadfixture.WithRevision(doc, n)
	require.NoErrorf(t, err, "фикстура: редакция %d", n)
	m, err := manifest.Load(d)
	require.NoErrorf(t, err, "фикстура: редакция %d обязана загружаться", n)
	return m
}

// deliverExpectingFailure исполняет помощник доставки с приёмником провала и
// возвращает текст провала; пустая строка — сцена не упала.
func (p *pcrWorld) deliverExpectingFailure(what string, m *manifest.Manifest) string {
	p.t.Helper()
	rec := &deliveryFailRecorder{}
	p.deliveryFail = rec
	defer func() { p.deliveryFail = nil }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.applyDelivered(what, m)
	}()
	<-done
	if !rec.failed {
		return ""
	}
	return rec.msg
}

// deliveryFailRecorder — приёмник провала: копит текст и завершает горутину
// помощника на `FailNow`.
type deliveryFailRecorder struct {
	failed bool
	msg    string
}

func (r *deliveryFailRecorder) Errorf(format string, args ...any) {
	r.msg += fmt.Sprintf(format, args...)
}

func (r *deliveryFailRecorder) FailNow() {
	r.failed = true
	runtime.Goexit()
}
