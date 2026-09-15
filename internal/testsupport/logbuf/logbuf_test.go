// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package logbuf_test

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/logbuf"
)

// TestBuffer_ReadWhileAForeignGoroutineWrites — предмет пакета: писатель и
// читатель в РАЗНЫХ горутинах, как у пробы асинхронной операции.
//
// Утверждение о гонке выносит детектор (`-race`, задание конвейера «пробы
// -race -short»): вернуть на место `Buffer` голый `bytes.Buffer` — и эта же
// проба краснеет с `WARNING: DATA RACE` на чтении. Без детектора проба судит
// только полноту: ни одна запись не потеряна и не разорвана.
func TestBuffer_ReadWhileAForeignGoroutineWrites(t *testing.T) {
	var buf logbuf.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	const writers, perWriter = 4, 200
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				logger.Info("probe", "writer", w, "seq", i)
			}
		}()
	}

	// Читатель крутится, пока пишут: ровно форма `require.Eventually` по буферу.
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				_ = strings.Contains(buf.String(), "seq=")
			}
		}
	}()

	wg.Wait()
	close(stop)
	<-readerDone

	out := buf.String()
	if got := strings.Count(out, "msg=probe"); got != writers*perWriter {
		t.Fatalf("записей %d, ожидалось %d: буфер терял или рвал записи", got, writers*perWriter)
	}
	for w := 0; w < writers; w++ {
		want := fmt.Sprintf("writer=%d seq=%d", w, perWriter-1)
		if !strings.Contains(out, want) {
			t.Fatalf("последняя запись писателя %d (%q) не найдена", w, want)
		}
	}
}

// TestBuffer_StringIsACopy — отданное читателю не меняется последующей записью:
// иначе чтение, сделанное под замком, продолжалось бы без него.
func TestBuffer_StringIsACopy(t *testing.T) {
	var buf logbuf.Buffer
	_, _ = buf.Write([]byte("first"))
	snap := buf.String()
	_, _ = buf.Write([]byte(" second"))

	if snap != "first" {
		t.Fatalf("снимок изменился после записи: %q", snap)
	}
	if got := buf.String(); got != "first second" {
		t.Fatalf("накопленное %q, ожидалось %q", got, "first second")
	}
}
