// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package execstub

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const stubBody = "#!/usr/bin/env bash\necho двойник-ответил\n"

// TestOpenWriteDescriptorMakesTheStubBusy — ПРЕДПОСЫЛКА класса на этом ядре:
// пока где-либо открыт дескриптор записи файла, его запуск отвечает ETXTBSY,
// а после закрытия — исполняется. Без этой пары остальные пробы пакета судили
// бы механизм, которого здесь нет.
func TestOpenWriteDescriptorMakesTheStubBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gh")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o700) // #nosec G302 G304 -- двойник в t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(stubBody); err != nil {
		t.Fatal(err)
	}

	err = exec.Command(path).Run() // #nosec G204 -- путь из t.TempDir()
	if !errors.Is(err, syscall.ETXTBSY) {
		_ = f.Close()
		t.Fatalf("запуск при открытом дескрипторе записи обязан отвечать ETXTBSY, получено: %v", err)
	}

	// Законный близнец: тот же файл, дескриптор закрыт — запуск проходит.
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(path).CombinedOutput(); err != nil { // #nosec G204 -- путь из t.TempDir()
		t.Fatalf("закрытый двойник обязан исполняться: %v\n%s", err, out)
	}
}

// TestNoForkStartsWhileTheStubIsWritable — НЕСУЩЕЕ свойство: пока дескриптор
// записи двойника открыт, ни одна горутина процесса не может начать `fork`.
// Порождённый ребёнок держит копию каждого дескриптора родителя до своего
// `exec` (O_CLOEXEC закрывает их лишь там), и ровно этот промежуток даёт
// соседней пробе ETXTBSY на только что записанном и закрытом двойнике.
// Переименование файла тут не спасает: ETXTBSY — свойство inode, а не имени.
// `fork` в Go берёт `syscall.ForkLock` на запись, поэтому свойство измеряется
// так: в окне записи блокировка на запись недоступна.
func TestNoForkStartsWhileTheStubIsWritable(t *testing.T) {
	// Законный близнец: вне окна записи блокировка доступна — иначе проверка
	// ниже краснела бы на чём угодно, а не на окне.
	if !syscall.ForkLock.TryLock() {
		t.Fatal("ForkLock занят вне окна записи — проба не способна различить окно")
	}
	syscall.ForkLock.Unlock()

	var calls int
	whileWritable = func() {
		calls++
		if syscall.ForkLock.TryLock() {
			syscall.ForkLock.Unlock()
			t.Error("в окне записи двойника fork мог начаться: ForkLock свободен на запись")
		}
	}
	t.Cleanup(func() { whileWritable = nil })

	Write(t, filepath.Join(t.TempDir(), "bin", "gh"), stubBody)
	if calls != 1 {
		t.Fatalf("окно записи пройдено %d раз вместо одного — проба не прочла предмет", calls)
	}
}

// TestStubWrittenAmongForkingNeighboursIsNeverBusy — то же свойство на
// НАБЛЮДАЕМОМ: соседи непрерывно порождают процессы, проба пишет и тут же
// запускает двойников. Исход — число ETXTBSY; другой отказ запуска — отказ
// пробы, а не её молчание.
func TestStubWrittenAmongForkingNeighboursIsNeverBusy(t *testing.T) {
	const neighbours, stubs = 8, 400
	dir := t.TempDir()

	var stop atomic.Bool
	var forks atomic.Int64
	var wg sync.WaitGroup
	for range neighbours {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_ = exec.Command("true").Run()
				forks.Add(1)
			}
		}()
	}
	t.Cleanup(func() { stop.Store(true); wg.Wait() })

	deadline := time.Now().Add(20 * time.Second)
	busy, ran := 0, 0
	for i := range stubs {
		if time.Now().After(deadline) {
			break
		}
		path := filepath.Join(dir, "bin"+strconv.Itoa(i), "gh")
		Write(t, path, stubBody)
		out, err := exec.Command(path).CombinedOutput() // #nosec G204 -- путь из t.TempDir()
		switch {
		case errors.Is(err, syscall.ETXTBSY):
			busy++
		case err != nil:
			t.Fatalf("двойник %s не исполнился: %v\n%s", path, err, out)
		case !strings.Contains(string(out), "двойник-ответил"):
			t.Fatalf("двойник %s ответил не своим телом: %q", path, out)
		}
		ran++
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("запусков двойника %d · порождений соседями %d · ETXTBSY %d", ran, forks.Load(), busy)
	if ran == 0 || forks.Load() == 0 {
		t.Fatalf("НЕ ИСПОЛНЯЛАСЬ: запусков %d, порождений %d — гонке не с чем было случиться", ran, forks.Load())
	}
	if busy != 0 {
		t.Fatalf("ETXTBSY %d из %d запусков: двойник исполнялся, пока сосед держал его дескриптор записи", busy, ran)
	}
}
