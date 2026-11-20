#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Образы окончательного манифеста; исходные байты идут только Helm/kubectl.

Нет сохранения/печати YAML, ссылок образов, окружения и вывода инструментов.
Неудачный pull на хосте оставляет настоящую попытку загрузки узлу Kubernetes.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


class Unavailable(Exception):
    def __init__(self, stage, reason, code=None):
        self.stage = stage
        self.reason = reason
        self.code = code


def unavailable(stage, error):
    # Только фиксированный класс причины и число; без текста, argv и stderr.
    if isinstance(error, subprocess.TimeoutExpired):
        return Unavailable(stage, "timeout")
    if isinstance(error, subprocess.CalledProcessError):
        return Unavailable(stage, "nonzero", error.returncode)
    return Unavailable(stage, "oserror", getattr(error, "errno", None))


def run_preload(stage, argv, quiet, **overrides):
    try:
        return subprocess.run(argv, check=True, **(quiet | overrides))
    except (OSError, subprocess.SubprocessError) as error:
        raise unavailable(stage, error) from error


def load_kind_image(cluster, image, quiet):
    try:
        run_preload("kind-load", ["kind", "load", "docker-image", image, "--name", cluster],
                    quiet, timeout=180, stderr=subprocess.PIPE)
        return
    except Unavailable as error:
        failure = error.__cause__
        if not isinstance(failure, subprocess.CalledProcessError) or not re.search(
            rb"ctr: content digest sha256:[0-9a-f]{64}: not found", failure.stderr or b""
        ):
            raise

    # Обычный импорт kind обходит весь индекс образа. Если Docker хранит только
    # скачанную платформу, передаём один вариант исходного образа с тем же тегом.
    platform_template = "{{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}"
    platform = run_preload("docker-platform", ["docker", "image", "inspect", "--format", platform_template, image],
                           quiet, timeout=30, stdout=subprocess.PIPE).stdout.strip()
    if not re.fullmatch(rb"[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?", platform):
        raise Unavailable("docker-platform", "invalid")
    try:
        with TemporaryDirectory(prefix="kaname-preload-") as directory:
            archive = str(Path(directory) / "image.tar")
            run_preload("docker-save-platform", ["docker", "image", "save", "--platform", platform.decode(),
                                                 "--output", archive, image], quiet, timeout=180)
            run_preload("kind-load-platform", ["kind", "load", "image-archive", archive, "--name", cluster],
                        quiet, timeout=180)
    except OSError as error:
        raise unavailable("platform-archive", error) from error
    print("стенд: preload fallback=single-platform outcome=success", file=sys.stderr)


def images(document):
    if document is None:
        return
    if not isinstance(document, dict):
        raise ValueError("manifest")
    kind = document.get("kind")
    if kind == "List":
        for item in document["items"]:
            yield from images(item)
        return
    # Только настоящие пути PodSpec, не произвольные spec/data/env объектов.
    paths = {
        "Pod": ("spec",),
        "PodTemplate": ("template", "spec"),
        "Deployment": ("spec", "template", "spec"),
        "StatefulSet": ("spec", "template", "spec"),
        "DaemonSet": ("spec", "template", "spec"),
        "ReplicaSet": ("spec", "template", "spec"),
        "ReplicationController": ("spec", "template", "spec"),
        "Job": ("spec", "template", "spec"),
        "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
    }
    if kind not in paths:
        return
    spec = document
    for field in paths[kind]:
        spec = spec[field]
    for field in ("containers", "initContainers", "ephemeralContainers"):
        for container in spec.get(field, []):
            image = container["image"]
            if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]*", image):
                raise ValueError("image")
            yield image


def mark(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(descriptor)


def main():
    marker = None
    try:
        cluster, marker_path = sys.argv[1:]
        marker = Path(marker_path)
        marker.unlink(missing_ok=True)
        try:
            import yaml
        except ImportError as error:
            raise Unavailable("dependency-yaml", "missing") from error
        manifest = sys.stdin.buffer.read()
        try:
            required = sorted({image for document in yaml.safe_load_all(manifest)
                               for image in images(document)})
        except (yaml.YAMLError, ValueError, TypeError, KeyError, AttributeError) as error:
            raise ValueError("manifest") from error
        if not required:
            raise ValueError("no workload images")
        quiet = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                 "stderr": subprocess.DEVNULL}
        # Отсутствие инструментов/демона — немедленное несозданное условие.
        for tool in ("docker", "kind"):
            if not shutil.which(tool):
                raise Unavailable("dependency-" + tool, "missing")
        try:
            subprocess.run(["docker", "info"], check=True, timeout=30, **quiet)
        except (OSError, subprocess.SubprocessError) as error:
            raise unavailable("docker-info", error) from error
        pull_pending = 0
        preloaded = 0
        for image in required:
            try:
                local = subprocess.run(["docker", "image", "inspect", image], timeout=30, **quiet)
            except (OSError, subprocess.SubprocessError) as error:
                raise unavailable("docker-inspect", error) from error
            if local.returncode:
                try:
                    subprocess.run(["docker", "pull", image], check=True, timeout=180, **quiet)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                    # Хост не загрузил образ: решение о готовности остаётся узлу.
                    pull_pending += 1
                    detail = unavailable("docker-pull", error)
                    code = "" if detail.code is None else " code=%d" % detail.code
                    print("стенд: preload stage=docker-pull reason=%s%s outcome=pending"
                          % (detail.reason, code), file=sys.stderr)
                    continue
                except OSError as error:
                    raise unavailable("docker-pull", error) from error
            load_kind_image(cluster, image, quiet)
            preloaded += 1
        if pull_pending:
            print("стенд: загрузка на хосте не завершена для %d образов; ожидается попытка узла"
                  % pull_pending, file=sys.stderr)
        # Успешный kind load подтверждает завершённую предзагрузку, не Ready пода.
        print("стенд: preload images=%d preloaded=%d pull_pending=%d"
              % (len(required), preloaded, pull_pending), file=sys.stderr)
        sys.stdout.buffer.write(manifest)
        return 0
    except Unavailable as error:
        if marker is not None:
            try:
                mark(marker)
            except OSError:
                pass
        code = "" if error.code is None else " code=%d" % error.code
        print("стенд: preload stage=%s reason=%s%s outcome=75"
              % (error.stage, error.reason, code), file=sys.stderr)
        return 75
    except Exception:
        # Текст исключения разбора может содержать YAML: только фиксированная строка.
        print("стенд: манифест или обработка образов некорректны (1)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
