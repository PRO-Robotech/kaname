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


class Unavailable(Exception):
    pass


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
            raise Unavailable() from error
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
        if not all(shutil.which(tool) for tool in ("docker", "kind")):
            raise Unavailable()
        try:
            subprocess.run(["docker", "info"], check=True, timeout=30, **quiet)
        except (OSError, subprocess.SubprocessError) as error:
            raise Unavailable() from error
        pull_pending = 0
        for image in required:
            try:
                local = subprocess.run(["docker", "image", "inspect", image], timeout=30, **quiet)
            except (OSError, subprocess.SubprocessError) as error:
                raise Unavailable() from error
            if local.returncode:
                try:
                    subprocess.run(["docker", "pull", image], check=True, timeout=180, **quiet)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    # Хост не загрузил образ: решение о готовности остаётся узлу.
                    pull_pending += 1
                    continue
                except OSError as error:
                    raise Unavailable() from error
            try:
                subprocess.run(["kind", "load", "docker-image", image, "--name", cluster],
                               check=True, timeout=180, **quiet)
            except (OSError, subprocess.SubprocessError) as error:
                raise Unavailable() from error
        if pull_pending:
            print("стенд: загрузка на хосте не завершена для %d образов; ожидается попытка узла"
                  % pull_pending, file=sys.stderr)
        sys.stdout.buffer.write(manifest)
        return 0
    except Unavailable:
        if marker is not None:
            try:
                mark(marker)
            except OSError:
                pass
        print("стенд: инструмент или загрузка в kind недоступны (75)", file=sys.stderr)
        return 75
    except Exception:
        # Текст исключения разбора может содержать YAML: только фиксированная строка.
        print("стенд: манифест или обработка образов некорректны (1)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
