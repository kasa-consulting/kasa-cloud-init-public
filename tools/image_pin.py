#!/usr/bin/env python3
"""Validate immutable cloud-image pins shared by build and updater tools."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import tempfile
from typing import Callable
from urllib.parse import urlparse

import yaml


class ImagePinError(ValueError):
    """An image pin is malformed or crosses its release trust boundary."""


@dataclass(frozen=True)
class ImagePin:
    os: str
    version: str
    codename: str
    build: str
    name: str
    url: str
    checksum_algorithm: str
    checksum: str


@dataclass(frozen=True)
class ImagePolicy:
    version: str
    codename: str
    build_re: re.Pattern[str]
    name_re: re.Pattern[str]
    host: str
    path: Callable[[ImagePin], str]
    checksum_algorithm: str


POLICIES = {
    ("debian", "13", "trixie"): ImagePolicy(
        version="13",
        codename="trixie",
        build_re=re.compile(r"\d{8}-\d{4}"),
        name_re=re.compile(r"debian-13-genericcloud-amd64-(?P<build>\d{8}-\d{4})\.qcow2"),
        host="cloud.debian.org",
        path=lambda pin: f"/images/cloud/trixie/{pin.build}/{pin.name}",
        checksum_algorithm="sha512",
    ),
    ("ubuntu", "24.04", "noble"): ImagePolicy(
        version="24.04",
        codename="noble",
        build_re=re.compile(r"\d{8}(?:\.\d+)?"),
        name_re=re.compile(r"ubuntu-24\.04-server-cloudimg-amd64\.img"),
        host="cloud-images.ubuntu.com",
        path=lambda pin: f"/releases/noble/release-{pin.build}/{pin.name}",
        checksum_algorithm="sha256",
    ),
    ("ubuntu", "26.04", "resolute"): ImagePolicy(
        version="26.04",
        codename="resolute",
        build_re=re.compile(r"\d{8}(?:\.\d+)?"),
        name_re=re.compile(r"ubuntu-26\.04-server-cloudimg-amd64\.img"),
        host="cloud-images.ubuntu.com",
        path=lambda pin: f"/releases/resolute/release-{pin.build}/{pin.name}",
        checksum_algorithm="sha256",
    ),
}


def validate_image_pin(document: dict[object, object]) -> ImagePin:
    if not isinstance(document, dict):
        raise ImagePinError("image pin must be a mapping")
    expected = {
        "os", "version", "codename", "build", "name", "url",
        "checksum_algorithm", "checksum",
    }
    missing = expected - document.keys()
    unknown = document.keys() - expected
    if missing:
        raise ImagePinError(f"image pin is missing keys: {sorted(missing)}")
    if unknown:
        raise ImagePinError(f"image pin has unknown keys: {sorted(unknown)}")

    values = {key: str(document[key]).strip() for key in expected}
    try:
        policy = POLICIES[
            (values["os"], values["version"], values["codename"])
        ]
    except KeyError as error:
        raise ImagePinError(
            "unsupported image release: "
            f"{values['os']} {values['version']} {values['codename']}"
        ) from error
    pin = ImagePin(**values)
    if pin.version != policy.version or pin.codename != policy.codename:
        raise ImagePinError(
            f"{pin.os} image identity must be {policy.version} {policy.codename}"
        )
    if not policy.build_re.fullmatch(pin.build):
        raise ImagePinError(f"invalid {pin.os} cloud image build: {pin.build!r}")
    name_match = policy.name_re.fullmatch(pin.name)
    if not name_match:
        raise ImagePinError(f"name is not the exact supported {pin.os} amd64 image")
    if "build" in name_match.groupdict() and name_match.group("build") != pin.build:
        raise ImagePinError("image filename build does not match build")
    if pin.checksum_algorithm != policy.checksum_algorithm:
        raise ImagePinError(
            f"{pin.os} images require {policy.checksum_algorithm}, "
            f"found {pin.checksum_algorithm!r}"
        )
    digest_length = {"sha256": 64, "sha512": 128}[pin.checksum_algorithm]
    if not re.fullmatch(rf"[0-9a-f]{{{digest_length}}}", pin.checksum):
        raise ImagePinError(
            f"{pin.checksum_algorithm} must be {digest_length} lowercase hexadecimal characters"
        )

    parsed = urlparse(pin.url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != policy.host
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != policy.path(pin)
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ImagePinError(f"url must be the exact immutable {pin.os} image URL")
    return pin


def load_image_pin(path: Path) -> ImagePin:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ImagePinError(f"cannot read image pin {path}: {error}") from error
    except yaml.YAMLError as error:
        raise ImagePinError(f"cannot parse image pin {path}: {error}") from error
    return validate_image_pin(document)


def render_image_pin(pin: ImagePin, *, header: str) -> str:
    """Render every immutable coordinate together; never partially update a pin.

    `header` is the release's own comment block rather than a generated one, so
    each updater keeps naming its checksum source. A generated header would
    otherwise drift from the committed file and make the first automated update
    look like someone had edited the comment by hand.
    """
    return (
        f"{header.rstrip()}\n\n"
        f"os: {pin.os}\n"
        f"version: \"{pin.version}\"\n"
        f"codename: {pin.codename}\n"
        f"build: \"{pin.build}\"\n"
        f"name: {pin.name}\n"
        f"url: {pin.url}\n"
        f"checksum_algorithm: {pin.checksum_algorithm}\n"
        f"checksum: {pin.checksum}\n"
    )


def atomic_write(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
