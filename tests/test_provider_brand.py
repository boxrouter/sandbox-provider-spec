# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Provider marks exist, coloured marks are clean, and every mark draws at its recorded size.

A mark is drawn in a 16 px box ("contain") by the dashboard. The size checks measure the bounding
box of the drawn ink without a browser: SVG path geometry, or the opaque pixels of a PNG.
"""

from __future__ import annotations

import math
import re
import struct
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import Any

import pytest
import yaml

from sandbox_provider_spec import provider_assets

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ROOT / "providers"
BOX = 16.0
TOLERANCE = 1.0
ALPHA_FLOOR = 40
NUMBER = re.compile(r"[-+]?(?:\d*\.\d+|\d+\.?)(?:[eE][-+]?\d+)?")
TOKEN = re.compile(r"[MmLlHhVvCcAaZz]|" + NUMBER.pattern)
SVG = "{http://www.w3.org/2000/svg}"
DRAWN = {"svg", "g", "path"}
IGNORED = {"defs", "linearGradient", "stop", "metadata", "title"}
Point = tuple[float, float]


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _brands() -> dict[str, dict[str, Any]]:
    brands: dict[str, dict[str, Any]] = provider_assets.build()["brand.json"]["providers"]
    return brands


def _mark_file(provider: str) -> Path:
    declared = _load(PROVIDERS / provider / "brand.yaml")
    return PROVIDERS / provider / str(declared["mark"])


def _arc(
    start: Point, rx: float, ry: float, turn: float, large: int, sweep: int, end: Point
) -> list[Point]:
    """Points along an SVG elliptical arc (endpoint form, no axis rotation beyond `turn`)."""
    if rx == 0 or ry == 0 or start == end:
        return [end]
    phi = math.radians(turn)
    cos, sin = math.cos(phi), math.sin(phi)
    dx, dy = (start[0] - end[0]) / 2, (start[1] - end[1]) / 2
    x1, y1 = cos * dx + sin * dy, -sin * dx + cos * dy
    rx, ry = abs(rx), abs(ry)
    scale = x1 * x1 / (rx * rx) + y1 * y1 / (ry * ry)
    if scale > 1:
        rx, ry = rx * math.sqrt(scale), ry * math.sqrt(scale)
    num = rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1
    den = rx * rx * y1 * y1 + ry * ry * x1 * x1
    factor = math.sqrt(max(0.0, num / den)) * (-1 if large == sweep else 1)
    cx1, cy1 = factor * rx * y1 / ry, -factor * ry * x1 / rx
    cx = cos * cx1 - sin * cy1 + (start[0] + end[0]) / 2
    cy = sin * cx1 + cos * cy1 + (start[1] + end[1]) / 2
    start_angle = math.atan2((y1 - cy1) / ry, (x1 - cx1) / rx)
    end_angle = math.atan2((-y1 - cy1) / ry, (-x1 - cx1) / rx)
    delta = end_angle - start_angle
    if sweep and delta < 0:
        delta += 2 * math.pi
    if not sweep and delta > 0:
        delta -= 2 * math.pi
    points = []
    for step in range(1, 65):
        angle = start_angle + delta * step / 64
        px, py = rx * math.cos(angle), ry * math.sin(angle)
        points.append((cos * px - sin * py + cx, sin * px + cos * py + cy))
    return points


def _path_points(data: str) -> list[Point]:
    """Every point the path's outline passes through, sampled along its curves."""
    tokens = TOKEN.findall(data)
    points: list[Point] = []
    here = start = (0.0, 0.0)
    command = ""
    index = 0

    def take(count: int) -> list[float]:
        nonlocal index
        values = [float(token) for token in tokens[index : index + count]]
        index += count
        return values

    while index < len(tokens):
        if tokens[index].isalpha():
            command = tokens[index]
            index += 1
        relative = command.islower()
        kind = command.upper()
        if kind == "Z":
            here = start
            continue
        ox, oy = here if relative else (0.0, 0.0)
        if kind in "ML":
            x, y = take(2)
            here = (ox + x, oy + y)
            if kind == "M":
                start = here
                command = "l" if relative else "L"
            points.append(here)
        elif kind == "H":
            here = ((here[0] if relative else 0.0) + take(1)[0], here[1])
            points.append(here)
        elif kind == "V":
            here = (here[0], (here[1] if relative else 0.0) + take(1)[0])
            points.append(here)
        elif kind == "C":
            x1, y1, x2, y2, x, y = take(6)
            p0 = here
            p1, p2, p3 = (ox + x1, oy + y1), (ox + x2, oy + y2), (ox + x, oy + y)
            for step in range(1, 65):
                t = step / 64
                a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t * t, t**3
                points.append(
                    (
                        a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0],
                        a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1],
                    )
                )
            here = p3
        elif kind == "A":
            rx, ry, turn, large, sweep, x, y = take(7)
            end = (ox + x, oy + y)
            points.extend(_arc(here, rx, ry, turn, int(large), int(sweep), end))
            here = end
        else:
            raise ValueError(f"unsupported path command {command}")
    return points


def _translate(value: str | None) -> Point:
    if value is None:
        return (0.0, 0.0)
    numbers = NUMBER.findall(value)
    if not value.strip().startswith("translate(") or len(numbers) != 2:
        raise ValueError(f"unsupported transform {value!r}")
    return (float(numbers[0]), float(numbers[1]))


def svg_ink(path: Path) -> tuple[float, float]:
    """Width and height in px of the SVG's drawn ink, drawn "contain" in the 16 px box."""
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    view = [float(value) for value in NUMBER.findall(root.get("viewBox", ""))]
    assert len(view) == 4, f"{path}: needs a viewBox"
    stroke = root.get("stroke-width") if root.get("stroke", "none") != "none" else None
    outline: list[Point] = []

    def walk(element: ET.Element, shift: Point) -> None:
        name = element.tag.removeprefix(SVG)
        if name in IGNORED:
            return
        assert name in DRAWN, f"{path}: cannot measure <{name}>"
        if name == "g":
            inner = _translate(element.get("transform"))
            shift = (shift[0] + inner[0], shift[1] + inner[1])
        for point in _path_points(element.get("d", "")) if name == "path" else []:
            outline.append((point[0] + shift[0], point[1] + shift[1]))
        for child in element:
            walk(child, shift)

    walk(root, (0.0, 0.0))
    half = float(stroke) / 2 if stroke else 0.0
    ink_w = max(x for x, _ in outline) - min(x for x, _ in outline) + 2 * half
    ink_h = max(y for _, y in outline) - min(y for _, y in outline) + 2 * half
    intrinsic = [
        float(root.get(name, view[index + 2])) for index, name in enumerate(("width", "height"))
    ]
    fit = min(BOX / intrinsic[0], BOX / intrinsic[1])
    scale = fit * min(intrinsic[0] / view[2], intrinsic[1] / view[3])
    return (ink_w * scale, ink_h * scale)


def png_ink(path: Path) -> tuple[float, float]:
    """Width and height in px of the PNG's pixels above the alpha floor, in the 16 px box."""
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path}: not a PNG"
    width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", data[16:29])
    assert (depth, color, interlace) == (8, 6, 0), f"{path}: only 8-bit RGBA PNGs are measured"
    chunks, offset = [], 8
    while offset < len(data):
        (size,) = struct.unpack(">I", data[offset : offset + 4])
        if data[offset + 4 : offset + 8] == b"IDAT":
            chunks.append(data[offset + 8 : offset + 8 + size])
        offset += 12 + size
    raw = zlib.decompress(b"".join(chunks))
    stride, previous = width * 4, bytearray(width * 4)
    columns: list[int] = []
    rows: list[int] = []
    for row in range(height):
        start = row * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1 : start + 1 + stride])
        for i in range(stride):
            left = line[i - 4] if i >= 4 else 0
            up = previous[i]
            upleft = previous[i - 4] if i >= 4 else 0
            if kind == 1:
                line[i] = (line[i] + left) & 255
            elif kind == 2:
                line[i] = (line[i] + up) & 255
            elif kind == 3:
                line[i] = (line[i] + (left + up) // 2) & 255
            elif kind == 4:
                guess = left + up - upleft
                near = min(
                    (abs(guess - left), left), (abs(guess - up), up), (abs(guess - upleft), upleft)
                )
                line[i] = (line[i] + near[1]) & 255
        previous = line
        solid = [x for x in range(width) if line[x * 4 + 3] > ALPHA_FLOOR]
        if solid:
            rows.append(row)
            columns.extend((min(solid), max(solid)))
    scale = BOX / max(width, height)
    return ((max(columns) - min(columns) + 1) * scale, (rows[-1] - rows[0] + 1) * scale)


def ink(path: Path) -> tuple[float, float]:
    return svg_ink(path) if path.suffix == ".svg" else png_ink(path)


def test_every_served_provider_has_a_brand_mark() -> None:
    served = _load(Path(__file__).parent / "fixtures" / "served-providers.yaml")
    brands = _brands()
    assert [name for name in served if "mark" not in brands.get(name, {})] == []


@pytest.mark.parametrize(
    "provider", sorted(name for name, b in _brands().items() if b.get("mark_colours"))
)
def test_a_coloured_mark_holds_only_the_brands_paths(provider: str) -> None:
    mark = _mark_file(provider)
    assert mark.suffix == ".svg"
    text = mark.read_text(encoding="utf-8")
    root = ET.fromstring(text)
    view = [float(value) for value in NUMBER.findall(root.get("viewBox", ""))]
    tags = {element.tag.removeprefix(SVG) for element in root.iter()}
    assert "image" not in tags
    assert "filter" not in tags and "filter=" not in text
    for element in root.iter(f"{SVG}rect"):
        covers = [float(element.get(name, 0)) for name in ("x", "y", "width", "height")]
        assert not (covers[2] >= view[2] and covers[3] >= view[3]), "a rect covers the viewBox"
    for value in re.findall(r"(?:fill|stroke|stop-color)(?:=\"|:\s*)(#[0-9A-Fa-f]{3,8})", text):
        digits = value.lstrip("#")
        digits = "".join(c * 2 for c in digits[:3]) if len(digits) in (3, 4) else digits[:6]
        channels = [int(digits[i : i + 2], 16) for i in (0, 2, 4)]
        assert min(channels) < 0xE6, f"{value} is white or near white"
    assert not re.search(r"(?:fill|stroke)=\"(?:white|currentColor)\"", text)


@pytest.mark.parametrize("provider", sorted(_brands()))
def test_a_mark_draws_at_its_recorded_size(provider: str) -> None:
    recorded = _load(PROVIDERS / provider / "brand" / "sizes.yaml")
    width, height = ink(_mark_file(provider))
    assert abs(width - recorded["width"]) <= TOLERANCE, (width, recorded)
    assert abs(height - recorded["height"]) <= TOLERANCE, (height, recorded)
    assert 12.0 <= max(width, height) <= BOX


def test_mark_colours_must_say_own(tmp_path: Path) -> None:
    folder = tmp_path / "providers" / "sixth"
    (folder / "brand").mkdir(parents=True)
    (folder / "brand" / "mark.svg").write_text("<svg/>")
    for declared, expected in (({"mark_colours": "own"}, "own"), ({"mark_colours": "mixed"}, None)):
        (folder / "brand.yaml").write_text(yaml.safe_dump({"mark": "brand/mark.svg", **declared}))
        if expected:
            assert (
                provider_assets.build(tmp_path)["brand.json"]["providers"]["sixth"]["mark_colours"]
                == expected
            )
        else:
            with pytest.raises(ValueError, match="mark_colours"):
                provider_assets.build(tmp_path)
    (folder / "brand.yaml").write_text(yaml.safe_dump({"mark_colours": "own"}))
    with pytest.raises(ValueError, match="needs a mark"):
        provider_assets.build(tmp_path)
