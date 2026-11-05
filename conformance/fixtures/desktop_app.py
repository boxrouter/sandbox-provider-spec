# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Ordinary X11 application records real pointer/key events without installing a desktop."""

import ctypes as c
import ctypes.util
import json
import os
from pathlib import Path


class InputEvent(c.Structure):
    _fields_ = [
        ("type", c.c_int),
        ("serial", c.c_ulong),
        ("send_event", c.c_int),
        ("display", c.c_void_p),
        ("window", c.c_ulong),
        ("root", c.c_ulong),
        ("subwindow", c.c_ulong),
        ("time", c.c_ulong),
        ("x", c.c_int),
        ("y", c.c_int),
        ("x_root", c.c_int),
        ("y_root", c.c_int),
        ("state", c.c_uint),
        ("detail", c.c_uint),
        ("same_screen", c.c_int),
    ]


class Event(c.Union):
    _fields_ = [("type", c.c_int), ("input", InputEvent), ("padding", c.c_long * 24)]


class Attributes(c.Structure):
    _fields_ = [
        ("background_pixmap", c.c_ulong),
        ("background_pixel", c.c_ulong),
        ("border_pixmap", c.c_ulong),
        ("border_pixel", c.c_ulong),
        ("bit_gravity", c.c_int),
        ("win_gravity", c.c_int),
        ("backing_store", c.c_int),
        ("backing_planes", c.c_ulong),
        ("backing_pixel", c.c_ulong),
        ("save_under", c.c_int),
        ("event_mask", c.c_long),
        ("do_not_propagate_mask", c.c_long),
        ("override_redirect", c.c_int),
        ("colormap", c.c_ulong),
        ("cursor", c.c_ulong),
    ]


library = c.CDLL(ctypes.util.find_library("X11"))


def function(name, result, arguments):
    selected = getattr(library, name)
    selected.restype, selected.argtypes = result, arguments
    return selected


open_display = function("XOpenDisplay", c.c_void_p, [c.c_char_p])
root_window = function("XDefaultRootWindow", c.c_ulong, [c.c_void_p])
create = function(
    "XCreateSimpleWindow",
    c.c_ulong,
    [c.c_void_p, c.c_ulong, c.c_int, c.c_int, c.c_uint, c.c_uint, c.c_uint, c.c_ulong, c.c_ulong],
)
change = function(
    "XChangeWindowAttributes", c.c_int, [c.c_void_p, c.c_ulong, c.c_ulong, c.POINTER(Attributes)]
)
select = function("XSelectInput", c.c_int, [c.c_void_p, c.c_ulong, c.c_long])
show = function("XMapRaised", c.c_int, [c.c_void_p, c.c_ulong])
focus = function("XSetInputFocus", c.c_int, [c.c_void_p, c.c_ulong, c.c_int, c.c_ulong])
flush = function("XFlush", c.c_int, [c.c_void_p])
next_event = function("XNextEvent", c.c_int, [c.c_void_p, c.POINTER(Event)])
lookup = function(
    "XLookupString",
    c.c_int,
    [c.POINTER(InputEvent), c.c_void_p, c.c_int, c.POINTER(c.c_ulong), c.c_void_p],
)

displays = [
    os.environ.get("DISPLAY"),
    *[":" + p.name[1:] for p in Path("/tmp/.X11-unix").glob("X*")],
]
display = None
for name in dict.fromkeys(item for item in displays if item):
    display = open_display(name.encode())
    if display:
        break
if not display:
    raise RuntimeError("native graphical display unavailable")
window = create(display, root_window(display), 0, 0, 400, 200, 0, 0, 0x11CB59)
attributes = Attributes()
attributes.override_redirect = 1
change(display, window, 1 << 9, c.byref(attributes))
select(display, window, 1 | 4)
show(display, window)
focus(display, window, 2, 0)
flush(display)
state = {"ready": True, "pointer_received": False, "typed": ""}
path = Path("/tmp/sps-desktop-events.json")


def save():
    pending = path.with_suffix(".pending")
    pending.write_text(json.dumps(state))
    pending.replace(path)


save()
typed = ""
event = Event()
while True:
    next_event(display, c.byref(event))
    if event.type == 4:
        state["pointer_received"] = True
        focus(display, window, 2, 0)
        flush(display)
        save()
    elif event.type == 2:
        buffer = c.create_string_buffer(64)
        symbol = c.c_ulong()
        length = lookup(c.byref(event.input), buffer, 64, c.byref(symbol), None)
        value = buffer.raw[:length].decode("utf-8", errors="replace")
        if value in {"\r", "\n"}:
            state["typed"] = typed
            save()
        elif value == "\b":
            typed = typed[:-1]
        else:
            typed += value
