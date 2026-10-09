#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Flower.
#
# Copyright ©2018 Nicolò Mazzucato
# Copyright ©2018 Antonio Groza
# Copyright ©2018 Brunello Simone
# Copyright ©2018 Alessio Marotta
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# Flower is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from database import FlowDetail
from ecsc_export import render_ecsc_exploit


def escape(value):
    if isinstance(value, str):
        value = ord(value)
    result = chr(value) if 0x20 <= value < 0x7F else f"\\x{value:02x}"
    if result in '\\"':
        result = "\\" + result
    return result


def convert(message):
    return "".join(escape(value) for value in message)


def flow2pwn(
    flow: FlowDetail,
    *,
    service_name: str = "service",
    candidates: list[str] | None = None,
):
    """Convert a captured TCP conversation into a pwntools ECSC runner."""
    body = [
        'context.log_level = os.getenv("PWNLIB_LOG_LEVEL", "error")',
        "output = bytearray()",
        "connection = remote(target.host, target.port, timeout=target.timeout)",
        "try:",
    ]

    for item in flow.kind_items():
        if item.direction == "c":
            body.append(f'    connection.send(materialize(b"{convert(item.data)}", target))')
        else:
            delimiter = convert(item.data[-10:]).replace("\n", "\\n")
            if delimiter:
                body.append(
                    f'    output.extend(connection.recvuntil(b"{delimiter}", timeout=target.timeout))'
                )

    body.extend(
        [
            "    try:",
            "        output.extend(connection.recvall(timeout=min(1.0, target.timeout)))",
            "    except EOFError:",
            "        pass",
            "finally:",
            "    connection.close()",
            "return bytes(output)",
        ]
    )

    return render_ecsc_exploit(
        service=service_name,
        port=flow.port_dst,
        protocol="tcp",
        candidates=candidates or [],
        imports='os.environ.setdefault("PWNLIB_NOTERM", "1")\nfrom pwn import context, remote',
        exploit_body="\n".join(body),
    )
