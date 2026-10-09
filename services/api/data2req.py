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

from http.server import BaseHTTPRequestHandler
from io import BytesIO
import json
from urllib.parse import parse_qs

from database import FlowDetail
from ecsc_export import render_ecsc_exploit


DISCARD_COOKIES = ["PHPSESSID", "wordpress_logged_in_", "session"]


class HTTPRequest(BaseHTTPRequestHandler):
    """Small, side-effect-free parser for a captured raw HTTP request."""

    def __init__(self, raw_http_request: bytes):
        self.rfile = BytesIO(raw_http_request)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

        self.headers: dict[str, str]
        try:
            self.headers = dict(self.headers)
        except AttributeError:
            self.headers = {}

        try:
            self.body = raw_http_request.split(b"\r\n\r\n", 1)[1].rstrip()
        except IndexError:
            self.body = None

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message


def decode_http_request(raw_request: bytes, tokenize: bool):
    request = HTTPRequest(raw_request)
    headers = {}
    blocked_headers = {
        "content-length",
        "accept-encoding",
        "connection",
        "accept",
        "host",
    }
    content_type = ""
    data = None
    data_param_name = None

    for key in request.headers:
        normalized_header = key.lower()
        if normalized_header == "content-type":
            content_type = request.headers[key]
        if normalized_header not in blocked_headers:
            headers[key] = request.headers[key]

    if tokenize and request.body:
        if content_type.startswith("application/x-www-form-urlencoded"):
            data_param_name = "data"
            data = {}
            body_dict = parse_qs(request.body.decode())
            for key, value in body_dict.items():
                data[key] = value[0] if len(value) == 1 else value

        if content_type.startswith("application/json"):
            data_param_name = "json"
            try:
                data = json.loads(request.body)
            except json.decoder.JSONDecodeError:
                pass

        if data is None:
            data_param_name = "data"
            data = request.body

    return request, data, data_param_name, headers


def _request_lines(raw_request: bytes, *, tokenize: bool) -> list[str]:
    request, data, data_param_name, headers = decode_http_request(raw_request, tokenize)
    if not request.path.startswith("/"):
        raise ValueError("request path must start with / to be a valid HTTP request")
    method = validate_request_method(request.command)

    lines = [
        f"headers = materialize({headers!r}, flag_id)",
        f"url = f\"http://{{host}}:{{port}}\" + materialize({request.path!r}, flag_id)",
    ]
    arguments = ["url"]
    if data is not None:
        lines.append(f"data = materialize({data!r}, flag_id)")
        arguments.append(f"{data_param_name}=data")
    arguments.extend(["headers=headers", "timeout=timeout"])
    lines.extend(
        [
            f"response = session.{method}({', '.join(arguments)})",
            "output.extend(response.content)",
            "output.extend(b\"\\n\")",
        ]
    )
    return lines


def _render_flow(
    flow: FlowDetail,
    requests_to_replay: list[bytes],
    *,
    tokenize: bool,
    service_name: str,
    candidates: list[str] | None,
    attack_info_tokens: list[str] | None,
) -> str:
    body = ["output = bytearray()", "session = requests.Session()"]
    for raw_request in requests_to_replay:
        body.extend(_request_lines(raw_request, tokenize=tokenize))
    body.append("return bytes(output)")

    return render_ecsc_exploit(
        service=service_name,
        port=flow.port_dst,
        protocol="http",
        candidates=candidates or [],
        attack_info_tokens=attack_info_tokens or [],
        imports="import requests",
        exploit_body="\n".join(body),
    )


def convert_single_http_requests(
    flow: FlowDetail,
    item_index: int,
    tokenize: bool = True,
    use_requests_session: bool = False,
    service_name: str = "service",
    candidates: list[str] | None = None,
    attack_info_tokens: list[str] | None = None,
):
    # Kept for API compatibility. A per-target Session is always used because
    # the ECSC runner may execute different targets concurrently.
    del use_requests_session
    if not flow.items:
        return "No data"
    return _render_flow(
        flow,
        [flow.items[item_index].data],
        tokenize=tokenize,
        service_name=service_name,
        candidates=candidates,
        attack_info_tokens=attack_info_tokens,
    )


def convert_flow_to_http_requests(
    flow: FlowDetail,
    tokenize: bool = True,
    use_requests_session: bool = True,
    service_name: str = "service",
    candidates: list[str] | None = None,
    attack_info_tokens: list[str] | None = None,
):
    del use_requests_session
    raw_requests = [item.data for item in flow.kind_items() if item.direction == "c"]
    return _render_flow(
        flow,
        raw_requests,
        tokenize=tokenize,
        service_name=service_name,
        candidates=candidates,
        attack_info_tokens=attack_info_tokens,
    )


def validate_request_method(request_method: str):
    request_method = request_method.lower()
    if request_method not in {
        "delete",
        "get",
        "head",
        "options",
        "patch",
        "post",
        "put",
    }:
        raise ValueError(f"Invalid request method: {request_method}")
    return request_method
