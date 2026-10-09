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
#
# Flower is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Flower.  If not, see <https://www.gnu.org/licenses/>.

import json
import os
from pathlib import Path

traffic_dir = Path(os.getenv("TULIP_TRAFFIC_DIR", "/traffic"))
dump_pcaps_dir = Path(os.getenv("DUMP_PCAPS", "/traffic"))
tick_length = os.getenv("TICK_LENGTH", 2*60*1000)
flag_lifetime = os.getenv("FLAG_LIFETIME", 5)
start_date = os.getenv("TICK_START", "2018-06-27T13:00:00+02:00")
flag_regex = os.getenv("FLAG_REGEX", "[A-Z0-9]{31}=")
vm_ip = os.getenv("VM_IP", "10.10.3.1")
visualizer_url = os.getenv("VISUALIZER_URL", "http://127.0.0.1:1337")

services_json = os.getenv("SERVICES_JSON", "")
services_file = Path(os.getenv("SERVICES_FILE", "")) if os.getenv("SERVICES_FILE") else None
if services_json:
    services = json.loads(services_json)
    if not isinstance(services, list):
        raise ValueError("SERVICES_JSON must contain a JSON list")
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("Each SERVICES_JSON entry must be an object")
        if not {"ip", "port", "name"}.issubset(service):
            raise ValueError("Each service requires ip, port, and name")
        service["port"] = int(service["port"])
else:
    services = [{"ip": vm_ip, "port": -1, "name": "other"}]


def get_services():
    if services_file and services_file.is_file():
        try:
            dynamic_services = json.loads(services_file.read_text(encoding="utf-8"))
            if not isinstance(dynamic_services, list):
                raise ValueError("services file must contain a list")
            for service in dynamic_services:
                if not isinstance(service, dict):
                    raise ValueError("invalid dynamic service entry")
                if not {"ip", "port", "name"}.issubset(service):
                    raise ValueError("dynamic service requires ip, port, and name")
                service["port"] = int(service["port"])
            return dynamic_services
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    return services
