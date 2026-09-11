#!/usr/bin/env python3
import json
import os
import tempfile
from datetime import datetime, timezone

import yaml
from jinja2 import Environment, FileSystemLoader

ROOT = os.environ.get("GREENPROOF_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def repo_root():
    return ROOT


def abs_path(*parts):
    return os.path.join(ROOT, *parts)


def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)



def load_config(root=ROOT):
    with open(os.path.join(root, "config.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)



def read_json_file(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)



def atomic_write_text(path, content):
    ensure_parent_dir(path)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=os.path.dirname(path), delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    os.replace(tmp_path, path)



def atomic_write_json(path, data):
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")



def utc_today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")



def template_env(root=ROOT):
    return Environment(
        loader=FileSystemLoader(os.path.join(root, "templates")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
