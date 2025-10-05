#!/usr/bin/env bash

set -x
set -e

mypy src
ruff check src
ruff format src --check
