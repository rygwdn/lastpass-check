#!/usr/bin/env python
# encoding: utf-8

from hookutils import collect_submodules

hiddenimports = collect_submodules('keyring.backends')
