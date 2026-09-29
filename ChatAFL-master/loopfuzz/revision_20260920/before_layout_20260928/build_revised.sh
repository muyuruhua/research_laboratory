#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")/.."
exec latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=revision_20260920 revision_20260920/main.revised.tex
