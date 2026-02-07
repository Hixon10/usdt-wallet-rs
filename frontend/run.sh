#!/bin/bash

set -e

cargo build -p frontend --target wasm32-unknown-unknown
wasm-pack build --target web
python3 -m http.server 8000