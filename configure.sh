#!/bin/bash

set -euo pipefail

./configure CFLAGS='-g -O0 -fstack-protector-strong -Wall -Wformat -Wformat-security -fstack-clash-protection -fcf-protection -Wl,-z,relro -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fno-sanitize=null -fno-sanitize=alignment' --enable-silent-rules
