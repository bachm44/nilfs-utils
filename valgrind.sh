#!/bin/bash

sudo libtool --mode=execute valgrind --tool=memcheck --leak-check=full --show-reachable=yes --track-origins=yes ./bin/dedup