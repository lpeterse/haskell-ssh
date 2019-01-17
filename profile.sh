#!/bin/bash

set -m
set -e

#trap 'kill $(jobs -p)' 0 1 2 3 6 9 15

#stack install
stack install --executable-profiling

#sh -c "sleep 3 && ssh fnord@localhost -vvvv ls > /dev/null"  &
#sh -c "sleep 3 && ssh fnord@localhost -vvvv ls > /dev/null"  &
#sh -c "sleep 3 && ssh fnord@localhost -vvvv ls > /dev/null"  &

#sudo timeout -s2 70 ~/.local/bin/hssh-demo +RTS -s -p -hm  || true
~/.local/bin/hssh-client +RTS -s -p -hy
#sudo ~/.local/bin/hssh-demo +RTS -s || true