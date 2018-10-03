#!/bin/bash

set -m

trap 'kill $(jobs -p)' 1 2 3 6 9 15

stack install --executable-profiling

sudo ~/.local/bin/hssh-demo +RTS -s -p -hc &
sleep 1
ssh fnord@localhost -vvvv ls &
ssh fnord@localhost -vvvv ls &
ssh fnord@localhost -vvvv ls &

sleep 600

sudo pkill -2 hssh-demo
sleep 2
kill -2 $(jobs -p) || true
