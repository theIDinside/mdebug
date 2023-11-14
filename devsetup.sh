#!/bin/bash
echo "Setting up developer environment settings"

drivertest () {
  ctest --output-on-failure $@
}

rectest () {
  REC=rr ctest --output-on-failure $@
}

buildmdb () {
  ninja mdb
}