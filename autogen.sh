#!/bin/sh
svn -q up
svn2cl -o doc/ChangeLog
autoreconf -fi
