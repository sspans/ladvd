#!/bin/sh
svn up
svn2cl -o doc/ChangeLog
autoreconf -fi
