#!/bin/sh
svn -q up
svn log | ./scripts/gnuify-changelog.pl > doc/ChangeLog
autoreconf -fi
