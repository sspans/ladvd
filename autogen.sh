#!/bin/sh
svn -q up
svn2cl --stdout | sed -e 's! /! !g' > doc/ChangeLog
autoreconf -fi
