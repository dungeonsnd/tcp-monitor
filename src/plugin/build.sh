#!/bin/sh

g++ -g -Wall -fPIC -shared -I. -I../ plugin_myapp_parser.c plugin_myapp_proto.c -pthread -o libplugin-myapp.so

mv libplugin-myapp.so ../../tcp-monitor/


