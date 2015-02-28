#!/bin/sh

cd plugin
./build.sh
cd ../

g++ -g -Wall custcap.c -o tcp-monitor -lpcap -I./plugin/ -lplugin-myapp -L../tcp-monitor/ -Wl,-rpath=.
mv tcp-monitor ../tcp-monitor/


