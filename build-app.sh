#!/bin/sh

g++ -DHAVE_CONFIG_H -I/usr/local/src/libvmi-master -I/usr/include/glib-2.0 \
-I/usr/lib/x86_64-linux-gnu/glib-2.0/include -Wall -Wextra -g -O2 -MT $1.o -MD -MP -c -o $1.o $1.cpp

libtool --tag=CXX --mode=link gcc -I/usr/local/src/libvmi-master -I/usr/include/glib-2.0 \
-I/usr/lib/x86_64-linux-gnu/glib-2.0/include -Wall -Wextra \
 -g -O2 -L/usr/local/src/libvmi-master/libvmi/.libs/ -o $2 $1.o -lvmi -lm -ldl -lglib-2.0 -ldl
