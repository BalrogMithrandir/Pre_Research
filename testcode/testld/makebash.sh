#!/bin/bash


rm *.o 
rm *.so
rm *.a

gcc -c lib2_static.c -fPIC

ar -cqs libstatic2.a lib2_static.o

gcc  -shared -fPIC -o libdynamic2.so lib2_dynamic.c

gcc  -shared -fPIC -o libdynamic1.so -lstatic2 -L./ dynamic1.c

gcc  main.c -ldynamic2 -L./

chmod +x out