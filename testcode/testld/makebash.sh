#!/bin/bash


rm *.o 
rm *.so
rm *.a

gcc -c lib2_static.c -fPIC
ar -cqs libdynamic2.a lib2_static.o

gcc  -shared -fPIC -o libdynamic.so lib2_static.c 

echo "to lib3 dynamic3"
#gcc  -shared -fPIC -o libdynamic3.so lib3_dynamic.c -L./ -ldynamic -Wl,--version-script=libmine.version -Wl,-rpath=./
gcc  lib3_dynamic.c -shared -fPIC -o libdynamic3.so -L./ -ldynamic -Wl,-rpath=./

echo "to lib1 dynamic1"
gcc  dynamic1.c -shared -fPIC -o libdynamic1.so  -L./  -ldynamic3 -Wl,-rpath=./

echo "to lib2 dynamic2"
gcc  lib2_dynamic.c -shared -fPIC -o libdynamic2.so 

echo "to main"
#gcc  main.c -Wl,-rpath=./ -L ./  -ldynamic1 -ldynamic2 
gcc  main.c -Wl,-rpath=./ -L ./ -ldynamic2 -ldl
