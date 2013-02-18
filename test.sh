#!/bin/bash

make
./mycrypt -e -f testfile.txt -lpri lpri.pem -spub spub.pem -lp 5470
./mycrypt -d -f testfile.txt.enc -cert cert.pem -spri spri.pem -sp 0745
make clean
#rm testfile.txt.enc

