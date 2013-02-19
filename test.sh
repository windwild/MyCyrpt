#!/bin/bash

make
#./mycrypt -e -f testfile.txt -lpri lpri.pem -spub spub.pem -lp 5470
#./mycrypt -d -f testfile.txt.enc -cert cert.pem -spri spri.pem -sp 0745

./mycrypt -e -f testfile.txt -lpri newkeys/pwlpri.pem -spub newkeys/rsapubkey.pem -lp abc123
./mycrypt -d -f testfile.txt.enc -cert newkeys/mycert.pem -spri newkeys/rsakey.pem -sp abc123

#./mycrypt -d -f pic.enc -cert newkeys/mycert.pem -spri newkeys/rsakey.pem -sp abc123

make clean
#rm testfile.txt.enc

