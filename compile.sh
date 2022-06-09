#!/bin/sh

gcc -g -o main -lnghttp3 -lngtcp2 -lssl -lcrypto -lngtcp2_crypto_openssl -levent main.c
