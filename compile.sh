#!/bin/sh

gcc -g -o main -lngtcp2 -lssl -lssl -lcrypto -lngtcp2_crypto_openssl -levent main.c
