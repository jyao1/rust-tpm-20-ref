# rust-tpm-20-ref

A rust version tpm-20-ref implementation.

It refers to https://github.com/microsoft/ms-tpm-20-ref.

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the library and the drivers are subject to change.

## Submodule

1. ms-tpm-20-ref  TPM20 library
2. openssl        Crypto Library used by TPM20 library(Optional)

## Build

- cd ms-tpm-20-ref

  git submodule update --init --recursive

- smallc

  CC=clang AR=llvm-ar make

- openssl-stubs

  follow openssl-how-to.md to build libcrypto.a(crypto.lib)

- tpm

  CC=clang AR=llvm-ar make -j8

## Directory layout

### ms-tmp-20-ref

  TPM library

### openssl

  OpenSSL library

### small c library

  A small c library for OpenSSL in bare metal environment

### tpm

  Tpm for library

### openssl-stubs

  Openssl library running on bare metal environment stubs
