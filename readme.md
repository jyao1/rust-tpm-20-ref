# rust-tpm-20-ref

A rust version tpm-20-ref implementation.

It refers to https://github.com/microsoft/ms-tpm-20-ref.

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the libary and the drivers are subject to change.

## Submodule

1. ms-tpm-20-ref  TPM20 library
2. openssl        Crypto Library used by TPM20 library(Optional)

## Build

### Build UEFI target

```
cargo build -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --target x86_64-unknown-uefi --release
```

## Directory layout

### ms-tmp-20-ref

  TPM library

### openssl

  OpenSSL library

### smallc

  A small libc for OpenSSL in baremetal environment

### tpm

  Tpm for library

### openssl-stubs

  Openssl library running on baremental environment stubs
