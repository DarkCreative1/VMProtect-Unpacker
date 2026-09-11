# VMProtect Unpacker
VMProtect 3.x unpacker. Static LZMA unpack, runtime dump, IAT fix.

## usage

```text
VMProtect.exe [--wait ms] [--decompress-only] [--strip-vmp] <packed> <out>
VMProtect.exe --runtime [--wait ms] [--strip-vmp] <packed> <out>
VMProtect.exe --pid <pid> [--module name] [--strip-vmp] <out>
VMProtect.exe --lift [--vmenter va] [--max-ops n] <in> [outdir]
```

## examples

```text
VMProtect.exe packed.exe unpacked.exe
VMProtect.exe --strip-vmp packed.exe unpacked.exe
VMProtect.exe --decompress-only packed.exe decompressed.exe
VMProtect.exe --runtime packed.exe dumped.exe
VMProtect.exe --pid 1234 --module Loader.exe(you can specify it to dump another injected module) dumped.exe
VMProtect.exe --lift virtualized.exe
VMProtect.exe --lift --vmenter 0x140001000 --max-ops 256 virtualized.exe lift-out
```

Use `--decompress-only` when you need the old decompression-only output. If offline loader emulation cannot recover imports for a VMProtect build, the command fails without writing a partial output and suggests `--decompress-only` or `--runtime`.
