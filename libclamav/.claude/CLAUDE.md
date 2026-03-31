# libclamav -- Core Scanning Engine

The shared library (`libclamav.dylib` on macOS) that powers `clamd`, `clamscan`, `clamdscan`, and `clamonacc`. All malware detection logic lives here. Consumer binaries link against it and call the public C API defined in `clamav.h`.

## Scanning Pipeline (high level)

```
cl_init()  -->  cl_engine_new()  -->  cl_load()  -->  cl_engine_compile()  -->  cl_scandesc_ex() / cl_scanfile_ex()
  |                |                     |                   |                          |
  global init      alloc engine     load .cvd/.cld       optimize matcher          scan a file/fd
                                    signature DBs         data structures           return verdict
```

After scanning, call `cl_engine_free()` to release the engine. Verdicts are returned as `cl_error_t` (`CL_CLEAN`, `CL_VIRUS`). Extended scans via `cl_scandesc_ex()` / `cl_scanfile_ex()` also return `cl_verdict_t` with finer granularity (trusted, strong indicator, PUA).

## Key Subsystems

### Signature Database (`readdb.c`, `cvd.c`, `dsig.c`)
- `cl_load()` reads `.cvd` / `.cld` / `.cbc` files from a database directory
- `cvd.c` parses the CVD container format (gzipped tar with a digital signature header)
- `readdb.c` parses individual signature formats (`.ndb`, `.hdb`, `.mdb`, `.ldb`, `.yar`, etc.) and registers them in the engine's matcher tables
- `dsig.c` verifies legacy DSA signatures on database files

### CVD Certificate Verification (`cvd.c`, `crypto.c`, `crtmgr.c`)
- CVD files are verified using X.509 certificates via OpenSSL
- `cl_cvdverify_ex()` accepts a `certs_directory` path for certificate lookup
- Resistine bundles `clamav.crt` into `Resistine.app/Contents/certs/` and the LaunchDaemon sets `CVD_CERTS_DIR` to point there
- `crypto.c` provides the full OpenSSL wrapper API: hashing (`cl_hash_*`), signing (`cl_sign_*`), and X.509 verification (`cl_verify_signature_*`, `cl_validate_certificate_chain*`)

### Pattern Matching (`matcher*.c`, `filtering.c`)
- **Aho-Corasick** (`matcher-ac.c`) -- multi-pattern string matching, the primary engine
- **Boyer-Moore** (`matcher-bm.c`) -- single-pattern matching for specific signatures
- **PCRE** (`matcher-pcre.c`) -- regex-based signatures
- **Byte-compare** (`matcher-byte-comp.c`) -- numeric byte comparisons
- **Hash matching** (`matcher-hash.c`) -- MD5/SHA1/SHA256 file and section hashes
- `matcher.c` is the dispatch layer that orchestrates all matcher backends
- `filtering.c` pre-filters content to skip matcher invocation when possible

### File Format Parsers
Parsers extract content from container formats so signatures can match inner payloads:
- **Executables**: PE (`pe.c`), ELF (`elf.c`), Mach-O (`macho.c`), with Authenticode verification (`asn1.c`)
- **Archives**: ZIP (`unzip.c`), TAR (`untar.c`), 7z (`7z_iface.c`), ARJ (`unarj.c`), CAB/CHM (`libmspack.c`), DMG (`dmg.c`), XAR (`xar.c`), EGG (`egg.c`), CPIO (`cpio.c`), ISO9660 (`iso9660.c`)
- **Documents**: OLE2 (`ole2_extract.c`), OOXML (`ooxml.c`), PDF (`pdf.c`, `pdfng.c`), RTF (`rtf.c`), HWP (`hwp.c`), VBA (`vba_extract.c`), XLM macros (`xlm_extract.c`)
- **Mail**: MIME/mbox (`mbox.c`), TNEF (`tnef.c`), BinHex (`binhex.c`), UUEncode (`uuencode.c`)
- **Images**: JPEG, PNG, TIFF, GIF (format validation / exploit detection)
- **Disk images**: MBR (`mbr.c`), GPT (`gpt.c`), APM (`apm.c`), HFS+ (`hfsplus.c`), UDF (`udf.c`)
- **Other**: SWF/Flash (`swf.c`), AutoIt (`autoit.c`), NSIS installer (`nsis/nulsft.c`), SIS (`sis.c`)

### Bytecode Engine (`bytecode.c`, `bytecode_vm.c`, `bytecode_api.c`)
- Executes `.cbc` bytecode signatures for complex detection logic
- Has a built-in interpreter (`bytecode_vm.c`) and optional LLVM JIT backend (`c++/bytecode2llvm.cpp`)
- The JIT is only built when LLVM is found at configure time; otherwise falls back to `bytecode_nojit.c`

### YARA Support (`yara*.c`)
- Full YARA rule compiler and executor integrated as an object library
- Rules loaded via `readdb.c` alongside native ClamAV signatures

### Scanning Core (`scanners.c`, `scan_layer.c`, `fmap.c`, `cache.c`)
- `scanners.c` is the main scan dispatcher -- identifies file type, invokes the correct parser, runs matchers
- `fmap.c` provides memory-mapped file I/O for efficient scanning
- `cache.c` caches scan results by file hash to avoid re-scanning known files
- `scan_layer.c` tracks recursion through nested containers (zip-in-zip, etc.)

## Build

Built as a shared library via CMake (`add_library(clamav SHARED)`). On macOS, produces `libclamav.X.Y.Z.dylib`. The static library is also available when `ENABLE_STATIC_LIB` is on.

### External Dependencies
- **OpenSSL** (SSL + Crypto) -- certificate verification, hashing, signing
- **zlib** -- gzip decompression (CVD files, archives)
- **bzip2** -- bzip2 decompression
- **PCRE2** -- regex signature matching
- **libxml2** -- XML parsing (OOXML, XAR, MSXML documents)
- **json-c** -- JSON metadata output and API
- **libiconv** (macOS/Unix) -- character encoding conversion
- **CoreFoundation** (macOS only)
- **LLVM** (optional) -- bytecode JIT compilation

### Bundled Libraries (built as object libs, linked into libclamav)
- **regex** -- POSIX regex implementation
- **lzma_sdk** -- 7z / LZMA / XZ decompression
- **yara** -- YARA rule engine
- **bytecode_runtime** -- bytecode interpreter or LLVM JIT
- **libmspack** -- CAB / CHM extraction
- **libunrar** -- RAR extraction (separate interface library)
- **libclamav_rust** -- Rust components (via `clamav_rust.h`)

## Public API Quick Reference

```c
cl_error_t cl_init(unsigned int options);
struct cl_engine *cl_engine_new(void);
cl_error_t cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions);
cl_error_t cl_engine_compile(struct cl_engine *engine);
cl_error_t cl_scandesc_ex(int desc, const char *filename, ...);   // scan file descriptor
cl_error_t cl_scanfile_ex(const char *filename, ...);              // scan file by path
cl_error_t cl_engine_free(struct cl_engine *engine);
const char *cl_strerror(cl_error_t clerror);
cl_error_t cl_cvdverify_ex(const char *file, const char *certs_directory, uint32_t dboptions);
```

Engine configuration uses `cl_engine_set_num()` / `cl_engine_set_str()` with field constants (e.g., `CL_ENGINE_MAX_FILESIZE`, `CL_ENGINE_TMPDIR`). Callbacks for scan events are registered via `cl_engine_set_clcb_*()` functions.

## Gotchas

- The engine is **not thread-safe during loading/compilation** -- only after `cl_engine_compile()` can it be shared across threads for scanning
- `cl_engine_compile()` is expensive (builds AC automaton) -- do it once, scan many times
- CVD certificate path can be overridden at runtime via `CVD_CERTS_DIR` environment variable
- Rust components are linked from `libclamav_rust` -- the `clamav_rust.h` header is auto-generated
