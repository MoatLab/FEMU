# Reference tables

## Compiler ids

These are return values of the `get_id` (Compiler family) and
`get_argument_syntax` (Argument syntax) method in a compiler object.

| Value     | Compiler family                  | Argument syntax |
| -----     | ---------------                  | --------------- |
| arm       | ARM compiler                     |                 |
| armclang  | ARMCLANG compiler                |                 |
| c2000     | Texas Instruments C2000 compiler |                 |
| ccomp     | The CompCert formally-verified C compiler |        |
| ccrx      | Renesas RX Family C/C++ compiler |                 |
| clang     | The Clang compiler               | gcc             |
| clang-cl  | The Clang compiler (MSVC compatible driver) | msvc |
| dmd       | D lang reference compiler        |                 |
| emscripten| Emscripten WASM compiler         |                 |
| flang     | Flang Fortran compiler           |                 |
| g95       | The G95 Fortran compiler         |                 |
| gcc       | The GNU Compiler Collection      | gcc             |
| intel     | Intel compiler (Linux and Mac)   | gcc             |
| intel-cl  | Intel compiler (Windows)         | msvc            |
| lcc       | Elbrus C/C++/Fortran Compiler    |                 |
| llvm      | LLVM-based compiler (Swift, D)   |                 |
| mono      | Xamarin C# compiler              |                 |
| msvc      | Microsoft Visual Studio          | msvc            |
| nagfor    | The NAG Fortran compiler         |                 |
| nvidia_hpc| NVidia HPC SDK compilers         |                 |
| open64    | The Open64 Fortran Compiler      |                 |
| pathscale | The Pathscale Fortran compiler   |                 |
| pgi       | Portland PGI C/C++/Fortran compilers |             |
| rustc     | Rust compiler                    |                 |
| sun       | Sun Fortran compiler             |                 |
| valac     | Vala compiler                    |                 |
| xc16      | Microchip XC16 C compiler        |                 |
| cython    | The Cython compiler              |                 |

## Linker ids

These are return values of the `get_linker_id` method in a compiler object.

| Value      | Linker family                               |
| -----      | ---------------                             |
| ld.bfd     | The GNU linker                              |
| ld.gold    | The GNU gold linker                         |
| ld.lld     | The LLVM linker, with the GNU interface     |
| ld.solaris | Solaris and illumos                         |
| ld.wasm    | emscripten's wasm-ld linker                 |
| ld64       | Apple ld64                                  |
| link       | MSVC linker                                 |
| lld-link   | The LLVM linker, with the MSVC interface    |
| xilink     | Used with Intel-cl only, MSVC like          |
| optlink    | optlink (used with DMD)                     |
| rlink      | The Renesas linker, used with CCrx only     |
| xc16-ar    | The Microchip linker, used with XC16 only   |
| ar2000     | The Texas Instruments linker, used with C2000 only |
| armlink    | The ARM linker (arm and armclang compilers) |
| pgi        | Portland/Nvidia PGI                         |
| nvlink     | Nvidia Linker used with cuda                |
| ccomp      | CompCert used as the linker driver          |

For languages that don't have separate dynamic linkers such as C# and Java, the
`get_linker_id` will return the compiler name.

## Script environment variables

| Value               | Comment                         |
| -----               | -------                         |
| MESONINTROSPECT     | Command to run to run the introspection command, may be of the form `python /path/to/meson introspect`, user is responsible for splitting the path if necessary. |
| MESON_BUILD_ROOT    | Absolute path to the build dir  |
| MESON_DIST_ROOT     | Points to the root of the staging directory, only set when running `dist` scripts |
| MESON_SOURCE_ROOT   | Absolute path to the source dir |
| MESON_SUBDIR        | Current subdirectory, only set for `run_command` |

## CPU families

These are returned by the `cpu_family` method of `build_machine`,
`host_machine` and `target_machine`. For cross compilation they are
set in the cross file.

| Value               | Comment                  |
| -----               | -------                  |
| aarch64             | 64 bit ARM processor     |
| alpha               | DEC Alpha processor      |
| arc                 | 32 bit ARC processor     |
| arm                 | 32 bit ARM processor     |
| avr                 | Atmel AVR processor      |
| c2000               | 32 bit C2000 processor   |
| csky                | 32 bit CSky processor    |
| dspic               | 16 bit Microchip dsPIC   |
| e2k                 | MCST Elbrus processor    |
| ia64                | Itanium processor        |
| loongarch64         | 64 bit Loongson processor|
| m68k                | Motorola 68000 processor |
| microblaze          | MicroBlaze processor     |
| mips                | 32 bit MIPS processor    |
| mips64              | 64 bit MIPS processor    |
| parisc              | HP PA-RISC processor     |
| pic24               | 16 bit Microchip PIC24   |
| ppc                 | 32 bit PPC processors    |
| ppc64               | 64 bit PPC processors    |
| riscv32             | 32 bit RISC-V Open ISA   |
| riscv64             | 64 bit RISC-V Open ISA   |
| rl78                | Renesas RL78             |
| rx                  | Renesas RX 32 bit MCU    |
| s390                | IBM zSystem s390         |
| s390x               | IBM zSystem s390x        |
| sh4                 | SuperH SH-4              |
| sparc               | 32 bit SPARC             |
| sparc64             | SPARC v9 processor       |
| wasm32              | 32 bit Webassembly       |
| wasm64              | 64 bit Webassembly       |
| x86                 | 32 bit x86 processor     |
| x86_64              | 64 bit x86 processor     |

Any cpu family not listed in the above list is not guaranteed to
remain stable in future releases.

Those porting from autotools should note that Meson does not add
endianness to the name of the cpu_family. For example, autotools
will call little endian PPC64 "ppc64le", Meson will not, you must
also check the `.endian()` value of the machine for this information.

## Operating system names

These are provided by the `.system()` method call.

| Value               | Comment                         |
| -----               | -------                         |
| android             | By convention only, subject to change |
| cygwin              | The Cygwin environment for Windows |
| darwin              | Either OSX or iOS |
| dragonfly           | DragonFly BSD |
| emscripten          | Emscripten's Javascript environment |
| freebsd             | FreeBSD and its derivatives |
| gnu                 | GNU Hurd |
| haiku               | |
| linux               | |
| netbsd              | |
| openbsd             | |
| windows             | Any version of Windows |
| sunos               | illumos and Solaris |

Any string not listed above is not guaranteed to remain stable in
future releases.

## Language arguments parameter names

These are the parameter names for passing language specific arguments to your build target.

| Language      | compiler name | linker name       |
| ------------- | ------------- | ----------------- |
| C             | c_args        | c_link_args       |
| C++           | cpp_args      | cpp_link_args     |
| C#            | cs_args       | cs_link_args      |
| D             | d_args        | d_link_args       |
| Fortran       | fortran_args  | fortran_link_args |
| Java          | java_args     | java_link_args    |
| Objective C   | objc_args     | objc_link_args    |
| Objective C++ | objcpp_args   | objcpp_link_args  |
| Rust          | rust_args     | rust_link_args    |
| Vala          | vala_args     | vala_link_args    |
| Cython        | cython_args   | cython_link_args  |

All these `<lang>_*` options are specified per machine. See in
[specifying options per
machine](Builtin-options.md#Specifying-options-per-machine) for on how
to do this in cross builds.

## Compiler and linker flag environment variables

These environment variables will be used to modify the compiler and
linker flags.

It is recommended that you **do not use these**. They are provided
purely to for backwards compatibility with other build systems. There
are many caveats to their use, especially when rebuilding the project.
It is **highly** recommended that you use [the command line
arguments](#language-arguments-parameter-names) instead.

| Name        | Comment                                  |
| -----       | -------                                  |
| CFLAGS      | Flags for the C compiler                 |
| CXXFLAGS    | Flags for the C++ compiler               |
| OBJCFLAGS   | Flags for the Objective C compiler       |
| FFLAGS      | Flags for the Fortran compiler           |
| DFLAGS      | Flags for the D compiler                 |
| VALAFLAGS   | Flags for the Vala compiler              |
| RUSTFLAGS   | Flags for the Rust compiler              |
| CYTHONFLAGS | Flags for the Cython compiler            |
| LDFLAGS     | The linker flags, used for all languages |

N.B. these settings are specified per machine, and so the environment
varibles actually come in pairs. See the [environment variables per
machine](#Environment-variables-per-machine) section for details.

## Function Attributes

These are the parameters names that are supported using
`compiler.has_function_attribute()` or
`compiler.get_supported_function_attributes()`

### GCC `__attribute__`

These values are supported using the GCC style `__attribute__` annotations,
which are supported by GCC, Clang, and other compilers.


| Name                     |
|--------------------------|
| alias                    |
| aligned                  |
| alloc_size               |
| always_inline            |
| artificial               |
| cold                     |
| const                    |
| constructor              |
| constructor_priority     |
| deprecated               |
| destructor               |
| error                    |
| externally_visible       |
| fallthrough              |
| flatten                  |
| format                   |
| format_arg               |
| force_align_arg_pointer³ |
| gnu_inline               |
| hot                      |
| ifunc                    |
| malloc                   |
| noclone                  |
| noinline                 |
| nonnull                  |
| noreturn                 |
| nothrow                  |
| optimize                 |
| packed                   |
| pure                     |
| returns_nonnull          |
| unused                   |
| used                     |
| visibility*              |
| visibility:default†      |
| visibility:hidden†       |
| visibility:internal†     |
| visibility:protected†    |
| warning                  |
| warn_unused_result       |
| weak                     |
| weakreaf                 |

\* *Changed in 0.52.0* the "visibility" target no longer includes
"protected", which is not present in Apple's clang.

† *New in 0.52.0* These split visibility attributes are preferred to the plain
"visibility" as they provide narrower checks.

³ *New in 0.55.0*

### MSVC __declspec

These values are supported using the MSVC style `__declspec` annotation,
which are supported by MSVC, GCC, Clang, and other compilers.

| Name                 |
|----------------------|
| dllexport            |
| dllimport            |


## Dependency lookup methods

These are the values that can be passed to `dependency` function's
`method` keyword argument.

| Name              | Comment                                      |
| -----             | -------                                      |
| auto              | Automatic method selection                   |
| pkg-config        | Use Pkg-Config                               |
| cmake             | Look up as a CMake module                    |
| config-tool       | Use a custom dep tool such as `cups-config`  |
| system            | System provided (e.g. OpenGL)                |
| extraframework    | A macOS/iOS framework                        |


## Compiler and Linker selection variables

N.B. these settings are specified per machine, and so the environment
varibles actually come in pairs. See the [environment variables per
machine](#Environment-variables-per-machine) section for details.

| Language      | Compiler | Linker    | Note                                        |
|---------------|----------|-----------|---------------------------------------------|
| C             | CC       | CC_LD     |                                             |
| C++           | CXX      | CXX_LD    |                                             |
| D             | DC       | DC_LD     | Before 0.54 D_LD*                           |
| Fortran       | FC       | FC_LD     | Before 0.54 F_LD*                           |
| Objective-C   | OBJC     | OBJC_LD   |                                             |
| Objective-C++ | OBJCXX   | OBJCXX_LD | Before 0.54 OBJCPP_LD*                      |
| Rust          | RUSTC    | RUSTC_LD  | Before 0.54 RUST_LD*                        |
| Vala          | VALAC    |           | Use CC_LD. Vala transpiles to C             |
| C#            | CSC      | CSC       | The linker is the compiler                  |

*The old environment variales are still supported, but are deprecated
and will be removed in a future version of Meson.*

## Environment variables per machine

Since *0.54.0*, Following Autotool and other legacy build systems,
environment variables that affect machine-specific settings come in
pairs: for every bare environment variable `FOO`, there is a suffixed
`FOO_FOR_BUILD`, where `FOO` just affects the host machine
configuration, while `FOO_FOR_BUILD` just affects the build machine
configuration. For example:

 - `PKG_CONFIG_PATH_FOR_BUILD` controls the paths pkg-config will search for
   just `native: true` dependencies (build machine).

 - `PKG_CONFIG_PATH` controls the paths pkg-config will search for just
   `native: false` dependencies (host machine).

This mirrors the `build.` prefix used for (built-in) Meson options,
which has the same meaning.

This is useful for cross builds. In the native builds, build = host,
and the unsuffixed environment variables alone will suffice.

Prior to *0.54.0*, there was no `_FOR_BUILD`-suffixed variables, and
most environment variables only effected native machine
configurations, though this wasn't consistent (e.g. `PKG_CONFIG_PATH`
still affected cross builds).
