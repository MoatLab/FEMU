# Tests in libspdm

Besides spdm_emu and UnitTest introduced in README, libspdm also supports other tests.

## Prerequisites

### Build Tool

1) [cmake](https://cmake.org/) for Windows and Linux.

## Run Test

### Test other ARCH (arm, aarch64, riscv32, riscv64, arc)

Linux support only.

1) Install compiler:

Refer to [build](https://github.com/DMTF/libspdm/blob/main/doc/build.md).

2) Install [qemu](https://qemu.org).

```
sudo apt-get install build-essential pkg-config zlib1g-dev libglib2.0-0 libglib2.0-dev  libsdl2-dev libpixman-1-dev libfdt-dev autoconf automake libtool librbd-dev libaio-dev flex bison -y
wget https://download.qemu.org/qemu-4.2.0.tar.xz
tar xvf qemu-4.2.0.tar.xz
cd qemu-4.2.0
./configure --prefix=/usr/local/qemu --audio-drv-list=
sudo make -j 8 && sudo make install
sudo ln -s /usr/local/qemu/bin/* /usr/local/bin
```

3) Run test

For arm (ARM_GCC): `qemu-arm -L /usr/arm-linux-gnueabi <TestBinary>`

For aarch64 (AARCH64_GCC): `qemu-aarch64 -L /usr/aarch64-linux-gnu <TestBinary>`

For riscv32 (RISCV GNU): `qemu-riscv32 -L /opt/riscv32/sysroot <TestBinary>`

For riscv64 (RISCV64 GCC): `qemu-riscv64 -L /usr/riscv64-linux-gnu <TestBinary>`

### Collect Code Coverage

1) Code Coverage in Windows with [DynamoRIO](https://dynamorio.org/)

   Download and install [DynamoRIO 8.0.0](https://github.com/DynamoRIO/dynamorio/wiki/Downloads).
   Then `set DRIO_PATH=<DynameRIO_PATH>`

   Install Perl [ActivePerl 5.26](https://www.activestate.com/products/perl/downloads/).

   Build cases.
   Goto libspdm/build. mkdir log and cd log.

   Run all tests and generate log file :
   `%DRIO_PATH%\<bin64|bin32>\drrun.exe -c %DRIO_PATH%\tools\<lib64|lib32>\release\drcov.dll -- <test_app>`

   Generate coverage data with filter :
   `%DRIO_PATH%\tools\<bin64|bin32>\drcov2lcov.exe -dir . -src_filter libspdm`

   Generate coverage report :
   `perl %DRIO_PATH%\tools\<bin64|bin32>\genhtml coverage.info`

   The final report is index.html.

2) Code Coverage with GCC and [lcov](https://github.com/linux-test-project/lcov/releases).

   Install lcov `sudo apt-get install lcov`.

   Build cases with `-DGCOV=ON`.

   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=GCC -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> -DGCOV=ON ..
   make copy_sample_key
   make
   ```

   Goto libspdm/build. mkdir log and cd log.

   Run all tests.

   Collect coverage data :
   `lcov --capture --directory <libspdm_root_dir> --output-file coverage.info`

   Collect coverage report :
   `genhtml coverage.info --output-directory .`

   The final report is index.html.

### Run fuzzing

1) Fuzzing in Linux with [AFL](https://lcamtuf.coredump.cx/afl/)

   Download and install [AFL](https://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz).
   Unzip and follow docs\QuickStartGuide.txt.
   Build it with `make`.
   Ensure AFL binary is in PATH environment variable.
   ```
   tar zxvf afl-latest.tgz
   cd afl-2.52b/
   make
   export AFL_PATH=<AFL_PATH>
   export PATH=$PATH:$AFL_PATH
   ```

   Then run commands as root (every time reboot the OS):
   ```
   sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
   cd /sys/devices/system/cpu/
   sudo bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
   ```

   Known issue: Above command cannot run in Windows Linux Subsystem.

   Build cases with AFL toolchain `-DTOOLCHAIN=AFL`. For example:
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=mbedtls ..
   make copy_sample_key
   make
   ```

   Run cases:
   ```
   mkdir testcase_dir
   mkdir /dev/shm/findings_dir
   cp <seed> testcase_dir
   afl-fuzz -i testcase_dir -o /dev/shm/findings_dir <test_app> @@
   ```
   Note: /dev/shm is tmpfs.

   Fuzzing Code Coverage in Linux with [AFL](https://lcamtuf.coredump.cx/afl/) and [lcov](https://github.com/linux-test-project/lcov/releases).
   Install lcov `sudo apt-get install lcov`.

   Build cases with AFL toolchain `-DTOOLCHAIN=AFL -DGCOV=ON`.
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..
   make copy_sample_key
   make
   ```
   You can launch the script `fuzzing_AFL.sh` to run a duration for each fuzzing test case. If you want to run a specific case modify the cmd tuple in the script.

   First install [screen](https://www.gnu.org/software/screen/) `sudo apt install screen`.

   The usage of the script `fuzzing_AFL.sh` is as following:
   ```
   libspdm/unit_test/fuzzing/fuzzing_AFL.sh <CRYPTO> <GCOV> <duration>
   <CRYPTO> means selected Crypto library: mbedtls or openssl
   <GCOV> means enable Code Coverage or not: ON or OFF
   <duration> means the duration of every program keep fuzzing: NUMBER seconds
   ```
   For example: build with `mbedtls`, enable Code Coverage and every test case run 60 seconds.
   ```
   libspdm/unit_test/fuzzing/fuzzing_AFL.sh mbedtls ON 60
   ```
   Fuzzing output path and code coverage output path of the script `fuzzing_AFL.sh`:
   ```
   #libspdm/unit_test/fuzzing/out_<CRYPTO>_<GitLogHash>/SummaryList.csv
   libspdm/unit_test/fuzzing/out_mbedtls_ac992fd/SummaryList.csv
   #libspdm/unit_test/fuzzing/out_<CRYPTO>_<GitLogHash>/coverage_log/index.html
   libspdm/unit_test/fuzzing/out_mbedtls_ac992fd/coverage_log/index.html
   ```

2) Fuzzing in Windows with [winafl](https://github.com/googleprojectzero/winafl)

   Clone [winafl](https://github.com/googleprojectzero/winafl).
   Download [DynamoRIO](https://dynamorio.org/).

   Set path `set AFL_PATH=<AFL_PATH>` and `set DRIO_PATH=<DynameRIO_PATH>`.

   NOTE: due to an issue https://github.com/googleprojectzero/winafl/issues/145 that causes compatibility issues in recent Windows versions, the author has disabled Drsyms in recent WinAFL builds. If you want to use the newest version you will need to rebuild winafl as detailed in the issue.

   Build winafl:
   ```
   mkdir [build32|build64]
   cd [build32|build64]
   cmake -G"Visual Studio 16 2019" -A [Win32|x64] .. -DDynamoRIO_DIR=%DRIO_PATH%\cmake -DUSE_DRSYMS=1
   cmake --build . --config Release
   ```

   NOTE: If you get errors where the linker couldn't find certain .lib files refer to https://github.com/googleprojectzero/winafl/issues/145 and delete the nonexistent files from "Additional Dependencies".

   Copy all binary under [build32|build64]/bin/Release to [bin32|bin64]. `robocopy /E /is /it [build32|build64]/bin/Release [bin32|bin64]`.

   Build cases with VS2019 toolchain. (non AFL toolchain in Windows).

   Run cases:
   ```
   cp <test_app> winafl\<bin64|bin32>
   cp <test_app_pdb> winafl\<bin64|bin32>
   cd winafl\<bin64|bin32>
   afl-fuzz.exe -i in -o out -D %DRIO_PATH%\<bin64|bin32> -t 20000 -- -coverage_module <test_app> -fuzz_iterations 1000 -target_module <test_app> -target_method main -nargs 2 -- <test_app> @@
   ```

3) Fuzzing in Linux with LLVM [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)

   First install LLVM with: `sudo apt install llvm`, and install CLANG with: `sudo apt install clang`.

   Ensure LLVM and CLANG binary in PATH environment variable.
   Use `llvm-ar --version` and `clang --version` to confirm the LLVM version(Take 'Ubuntu 20.04.2 LTS' as an example).
   ```
   ~$ llvm-ar --version
   LLVM (https://llvm.org/):
     LLVM version 10.0.0

     Optimized build.
     Default target: x86_64-pc-linux-gnu
     Host CPU: haswell

   ~$ clang --version
   clang version 10.0.0-4ubuntu1
   Target: x86_64-pc-linux-gnu
   Thread model: posix
   InstalledDir: /usr/bin
   ```
   Currently when building with LIBFUZZER toolchain, it will enable [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) by using the `-fsanitize=fuzzer,address` flag during the compilation and linking.
   You can check it in [CMakeLists.txt](https://github.com/DMTF/libspdm/blob/main/CMakeLists.txt).

   Build cases with LIBFUZZER toolchain `-DTOOLCHAIN=LIBFUZZER`(Note the unit test doesn't build when DTOOLCHAIN=LIBFUZZER).
   ```
   cd libspdm
   mkdir build_libfuzz
   cd build_libfuzz
   cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER -DTARGET=Release -DCRYPTO=mbedtls ..
   make copy_sample_key
   make
   ```
   If you want to collect the code coverage of fuzzing test build cases with `-DGCOV=ON`.
   ```
   cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..
   ```
   Run cases:
   ```
   mkdir NEW_CORPUS_DIR // Copy test seeds to the folder before run test
   <test_app> NEW_CORPUS_DIR -rss_limit_mb=0 -artifact_prefix=<OUTPUT_PATH>
   ```
   You can launch the script `fuzzing_LibFuzzer.sh` to run a duration for each fuzzing test case. If you want to run a specific case modify the cmd tuple in the script.

   First install [screen](https://www.gnu.org/software/screen/) `sudo apt install screen`.

   The usage of the script `fuzzing_LibFuzzer.sh` is as following:
   ```
   Usage: ./libspdm/unit_test/fuzzing/fuzzing_LibFuzzer.sh <CRYPTO> <GCOV> <duration>
   <CRYPTO> means selected Crypto library: mbedtls or openssl
   <GCOV> means enable Code Coverage or not: ON or OFF
   <duration> means the duration of every program keep fuzzing: NUMBER seconds
   ```
   For example: build with `mbedtls`, enable Code Coverage and every test case run 30 seconds.
   ```
   libspdm/unit_test/fuzzing/fuzzing_LibFuzzer.sh mbedtls ON 30
   ```
   Fuzzing output path of the script `fuzzing_LibFuzzer.sh`:
   ```
   #libspdm/unit_test/fuzzing/out_libfuzz_<CRYPTO>_<GitLogHash>/
   libspdm/unit_test/fuzzing/out_libfuzz_mbedtls_05e7bb4/
   ```
4) Fuzzing in Windows with LLVM [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)

   Note: IA32 build is not supported with LLVM in Windows.

   Ensure LLVM binary in in PATH environment variable.

   Build cases with LIBFUZZER toolchain `-DARCH=x64 -DTOOLCHAIN=LIBFUZZER`.

   Run cases:
   ```
   mkdir NEW_CORPUS_DIR // Copy test seeds to the folder before run test
   <test_app> NEW_CORPUS_DIR -rss_limit_mb=0 -artifact_prefix=<OUTPUT_PATH>
   ```
5) Fuzzing in Linux with [OSS-Fuzz](https://github.com/google/oss-fuzz) locally

   Take 'Ubuntu 20.04.2 LTS' as an example:
   a. Install [Docker](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)
   You can verify that Docker Engine is installed correctly by running the hello-world image.
   ```
   sudo docker run hello-world
   ```
   The above command downloads a test image and runs it in a container. When the container runs, it prints the following message and exits.
   ```
   Hello from Docker!
   This message shows that your installation appears to be working correctly.
   ```
   If you get the following `Timeout` error add and check your proxy configuration.
   ```
   Unable to find image 'hello-world:latest' locally
   docker: Error response from daemon: Get https://registry-1.docker.io/v2/: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers).
   See 'docker run --help'.
   ```
   Just add your Proxy details to the `/etc/systemd/system/docker.service.d/proxy.conf` (folder docker.service.d may not exists , so create the directory before), for example:
   ```
   [Service]
   Environment="HTTP_PROXY=http://proxy.example.com:80/"
   Environment="HTTPS_PROXY=https://proxy.example.com:80/"
   ```
   If you get the following `toomanyrequests` error, configure the registry-mirrors option for the Docker daemon.
   ```
   Unable to find image 'hello-world:latest' locally
   docker: Error response from daemon: toomanyrequests: You have reached your pull rate limit. You may increase the limit by authenticating and upgrading: https://www.docker.com/increase-rate-limit.
   ```
   Just add your mirror details to the `/etc/docker/daemon.json`, for example:
   ```
   {
      "registry-mirrors": ["https.your-mirror.example.com"]
   }
   ```
   If you want to run `docker` without `sudo`, you can create a docker group.
   To create the docker group, add your user and activate the changes to groups:
   ```
   sudo groupadd docker
   sudo usermod -aG docker $USER
   newgrp docker
   ```
   b. Setting up new project
   Clone [OSS-Fuzz](https://github.com/google/oss-fuzz)
   ```
   git clone https://github.com/google/oss-fuzz.git
   ```
   Generate templated versions of the configuration files(`project.yaml` `Dockerfile` `build.sh`) by running the following commands:
   ```
   $ cd oss-fuzz
   $ export PROJECT_NAME=libspdm
   $ export LANGUAGE=c
   $ python3 infra/helper.py generate $PROJECT_NAME --language=$LANGUAGE
   ```
   Once the template configuration files are created, replace them with our modified files to fit our project:
   ```
   cd ~/oss-fuzz
   cp ~/libspdm/unit_test/fuzzing/oss-fuzz_conf/* ~/oss-fuzz/projects/libspdm/
   ```
   c. Testing locally
   Build your docker image
   ```
   cd oss-fuzz
   sudo python3 infra/helper.py build_image $PROJECT_NAME
   ```
   If build docker image successfully, it will print the following messages at last.
   ```
   Successfully built 19b86a662c16
   Successfully tagged gcr.io/oss-fuzz/libspdm:latest
   ```
   If you get the following `connection timed out` error when building docker image, unable to apt-get update through dockerfile then enable proxy configuration in `Dockerfile`.
   ```
   Err:1 https://archive.ubuntu.com/ubuntu xenial InRelease
   Could not connect to archive.ubuntu.com:80 (91.189.88.162), connection timed out [IP: 91.189.88.162 80]
   ```
   Just set your Proxy Environment before `RUN apt-get` in `oss-fuzz/projects/libspdm/Dockerfile`, for example:
   ```
   FROM gcr.io/oss-fuzz-base/base-builder
   ENV http_proxy 'http://proxy.example.com:80/'
   ENV https_proxy 'https://proxy.example.com:80/'
   RUN apt-get update && apt-get install -y make autoconf automake libtool
   ```
   Build your fuzz targets, the built binaries appear in the `~/oss-fuzz/build/out/$PROJECT_NAME` directory on your machine (and `$OUT` in the container).
   ```
   sudo python3 infra/helper.py build_fuzzers --sanitizer coverage $PROJECT_NAME
   ```
   Run your fuzz target, to provide a corpus for `my_fuzzer`, put `my_fuzzer_seed_corpus.zip` file next to the fuzz target’s binary in `$OUT` during the build. Individual files in this archive will be used as starting inputs for mutations. for example:
   ```
   cd oss-fuzz
   sudo mkdir -p ./build/corpus/$PROJECT_NAME/test_spdm_responder_version
   zip -j ./build/out/libspdm/test_spdm_responder_version_seed_corpus.zip ~/libspdm/unit_test/fuzzing/seeds/test_spdm_responder_version/*
   sudo python3 infra/helper.py run_fuzzer --corpus-dir=./build/corpus/libspdm/test_spdm_responder_version $PROJECT_NAME test_spdm_responder_version
   ```
   Generate a code coverage report using the corpus you have locally, the code coverage report appear in the `~/oss-fuzz/build/out/$PROJECT_NAME/report/linux/index.html` directory on your machine.
   ```
   sudo python3 infra/helper.py coverage --no-corpus-download $PROJECT_NAME --fuzz-target=test_spdm_responder_version
   ```
   d. Automation script
   You can launch the script `oss_fuzz.sh` to run a duration for each fuzzing test case. If you want to run a specific case modify the cmd tuple in the script.

   First install [screen](https://www.gnu.org/software/screen/) `sudo apt install screen`.

   The usage of the script `oss_fuzz.sh` is as following:
   ```
   Usage: ./libspdm/unit_test/fuzzing/oss_fuzz.sh <CRYPTO> <GCOV> <duration>
   <CRYPTO> means selected Crypto library: mbedtls or openssl
   <GCOV> means enable Code Coverage or not: ON or OFF
   <duration> means the duration of every program keep fuzzing: NUMBER seconds
   ```
   For example: build with `mbedtls`, enable Code Coverage and every test case run 30 seconds.
   ```
   libspdm/unit_test/fuzzing/oss_fuzz.sh mbedtls ON 30
   ```
6) Fuzzing in Linux with [AFLTurbo](https://github.com/sleicasper/aflturbo)

   #### Install crypto libs then clone the repository and build the aflturbo code
   ```
   sudo apt-get install libssl-dev
   git clone https://github.com/sleicasper/aflturbo.git
   cd aflturbo/
   make
   cp afl-fuzz afl-turbo-fuzz
   export AFL_PATH=$(pwd)
   export PATH=$PATH:$AFL_PATH
   ```
   > Build it with make & ensure AFLTurbo binary is in PATH environment variable.

   Then run commands as root (every time reboot the OS):
   ```
   sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
   cd /sys/devices/system/cpu/
   sudo bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
   ```

   Known issue: Above command cannot run in Windows Linux Subsystem.

   Build cases with AFL toolchain `-DTOOLCHAIN=AFL`. For example:
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=mbedtls ..
   make copy_sample_key
   make
   ```

   Run cases:
   ```
   mkdir testcase_dir
   mkdir /dev/shm/findings_dir
   cp <seed> testcase_dir
   afl-turbo-fuzz -i testcase_dir -o /dev/shm/findings_dir <test_app> @@
   ```
   Note: /dev/shm is tmpfs.

   Fuzzing Code Coverage in Linux with [AFLTurbo](https://github.com/sleicasper/aflturbo) and [lcov](https://github.com/linux-test-project/lcov/releases).
   Install lcov `sudo apt-get install lcov`.

   Build cases with AFL toolchain `-DTOOLCHAIN=AFL -DGCOV=ON`.
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..
   make copy_sample_key
   make
   ```
   You can launch the script `fuzzing_AFLTurbo.sh` to run a duration for each fuzzing test case. If you want to run a specific case modify the cmd tuple in the script.

   First install [screen](https://www.gnu.org/software/screen/) `sudo apt install screen`.

   The usage of the script `fuzzing_AFLTurbo.sh` is as following:
   ```
   libspdm/unit_test/fuzzing/fuzzing_AFLTurbo.sh <CRYPTO> <GCOV> <duration>
   <CRYPTO> means selected Crypto library: mbedtls or openssl
   <GCOV> means enable Code Coverage or not: ON or OFF
   <duration> means the duration of every program keep fuzzing: NUMBER seconds
   ```
   For example: build with `mbedtls`, enable Code Coverage and every test case run 60 seconds.
   ```
   libspdm/unit_test/fuzzing/fuzzing_AFLTurbo.sh mbedtls ON 60
   ```
   Fuzzing output path and code coverage output path of the script `fuzzing_AFLTurbo.sh`:
   ```
   #libspdm/unit_test/fuzzing/out_<CRYPTO>_<GitLogHash>_<TIMESTAMP>/SummaryList.csv
   libspdm/unit_test/fuzzing/out_mbedtls_ac992fd_2022-06-23_08-45-48/SummaryList.csv
   #libspdm/unit_test/fuzzing/out_<CRYPTO>_<GitLogHash>_<TIMESTAMP>/coverage_log/index.html
   libspdm/unit_test/fuzzing/out_mbedtls_ac992f_2022-06-23_08-45-48/coverage_log/index.html
   ```
7) Fuzzing in Linux with [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

   #### Install crypto libs then clone the repository and build the AFLplusplus code
   ```
   sudo apt-get install libssl-dev
   git clone https://github.com/AFLplusplus/AFLplusplus.git
   cd AFLplusplus/
   make
   cp afl-fuzz afl-plusplus-fuzz
   export AFL_PATH=~/AFLplusplus/
   export PATH=$PATH:$AFL_PATH
   ```
   > Build it with make & ensure AFLplusplus binary is in PATH environment variable.

   Then run commands as root (every time reboot the OS):
   ```
   sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
   cd /sys/devices/system/cpu/
   sudo bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
   ```

   Known issue: Above command cannot run in Windows Linux Subsystem.

   Build cases with AFL toolchain `-DTOOLCHAIN=AFL`. For example:
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=mbedtls ..
   make copy_sample_key
   make
   ```

   Run cases:
   ```
   mkdir testcase_dir
   mkdir /dev/shm/findings_dir
   cp <seed> testcase_dir
   afl-plusplus-fuzz -i testcase_dir -o /dev/shm/findings_dir <test_app> @@
   ```
   Note: /dev/shm is tmpfs.

   Fuzzing Code Coverage in Linux with [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) and [lcov](https://github.com/linux-test-project/lcov/releases).
   Install lcov `sudo apt-get install lcov`.

   Build cases with AFL toolchain `-DTOOLCHAIN=AFL -DGCOV=ON`.
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..
   make copy_sample_key
   make
   ```
   You can launch the script `fuzzing_AFLplusplus.sh` to run a duration for each fuzzing test case. If you want to run a specific case modify the cmd tuple in the script.

   First install [screen](https://www.gnu.org/software/screen/) `sudo apt install screen`.

   The usage of the script `fuzzing_AFLplusplus.sh` is as following:
   ```
   libspdm/unit_test/fuzzing/fuzzing_AFLplusplus.sh <CRYPTO> <GCOV> <duration>
   <CRYPTO> means selected Crypto library: mbedtls or openssl
   <GCOV> means enable Code Coverage or not: ON or OFF
   <duration> means the duration of every program keep fuzzing: NUMBER seconds
   ```
   For example: build with `mbedtls`, enable Code Coverage and every test case run 60 seconds.
   ```
   libspdm/unit_test/fuzzing/fuzzing_AFLplusplus.sh mbedtls ON 60
   ```
   Fuzzing output path and code coverage output path of the script `fuzzing_AFLplusplus.sh`:
   ```
   #libspdm/unit_test/fuzzing/out_<CRYPTO>_<GitLogHash>_<TIMESTAMP>/SummaryList.csv
   libspdm/unit_test/fuzzing/out_mbedtls/SummaryList.csv
   #libspdm/unit_test/fuzzing/out_<CRYPTO>_<GitLogHash>_<TIMESTAMP>/coverage_log/index.html
   libspdm/unit_test/fuzzing/out_mbedtls/coverage_log/index.html
   ```
### Run Symbolic Execution

1) [KLEE](https://klee.github.io/)

   Download and install [KLEE with LLVM9](https://klee.github.io/build-llvm9/). Follow all 12 steps including optional ones.

   In step 3, constraint solver [STP](https://klee.github.io/build-stp) is recommended here.
   Set size of the stack to a very large value: `$ ulimit -s unlimited`.

   In step 8, below example can be used:
   ```
   $ cmake \
      -DENABLE_SOLVER_STP=ON \
      -DENABLE_POSIX_RUNTIME=ON \
      -DENABLE_KLEE_UCLIBC=ON \
      -DKLEE_UCLIBC_PATH=/home/tiano/env/klee-uclibc \
      -DGTEST_SRC_DIR=/home/tiano/env/googletest-release-1.7.0 \
      -DENABLE_UNIT_TESTS=ON \
      -DLLVM_CONFIG_BINARY=/usr/bin/llvm-config \
      -DLLVMCC=/usr/bin/clang \
      -DLLVMCXX=/usr/bin/clang++
      /home/tiano/env/klee
   ```

   Ensure KLEE binary is in PATH environment variable.
   ```
   export KLEE_SRC_PATH=<KLEE_SOURCE_DIR>
   export KLEE_BIN_PATH=<KLEE_BUILD_DIR>
   export PATH=$KLEE_BIN_PATH:$PATH
   ```

   Build cases in Linux with KLEE toolchain `-DTOOLCHAIN=KLEE`. (KLEE does not support Windows)

   Use [KLEE](https://klee.github.io/tutorials) to [generate ktest](https://klee.github.io/tutorials/testing-coreutils/):
   `klee --only-output-states-covering-new <test_app>`

   Transfer .ktest to seed file, which can be used for AFL-fuzzer.
   `python unit_test/fuzzing/Tools/TransferKtestToSeed.py <Arguments>`

   Arguments:
   <KtestFile>                          the path of .ktest file.
   <KtestFile1> <KtestFile2> ...        the paths of .ktest files.
   <KtestFolder>                        the path of folder contains .ktest file.
   <KtestFolder1> <KtestFolder2> ...    the paths of folders contain .ktest file.

### Run Model Checker

1) [CBMC](https://www.cprover.org/cbmc/)

   Install [CBMC tool](https://www.cprover.org/cprover-manual/).
   For Windows, unzip [cbmc-5-10-win](https://www.cprover.org/cbmc/download/cbmc-5-10-win.zip).
   For Linux, unzip [cbmc-5-11-linux-64](https://www.cprover.org/cbmc/download/cbmc-5-11-linux-64.tgz).
   Ensure CBMC executable directory is in PATH environment variable.

   Build cases with CBMC toolchain:

   For Windows, open Visual Studio 2019 command prompt at libspdm dir and build it with CBMC toolchain `-DARCH=ia32 -DTOOLCHAIN=LIBFUZZER`. (Use x86 command prompt for ARCH=ia32 only)

   For Linux, open command prompt at libspdm dir and build it with CBMC toolchain `-DARCH=x64 -DTOOLCHAIN=CBMC`. (ARCH=x64 only)

   The output binary is created by the [goto-cc](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/goto-cc.md).

   For more infomration on how to use [CBMC](https://github.com/diffblue/cbmc/), refer to [CBMC Manual](https://github.com/diffblue/cbmc/tree/develop/doc/cprover-manual), such as [properties](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/properties.md), [modeling-nondeterminism](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/modeling-nondeterminism.md), [api](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/api.md). Example below:

   Using [goto-instrument](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/goto-instrument.md) static analyzer operates on goto-binaries and generate a modified binary:
   `goto-instrument SpdmRequester.exe SpdmRequester.gb <instrumentation-options>`

   Using [CBMC](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/cbmc-tutorial.md) on the modified binary:
   `cbmc SpdmRequester.gb --show-properties`

### Run Static Analysis

1) Use [Klocwork](https://www.perforce.com/products/klocwork) in Windows as an example.

   Install Klocwork and set environment.
   ```
   set KW_HOME=C:\Klocwork
   set KW_ROOT=%KW_HOME%\<version>\projects_root
   set KW_TABLE_ROOT=%KW_HOME%\Tables
   set KW_CONFIG=%KW_ROOT%\projects\workspace\rules\analysis_profile.pconf
   set KW_PROJECT_NAME=libspdm
   ```

   Run CMAKE to generate makefile.

   Build libspdm with Klocwork :
   ```
   kwinject --output %KW_ROOT%\%KW_PROJECT_NAME%.out nmake
   ```

   Collect analysis data :
   ```
   kwservice start
   kwadmin create-project %KW_PROJECT_NAME%
   kwadmin import-config %KW_PROJECT_NAME% %KW_CONFIG%
   kwbuildproject --project %KW_PROJECT_NAME% --tables-directory %KW_TABLE_ROOT%\%KW_PROJECT_NAME% %KW_ROOT%\%KW_PROJECT_NAME%.out --force
   kwadmin load %KW_PROJECT_NAME% %KW_TABLE_ROOT%\%KW_PROJECT_NAME%
   ```

   View report at http://localhost:8080/.

2) Use [Coverity](https://scan.coverity.com/) in Windows as an example.

   Install Coverity and set environment.
   For x64 builds, use a `x64 Native Tools Command Prompt for Visual Studio...` command prompt.
   ```
   set PATH=%PATH%;C:\Program Files\Coverity\Coverity Static Analysis\bin\
   cov-configure --msvc --config C:\libspdm\CoverityConfig\coverity-config.xml
   ```
   Run CMAKE to generate makefile and build libspdm with Coverity :
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=mbedtls ..
   nmake copy_sample_key
   cov-build --config C:\libspdm\CoverityConfig\coverity-config.xml --dir C:\libspdm\coverity-output nmake
   ```
   Execute `cov-analyze` command and generate the report :
   ```
   cov-analyze --dir C:\libspdm\coverity-output --all --rule --enable-constraint-fpp --enable-fnptr --enable-virtual --enable FORWARD_NULL
   cov-format-errors --dir C:\libspdm\coverity-output --html-output html-report
   ```
   Retrieve the report from the folder `html-report`.

3) Use [CodeQL](https://github.com/github/codeql) in CI.

   [Set up and check result](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/setting-up-code-scanning-for-a-repository#setting-up-code-scanning-using-actions)

   [Manageing code scanning alerts for your repository](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#viewing-the-alerts-for-a-repository)

### Collect Stack Usage

1) Stack usage with GCC -fstack-usage flag

   Build with -DSTACK_USAGE=ON
   ```
   cd libspdm
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=GCC -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> -DSTACK_USAGE=ON ..
   make copy_sample_key
   make
   ```
2) Check the stack usage of individual functions in the .su file corresponding to every .c file

   For example:
   `<path_to_libspdm>/build/library/spdm_requester_lib/CMakeFiles/spdm_requester_lib.dir/libspdm_req_send_receive.c.su`
   ```
   <path_to_libspdm>/library/spdm_requester_lib/libspdm_req_send_receive.c:25:15:libspdm_send_request     4736    static
   <path_to_libspdm>/library/spdm_requester_lib/libspdm_req_send_receive.c:76:15:libspdm_receive_response 4752    static
   <path_to_libspdm>/library/spdm_requester_lib/libspdm_req_send_receive.c:167:15:spdm_send_spdm_request  64      static
   <path_to_libspdm>/library/spdm_requester_lib/libspdm_req_send_receive.c:212:15:spdm_receive_spdm_response      64      static
   ```
3) Useful tools

   avstack.pl, daniel beer, https://dlbeer.co.nz/oss/avstack.html

### Measure spdm_context Size

libspdm requires an spdm_context as input parameter. The consumer of libspdm needs to allocate the spdm_context with size returned from libspdm_get_context_size().

Usually the spdm_context is allocated in the heap. The size of spdm_context can be shown in the [spdm emulator](https://github.com/DMTF/spdm-emu) with `printf("context_size - 0x%x\n", (uint32_t)libspdm_get_context_size());`.

### Measure libspdm Size

The size of libspdm can be evaluated by [test_size_of_spdm_requester](https://github.com/DMTF/libspdm/tree/main/unit_test/test_size/test_size_of_spdm_requester) and [test_size_of_spdm_responder](https://github.com/DMTF/libspdm/tree/main/unit_test/test_size/test_size_of_spdm_responder).

Use a release build with `-DTARGET=Release`.

You can find the a raw image at `bin/test_size_of_spdm_requester` and `bin/test_size_of_spdm_responder`.
Those images includes all SPDM features. They do not include cryptography library or standard library.
Those images are used for size evaluation. They cannot run in OS environment.

The SPDM features can be controlled by [spdm_lib_config.h](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h).
