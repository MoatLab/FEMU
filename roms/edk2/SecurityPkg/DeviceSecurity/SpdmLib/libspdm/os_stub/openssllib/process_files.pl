#!/usr/bin/perl -w
#
# This script runs the OpenSSL Configure script, then processes the
# resulting file list into our local openssllib[Crypto].inf and also
# takes copies of opensslconf.h and dso_conf.h.
#
# This only needs to be done once by a developer when updating to a
# new version of OpenSSL (or changing options, etc.). Normal users
# do not need to do this, since the results are stored in the EDK2
# git repository for them.
#
use strict;
use Cwd;
use File::Copy;

#
# Find the openssl directory name for use lib. We have to do this
# inside of BEGIN. The variables we create here, however, don't seem
# to be available to the main script, so we have to repeat the
# exercise.
#
my $OPENSSL_PATH;

BEGIN {
    # We need to run Configure before we can include its result...
    my $basedir = getcwd();

    $OPENSSL_PATH = "$basedir/openssl";

    chdir($OPENSSL_PATH) ||
        die "Cannot change to OpenSSL directory \"" . $OPENSSL_PATH . "\"";

    # Configure UEFI
    system(
        "./Configure",
        "UEFI",
        "no-afalgeng",
        "no-asm",
        "no-async",
        "no-autoalginit",
        "no-autoerrinit",
        "no-autoload-config",
        "no-bf",
        "no-blake2",
        "no-camellia",
        "no-capieng",
        "no-cast",
        "no-chacha",
        "no-cms",
        "no-ct",
        "no-deprecated",
        "no-dgram",
        "no-dsa",
        "no-dynamic-engine",
        "no-ec",
        "no-ec2m",
        "no-engine",
        "no-err",
        "no-filenames",
        "no-gost",
        "no-hw",
        "no-idea",
        "no-mdc2",
        "no-pic",
        "no-ocb",
        "no-poly1305",
        "no-posix-io",
        "no-rc2",
        "no-rfc3779",
        "no-rmd160",
        "no-scrypt",
        "no-seed",
        "no-sock",
        "no-srp",
        "no-ssl",
        "no-stdio",
        "no-threads",
        "no-ts",
        "no-ui",
        "no-whirlpool",
        # OpenSSL1_1_1b doesn't support default rand-seed-os for UEFI
        # UEFI only support --with-rand-seed=none
        "--with-rand-seed=none"
        ) == 0 ||
            die "OpenSSL Configure failed!\n";

    # Generate opensslconf.h per config data
    system(
        "perl -I. -Mconfigdata util/dofile.pl " .
        "include/openssl/opensslconf.h.in " .
        "> include/openssl/opensslconf.h"
        ) == 0 ||
            die "Failed to generate opensslconf.h!\n";

    # Generate dso_conf.h per config data
    system(
        "perl -I. -Mconfigdata util/dofile.pl " .
        "include/crypto/dso_conf.h.in " .
        "> include/crypto/dso_conf.h"
        ) == 0 ||
            die "Failed to generate dso_conf.h!\n";

    chdir($basedir) ||
        die "Cannot change to base directory \"" . $basedir . "\"";
}

#
# Copy opensslconf.h and dso_conf.h generated from OpenSSL Configuration
#
print "\n--> Duplicating opensslconf.h into include/openssl ... ";
copy($OPENSSL_PATH . "/include/openssl/opensslconf.h",
     $OPENSSL_PATH . "/../include/openssl/") ||
   die "Cannot copy opensslconf.h!";
print "Done!";
print "\n--> Duplicating dso_conf.h into include/crypto ... ";
copy($OPENSSL_PATH . "/include/crypto/dso_conf.h",
     $OPENSSL_PATH . "/../include/crypto/") ||
   die "Cannot copy dso_conf.h!";
print "Done!\n";

print "\nProcessing Files Done!\n";

exit(0);

