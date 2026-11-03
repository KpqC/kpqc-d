#!/bin/sh

set -eu

kpqc_package_dir=$1
kpqc_configuration=${2:-library}

case "$kpqc_configuration" in
    library)
        kpqc_build_dir="$kpqc_package_dir/.dub/native"
        kpqc_test_entropy=OFF
        ;;
    kat)
        kpqc_build_dir="$kpqc_package_dir/.dub/native-kat"
        kpqc_test_entropy=ON
        ;;
    *)
        echo "unknown native configuration: $kpqc_configuration" >&2
        exit 2
        ;;
esac

cmake -S "$kpqc_package_dir" -B "$kpqc_build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DKPQC_TEST_ENTROPY="$kpqc_test_entropy"
cmake --build "$kpqc_build_dir" --config Release
