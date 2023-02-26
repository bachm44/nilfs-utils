#!/bin/bash

set -euo pipefail

make dist-bzip2
COMMIT_ID=$(git rev-list --max-count=1 HEAD)
RELEASE_NAME=2.3.0-dev-$COMMIT_ID
ARTIFACT_FILENAME=nilfs-utils-$RELEASE_NAME.tar.bz2

mv nilfs-utils-2.3.0-dev.tar.bz2 $ARTIFACT_FILENAME
RELEASE_SHA512=$(sha512sum $ARTIFACT_FILENAME)

gh release create $RELEASE_NAME $ARTIFACT_FILENAME \
	--generate-notes \
	--notes-file -<<EOF
NILFS_UTILS_VERSION = $RELEASE_NAME
sha512  $RELEASE_SHA512
EOF
