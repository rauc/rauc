#!/bin/bash

set -e

# Based on systemd's travis-ci/tools/get-coverity.sh

# Environment check, note that secure tokens are not available for PR's not coming form the main repo
[ -z "$COVERITY_SCAN_TOKEN" ] && echo 'ERROR: COVERITY_SCAN_TOKEN must be set' && exit 1

# Use default values if not set
PLATFORM=$(uname)

TOOL_BASE=${TOOL_BASE:="/tmp/coverity-scan-analysis"}
TOOL_ARCHIVE=${TOOL_ARCHIVE:="/tmp/cov-analysis-${PLATFORM}.tgz"}

TOOL_URL="https://scan.coverity.com/download/${PLATFORM}"

# Get coverity tool
if [ ! -d $TOOL_BASE ]; then
  # Download Coverity Scan Analysis Tool
  if [ ! -e $TOOL_ARCHIVE ]; then
	  echo -e "\033[33;1mDownloading Coverity Scan Analysis Tool...\033[0m"
	  curl -s -o $TOOL_ARCHIVE $TOOL_URL -d "project=$COVERITY_SCAN_PROJECT_NAME&token=$COVERITY_SCAN_TOKEN"
  fi

  # Extract Coverity Scan Analysis Tool
  echo -e "\033[33;1mExtracting Coverity Scan Analysis Tool...\033[0m"
  mkdir -p $TOOL_BASE
  pushd $TOOL_BASE
  if ! tar xzf $TOOL_ARCHIVE; then
    rm -r $TOOL_BASE
    exit 1
  fi
  popd
fi

echo -e "\033[33;1mCoverity Scan Analysis Tool can be found at $TOOL_BASE ...\033[0m"
