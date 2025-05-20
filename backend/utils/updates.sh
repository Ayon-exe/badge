#!/bin/bash

# Check if the directory argument is provided
if [ -z "$1" ] || [ -z "$2" ] ; then
        echo "Usage: $0 <git-directory> <output-file-path>"
            exit 1
            fi

pwd
# Store the Git directory passed as an argument
GIT_DIR="$1"

# Check if the provided directory exists and is a valid Git repository
if [ ! -d "$GIT_DIR/.git" ]; then
        echo "Error: '$GIT_DIR' is not a valid Git repository."
            exit 1
            fi

# Navigate to the Git directory
cd "$GIT_DIR" || exit


git fetch
git diff --name-status main..origin/main | grep "CVE-" | sed "s/\(^.\)[^C]*\([^\.]*\).*/\1,\2/" > "/tmp/updates.csv"

cd -
echo "stat,CVE_ID" >$2
cat /tmp/updates.csv >> $2
