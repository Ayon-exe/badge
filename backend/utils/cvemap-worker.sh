#!/bin/bash

# Check if input file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <cves_file>"
    exit 1
fi

cves_file="$1"
dir_path="${cves_file%/*}"
changes_file="$dir_path/changes"
output_file="$dir_path/output.json"
tmp_file="$dir_path/cc"
mine_file="$dir_path/mine.json"
instant_file="$dir_path/instant.json"

# Handling Changes and adding to buffer (in this case input file)
grep -o "CVE-....-[^\.]*" $changes_file >>$cves_file

# Create a file with all the CVE IDs for a year
echo "$(head -3 "$cves_file" | xargs)"

# Load the data into a buffer file for a given year
sed "s/\(CVE-....-\(.*\)\)/\2 \1/" "$cves_file" | sort -n | cut -d " " -f 2 >"$tmp_file"
echo "$(head -3 "$tmp_file" | xargs)"

# Initiating variables and files
remain=$(wc -l < "$tmp_file")
total=$remain
echo "$total"

echo "[]" >"$mine_file"

# Batch process
while [ $remain -gt 0 ]; do
    ids=""
    for i in $(head -90 "$tmp_file"); do
        if [ -z "$ids" ]; then
            ids="$i"
        else
            ids="$ids,$i"
        fi
    sed -i '1d' "$tmp_file"  # Remove the first line from the temporary file
    done

    echo "Processing CVE IDs: $ids"

# Check if ids is empty
    if [ -z "$ids" ]; then
    echo "No CVE IDs to process. Exiting."
    exit 1
    fi

# Execute cvemap and handle timeout
    ./utils/cvemap -json -id $ids > "$instant_file" 2>"$dir_path/err" &
    cvemap_pid=$!  # Capture the process ID
    echo $cvemap_pid

# Set a timeout
    ( sleep 20 && kill -HUP "$cvemap_pid" ) &
    timeout_pid=$!  # Capture the timeout process ID

# Wait for cvemap to finish
    wait "$cvemap_pid"
    cvemap_status=$?  # Capture the exit status of cvemap

# Kill the timeout if cvemap finished in time
    kill -9 "$timeout_pid" 2>/dev/null

# Check if cvemap was successful
    if [ $cvemap_status -ne 0 ]; then
        echo "Error executing cvemap for IDs: $ids. Exiting."
        exit 1
    fi

# Combine results with existing data
    jq -s '[.[][]]' "$mine_file" "$instant_file" > "$dir_path/interim"
    mv "$dir_path/interim" "$mine_file"

    remain=$((remain - 90))
    sleep 3
done

# Get the current date and time in the desired format
cp "$mine_file" "$output_file"

#update the buffer ( in this case input file from earlier)
grep -v -f <(jq '.[] | .cve_id ' $output_file | sed 's/"//g') $1 >$tmp_file
#jq '.[] | select( .is_poc == true ) | .cve_id' $output_file | sed 's/"//g' >>$tmp_file
mv $tmp_file $1

echo -e "\nFile saved in $output_file"
exit 0

