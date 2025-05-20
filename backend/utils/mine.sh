#!/bin/bash

CVELISTV5="${HOME}/cvelistV5/"

# Check if the directory argument is provided
if [ -z "$1" ]; then
    echo "missing the cvelistV5/ directory"
    echo "switching to pre-defined path"
    echo "PATH: $CVELISTV5"
    #exit 1
fi

#assigning the argument value to CVELISTV5 variable 
if [ -n "$1" ]; then
    echo "Argument is provided."
    CVELISTV5=$1
fi


# Loop through the years from 1999 to the current year
for year in $(seq 1999 $(date +%Y)); do
    cves_file="/tmp/cves/cve-$year"
    tmp_file="/tmp/cc"
    tmp_mine_file="/tmp/mine.json"

    mkdir -p "/tmp/cves" && touch $cves_file

    find "${CVELISTV5}cves/${year}" -type f | 
      grep -o "CVE-[^-]*-[^\.]*" >"$cves_file"

    # Create a file with all the CVE IDs for the current year
    find "$CVELISTV5" -type f | grep -o "CVE-$year-[^\.]*" > "$cves_file"
    echo "File created successfully in $(pwd)/$cves_file which contains..."
    head -3 "$cves_file"

    # Load the data into a buffer for the current year
    sed "s/\(CVE-[^-]*-\(.*$\)\)/\2 \1/" "$cves_file" | sort -n | cut -d " " -f 2 > "$tmp_file"
    echo "Sorted and loaded successfully in CC which contains..."
    head -3 "$tmp_file"

    # Initiating variables and files
    remain=$(wc -l < "$tmp_file")
    total=$remain
    echo "[]" > "$tmp_mine_file"

    # Batch process
    while [ $remain -gt 0 ]; do
        ids=""
        for i in $(head -90 "$tmp_file"); do
            # Logic to build the IDs string
            if [ -z "$ids" ]; then
                ids="$i"
            else
                ids="$ids,$i"
            fi
            sed -i '1,1d' "$tmp_file"
        done

        # CVE action
        cvemap -json -id "$ids" >/tmp/instant.json 2>/dev/null
        jq -s '[.[][]]' "$tmp_mine_file" /tmp/instant.json > tmp
        mv tmp "$tmp_mine_file"

        # Stat info
        first=$(echo "$ids" | awk -F ',' '{print $CVELISTV5}')
        last=$(echo "$ids" | awk -F "," '{print $NF}' | cut -d "-" -f 3)
        ending=$(tail -1 "$tmp_file" | cut -d "-" -f 3)
        count=$(grep cve_id $tmp_mine_file | wc -l)
        echo -ne "$first-$last / $ending  [$count/$total]\r"
        remain=$((remain - 90))
        sleep 5
    done

    mkdir -p "mines/"
    cp "$tmp_mine_file" "mines/$year.json"
    echo -e "\nFile saved in $(pwd)/mines/$year.json"
done

