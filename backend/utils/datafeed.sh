#!/bin/bash

# Base URL for the file to download
BASE_URL="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"  # Replace with your actual URL
OUTPUT_DIR="${HOME}/nvd"  # Directory to save downloaded files

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Get the current year
CURRENT_YEAR=$(date +%Y)

# Loop through the years from 2002 to the current year
for YEAR in $(seq 2002 $CURRENT_YEAR); do
    # Construct the full URL
    FILE_URL="${BASE_URL}${YEAR}.json.gz"  # Adjust the URL format as needed
    OUTPUT_FILE="${OUTPUT_DIR}/nvd-datafeed-${YEAR}.json.gz"

    # Download the file
    echo "Downloading $FILE_URL..."
    curl -o "${OUTPUT_FILE}" "${FILE_URL}"

    # Check if the download was successful
    if [ $? -eq 0 ]; then
        echo "Downloaded $OUTPUT_FILE"
        
        # Unzip the file
        echo "Unzipping $OUTPUT_FILE..."
        gunzip "$OUTPUT_FILE"
        
        if [ $? -eq 0 ]; then
            echo "Unzipped ${OUTPUT_FILE%.gz}"
        else
            echo "Failed to unzip $OUTPUT_FILE"
        fi
    else
        echo "Failed to download $FILE_URL"
    fi
done

echo "All downloads and unzipping completed."

