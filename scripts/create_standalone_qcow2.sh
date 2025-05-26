#!/bin/bash

base_img_path="$1"
snapshot_img_path="$2"
output_dir="${3:-$(dirname "$snapshot_img_path")}"

if [ -z "$base_img_path" ] || [ -z "$snapshot_img_path" ]; then
    echo "Usage: $0 <base_image> <snapshot_name> [<output_directory>]"
    exit 1
fi

# Check if the base image exists
if [ ! -f "$base_img_path" ]; then
    echo "Base image '$base_img_path' does not exist."
    exit 1
fi


# Check if the snapshot image exists
if [ ! -f "$snapshot_img_path" ]; then
    echo "Snapshot image '$snapshot_img_path' does not exist."
    exit 1
fi
standalone_img="$output_dir/$(basename "${snapshot_img_path%.qcow2}_standalone.qcow2")"

if [ -f "$standalone_img" ]; then
    echo "Standalone image '$standalone_img' already exists."
    exit 1
fi

qemu-img convert -O qcow2 "$snapshot_img_path" "$standalone_img" > /dev/null

echo "Standalone qcow2 image created successfully: $standalone_img"
