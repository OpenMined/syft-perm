#!/bin/bash

# Convert video for web usage
echo "Converting video to web-friendly formats..."

# Check if ffmpeg is installed
if ! command -v ffmpeg &> /dev/null; then
    echo "ffmpeg is not installed. Please install it first:"
    echo "brew install ffmpeg"
    exit 1
fi

# Input and output paths
INPUT_VIDEO="/Users/atrask/Desktop/file_viewer.mov"
OUTPUT_DIR="/Users/atrask/Desktop/Laboratory/syft-perm/docs/images"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Convert to MP4 (H.264) - best compatibility
echo "Converting to MP4..."
ffmpeg -i "$INPUT_VIDEO" \
    -c:v libx264 \
    -preset slow \
    -crf 22 \
    -pix_fmt yuv420p \
    -an \
    "$OUTPUT_DIR/syft-perm-widgets-demo.mp4" -y

# Convert to WebM (VP9) - modern browsers, better compression
echo "Converting to WebM..."
ffmpeg -i "$INPUT_VIDEO" \
    -c:v libvpx-vp9 \
    -crf 30 \
    -b:v 0 \
    -an \
    "$OUTPUT_DIR/syft-perm-widgets-demo.webm" -y

# Create a poster frame (first frame as image)
echo "Creating poster frame..."
ffmpeg -i "$INPUT_VIDEO" \
    -vframes 1 \
    -f image2 \
    "$OUTPUT_DIR/syft-perm-widgets-demo-poster.jpg" -y

# Optional: Create animated GIF (lower quality but universal support)
echo "Creating animated GIF (this may take a while)..."
ffmpeg -i "$INPUT_VIDEO" \
    -vf "fps=10,scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
    -loop 0 \
    "$OUTPUT_DIR/syft-perm-widgets-demo.gif" -y

echo "Conversion complete!"
echo "Files created:"
echo "  - $OUTPUT_DIR/syft-perm-widgets-demo.mp4"
echo "  - $OUTPUT_DIR/syft-perm-widgets-demo.webm"
echo "  - $OUTPUT_DIR/syft-perm-widgets-demo-poster.jpg"
echo "  - $OUTPUT_DIR/syft-perm-widgets-demo.gif"