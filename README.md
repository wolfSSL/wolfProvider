# Yocto WIC Image Downloads

This branch contains compressed Yocto disk images (.wic.xz files) for testing purposes.

## File Structure

- `fips/standalone/` - FIPS standalone images
- `fips/replace-default/` - FIPS replace-default images  
- `nonfips/standalone/` - Non-FIPS standalone images
- `nonfips/replace-default/` - Non-FIPS replace-default images

## Downloading Files

### Option 1: Complete Files (< 100MB)

If the file is under 100MB, it will be stored as a single `.wic.xz` file:

```bash
# Download and decompress
xz -d core-image-minimal.wic.xz
```

### Option 2: Split Files (> 100MB)

If the file exceeds 100MB, it will be split into chunks (`.wic.xz.part-000`, `.wic.xz.part-001`, etc.) to comply with GitHub's 100MB file size limit.

**To reassemble and decompress:**

```bash
# Method 1: Use the provided reassembly script
bash core-image-minimal.wic.xz.reassemble.sh
xz -d core-image-minimal.wic.xz

# Method 2: Manual reassembly
cat core-image-minimal.wic.xz.part-* > core-image-minimal.wic.xz
xz -d core-image-minimal.wic.xz
```

**Important:** Make sure all part files are downloaded before reassembling. The parts must be combined in order.

## Verification

After decompression, verify the file:

```bash
file core-image-minimal.wic
# Should show: core-image-minimal.wic: DOS/MBR boot sector
```

## Usage

These images can be written to SD cards or used with QEMU:

```bash
# Write to SD card (replace /dev/sdX with your device)
sudo dd if=core-image-minimal.wic of=/dev/sdX bs=4M status=progress

# Or use with QEMU
qemu-system-x86_64 -drive file=core-image-minimal.wic,format=raw
```

## Notes

- Files are compressed using xz with extreme mode (-9e) for maximum compression
- Files over 100MB are automatically split into 90MB chunks
- All files are for testing purposes only, not for production use
