# Exifrecover

Dig EXIF and leftover metadata out of images after someone stripped them (or tried to).
Stdlib only, no pip stuff.

Works on live APP1, orphaned `Exif\0\0` residue past SOS, XMP, PNG text/eXIf, WebP EXIF.
Filename / brand-byte guesses are labeled as guesses so you dont mix them up with real tags.

## run

```bash
python exif_recovery_tool.py photo.jpg
python exif_recovery_tool.py photos/ -r -q
python exif_recovery_tool.py photo.jpg -j -o report.json
python exif_recovery_tool.py photo.jpg -c photo_original.jpg
python exif_recovery_tool.py -i
python -m unittest test_exif_recovery.py -v
```

If the EXIF was fully overwritten, this cant invent it back. It just surfaces what is still on disk.

## license

MIT
