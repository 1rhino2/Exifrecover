# Rhino EXIF Recovery Tool
# by 1rhino2 (github.com/1rhino2)
# Recovers lost or wiped EXIF and plausible metadata from images, using only built-in Python
#
# Usage: python exif_recovery_tool.py
#
# This tool is user-friendly, robust, and ready for GitHub release.

import os, sys, glob, datetime, struct, hashlib, json, subprocess, urllib.request, re, webbrowser
from collections import Counter

CREDITS = "Tool by 1rhino2 (github.com/1rhino2)"

def list_images_in_dir(directory):
    exts = ('.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp', '.gif', '.webp')
    files = []
    for ext in exts:
        files.extend(glob.glob(os.path.join(directory, ext)))
    return files

def show_image_ascii(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(1024)
        print(f"[Preview: {os.path.basename(filepath)}] (first 1KB as hex)")
        print(' '.join(f'{b:02x}' for b in data[:64]))
    except Exception:
        print("[!] Could not preview image.")

def show_image(filepath):
    try:
        if sys.platform.startswith('win'):
            os.startfile(filepath)
        elif sys.platform.startswith('darwin'):
            subprocess.run(['open', filepath])
        else:
            subprocess.run(['xdg-open', filepath])
    except Exception as e:
        print(f"[!] Could not open image: {e}")

def gps_to_decimal(gps, ref):
    if not gps or not ref:
        return None
    d, m, s = gps
    sign = -1 if ref in ['S', 'W'] else 1
    return sign * (d + m/60 + s/3600)

def reverse_geocode(lat, lon):
    try:
        url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}&zoom=10&addressdetails=1'
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get('display_name')
    except Exception:
        return None

def recover_exif_builtin(filepath):
    exif = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        exif_start = data.find(b'Exif\x00\x00')
        if exif_start != -1:
            try:
                tiff_start = exif_start + 6
                endian = data[tiff_start:tiff_start+2]
                byte_order = '<' if endian == b'II' else '>' if endian == b'MM' else '<'
                ifd_offset = int.from_bytes(data[tiff_start+4:tiff_start+8], byte_order)
                ifd_start = tiff_start + ifd_offset
                num_entries = int.from_bytes(data[ifd_start:ifd_start+2], byte_order)
                for i in range(num_entries):
                    entry_offset = ifd_start + 2 + i*12
                    tag = int.from_bytes(data[entry_offset:entry_offset+2], byte_order)
                    dtype = int.from_bytes(data[entry_offset+2:entry_offset+4], byte_order)
                    count = int.from_bytes(data[entry_offset+4:entry_offset+8], byte_order)
                    value_offset = data[entry_offset+8:entry_offset+12]
                    if tag in [0x010F, 0x0110, 0x0131, 0x0132, 0x8298]:
                        val_offset = int.from_bytes(value_offset, byte_order)
                        val_start = tiff_start + val_offset
                        val = b''
                        for j in range(64):
                            if data[val_start+j] == 0:
                                break
                            val += bytes([data[val_start+j]])
                        try:
                            if tag == 0x010F:
                                exif['Make'] = val.decode(errors='ignore')
                            if tag == 0x0110:
                                exif['Model'] = val.decode(errors='ignore')
                            if tag == 0x0131:
                                exif['Software'] = val.decode(errors='ignore')
                            if tag == 0x0132:
                                exif['DateTime'] = val.decode(errors='ignore')
                            if tag == 0x8298:
                                exif['Copyright'] = val.decode(errors='ignore')
                        except Exception as e:
                            exif['StringTagError'] = str(e)
                    if tag == 0x8769:
                        try:
                            exif_ifd_offset = int.from_bytes(value_offset, byte_order)
                            exif_ifd_start = tiff_start + exif_ifd_offset
                            exif_entries = int.from_bytes(data[exif_ifd_start:exif_ifd_start+2], byte_order)
                            for j in range(exif_entries):
                                e_offset = exif_ifd_start + 2 + j*12
                                e_tag = int.from_bytes(data[e_offset:e_offset+2], byte_order)
                                e_dtype = int.from_bytes(data[e_offset+2:e_offset+4], byte_order)
                                e_count = int.from_bytes(data[e_offset+4:e_offset+8], byte_order)
                                e_value = data[e_offset+8:e_offset+12]
                                if e_tag == 0x9003:
                                    v_offset = int.from_bytes(e_value, byte_order)
                                    v_start = tiff_start + v_offset
                                    v = b''
                                    for k in range(32):
                                        if data[v_start+k] == 0:
                                            break
                                        v += bytes([data[v_start+k]])
                                    exif['DateTimeOriginal'] = v.decode(errors='ignore')
                                if e_tag == 0x829A:
                                    v = int.from_bytes(e_value, byte_order)
                                    exif['ExposureTime'] = v
                                if e_tag == 0x829D:
                                    v = int.from_bytes(e_value, byte_order)
                                    exif['FNumber'] = v
                                if e_tag == 0x8827:
                                    v = int.from_bytes(e_value, byte_order)
                                    exif['ISO'] = v
                        except Exception as e:
                            exif['ExifIFDError'] = str(e)
                    if tag == 0x8825:
                        try:
                            gps_ifd_offset = int.from_bytes(value_offset, byte_order)
                            gps_ifd_start = tiff_start + gps_ifd_offset
                            gps_entries = int.from_bytes(data[gps_ifd_start:gps_ifd_start+2], byte_order)
                            for j in range(gps_entries):
                                g_offset = gps_ifd_start + 2 + j*12
                                g_tag = int.from_bytes(data[g_offset:g_offset+2], byte_order)
                                g_dtype = int.from_bytes(data[g_offset+2:g_offset+4], byte_order)
                                g_count = int.from_bytes(data[g_offset+4:g_offset+8], byte_order)
                                g_value = data[g_offset+8:g_offset+12]
                                if g_tag == 0x0002:
                                    v_offset = int.from_bytes(g_value, byte_order)
                                    v_start = tiff_start + v_offset
                                    lat = []
                                    for k in range(3):
                                        num = int.from_bytes(data[v_start+k*8:v_start+k*8+4], byte_order)
                                        den = int.from_bytes(data[v_start+k*8+4:v_start+k*8+8], byte_order)
                                        lat.append(num/den if den else 0)
                                    exif['GPSLatitude'] = lat
                                if g_tag == 0x0004:
                                    v_offset = int.from_bytes(g_value, byte_order)
                                    v_start = tiff_start + v_offset
                                    lon = []
                                    for k in range(3):
                                        num = int.from_bytes(data[v_start+k*8:v_start+k*8+4], byte_order)
                                        den = int.from_bytes(data[v_start+k*8+4:v_start+k*8+8], byte_order)
                                        lon.append(num/den if den else 0)
                                    exif['GPSLongitude'] = lon
                                if g_tag == 0x0001:
                                    v_offset = int.from_bytes(g_value, byte_order)
                                    v_start = tiff_start + v_offset
                                    ref = b''
                                    for k in range(2):
                                        if data[v_start+k] == 0:
                                            break
                                        ref += bytes([data[v_start+k]])
                                    exif['GPSLatitudeRef'] = ref.decode(errors='ignore')
                                if g_tag == 0x0003:
                                    v_offset = int.from_bytes(g_value, byte_order)
                                    v_start = tiff_start + v_offset
                                    ref = b''
                                    for k in range(2):
                                        if data[v_start+k] == 0:
                                            break
                                        ref += bytes([data[v_start+k]])
                                    exif['GPSLongitudeRef'] = ref.decode(errors='ignore')
                        except Exception as e:
                            exif['GPSIFDError'] = str(e)
            except Exception as e:
                exif['EXIFParseError'] = str(e)
        try:
            icc_idx = data.find(b'ICC_PROFILE')
            exif['ICCProfilePresent'] = icc_idx != -1
            jfif_idx = data.find(b'JFIF')
            exif['JFIFPresent'] = jfif_idx != -1
            for i in range(16):
                marker = bytes([0xFF, 0xE0 + i])
                if marker in data:
                    exif[f'APP{i}Present'] = True
        except Exception as e:
            exif['MarkerScanError'] = str(e)
        stat = os.stat(filepath)
        exif['FileCreateTime'] = datetime.datetime.fromtimestamp(stat.st_ctime).isoformat()
        exif['FileModifyTime'] = datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
        h = hashlib.sha256(); h.update(data)
        exif['SHA256'] = h.hexdigest()
        idx = data.find(b'\xff\xfe')
        exif['JPEGComment'] = None
        if idx != -1:
            try:
                length = int.from_bytes(data[idx+2:idx+4], 'big')
                comment = data[idx+4:idx+4+length-2]
                exif['JPEGComment'] = comment.decode(errors='ignore')
            except Exception:
                exif['JPEGComment'] = None
        start = data.find(b'<x:xmpmeta')
        end = data.find(b'</x:xmpmeta>')
        exif['XMP'] = data[start:end+12].decode(errors='ignore') if start != -1 and end != -1 else None
        exif['IPTC'] = 'Photoshop 3.0 APP13 segment detected' if b'Photoshop 3.0' in data else None
        brands = ['Canon', 'Nikon', 'Sony', 'Olympus', 'Fujifilm', 'Panasonic', 'Leica', 'Pentax', 'Samsung', 'GoPro']
        found_brand = None
        for b in brands:
            if b.encode() in data:
                found_brand = b
                break
        exif['CameraModel'] = f"{found_brand} (guessed)" if found_brand else 'Unknown'
        name = os.path.basename(filepath).lower()
        if 'night' in name or 'dark' in name:
            exif['EstimatedTimeOfDay'] = 'Night'
        elif 'sunset' in name or 'evening' in name:
            exif['EstimatedTimeOfDay'] = 'Evening'
        elif 'morning' in name or 'sunrise' in name:
            exif['EstimatedTimeOfDay'] = 'Morning'
        else:
            exif['EstimatedTimeOfDay'] = 'Unknown'
        exif['FileSizeBytes'] = stat.st_size
        exif['EXIFBlockPresent'] = exif_start != -1
        if 'GPSLatitude' in exif and 'GPSLongitude' in exif and 'GPSLatitudeRef' in exif and 'GPSLongitudeRef' in exif:
            lat = gps_to_decimal(exif['GPSLatitude'], exif['GPSLatitudeRef'])
            lon = gps_to_decimal(exif['GPSLongitude'], exif['GPSLongitudeRef'])
            exif['Location'] = reverse_geocode(lat, lon)
        def parse_quant_tables(data):
            tables = []
            idx = 0
            while True:
                idx = data.find(b'\xff\xdb', idx)
                if idx == -1:
                    break
                length = int.from_bytes(data[idx+2:idx+4], 'big')
                tables.append(data[idx+4:idx+4+length-2])
                idx += 4+length-2
            return tables
        quant_tables = parse_quant_tables(data)
        exif['JPEGQuantTablesCount'] = len(quant_tables)
        quant_signatures = {
            b'\x00\x01\x01\x01\x01\x01\x01\x01': 'Canon',
            b'\x00\x02\x01\x02\x01\x01\x01\x01': 'Nikon',
            b'\x00\x01\x01\x01\x01\x01\x01\x02': 'Sony',
        }
        for qt in quant_tables:
            for sig, brand in quant_signatures.items():
                if qt.startswith(sig):
                    exif['CameraModelQuantGuess'] = brand
                    break
        orphaned_exif = []
        idx = 0
        while True:
            idx = data.find(b'Exif\x00\x00', idx+1)
            if idx == -1:
                break
            orphaned_exif.append(idx)
        exif['OrphanedEXIFOffsets'] = orphaned_exif if orphaned_exif else None
        fname = os.path.basename(filepath)
        date_match = re.search(r'(20\d{2}[\-_]?(0[1-9]|1[0-2])[\-_]?(0[1-9]|[12][0-9]|3[01]))', fname)
        time_match = re.search(r'([01][0-9]|2[0-3])[0-5][0-9][0-5][0-9]', fname)
        if date_match:
            exif['DateFromFilename'] = date_match.group(1)
        if time_match:
            exif['TimeFromFilename'] = time_match.group(0)
        def image_entropy(data):
            counts = Counter(data)
            total = sum(counts.values())
            import math
            entropy = -sum((c/total)*math.log2(c/total) for c in counts.values() if c)
            return entropy
        exif['ImageEntropy'] = round(image_entropy(data), 3)
        if exif['XMP']:
            xmp_fields = {}
            for tag in ['dc:creator', 'dc:title', 'xmp:CreateDate', 'xmp:ModifyDate']:
                m = re.search(f'<{tag}>(.*?)</{tag}>', exif['XMP'])
                if m:
                    xmp_fields[tag] = m.group(1)
            exif['XMPFields'] = xmp_fields if xmp_fields else None
    except Exception as e:
        exif['FatalError'] = str(e)
    return exif

def recover_exif(filepath):
    return recover_exif_builtin(filepath)

def main():
    print(f"\n--- Rhino EXIF Recovery Tool ---\n{CREDITS}\n")
    directory = os.getcwd()
    images = []
    for f in os.listdir(directory):
        if f.lower().endswith(('.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp', '.gif', '.webp')):
            images.append(os.path.join(directory, f))
    if not images:
        print("[!] No images found in the current directory.")
        return
    print("Found these images:")
    for idx, img_path in enumerate(images):
        print(f"[{idx}] {os.path.basename(img_path)}")
    while True:
        try:
            choice = int(input(f"Select an image by number (0-{len(images)-1}): "))
            if 0 <= choice < len(images):
                filepath = images[choice]
                break
            else:
                print("Invalid selection.")
        except Exception:
            print("Please enter a valid number.")
    print(f"\n[*] Showing EXIF for: {os.path.basename(filepath)}\n")
    og_path = None
    base, ext = os.path.splitext(filepath)
    for suffix in ['_original', '_og', '-original', '-og', '.original', '.backup', '.bak']:
        candidate = base + suffix + ext
        if os.path.exists(candidate):
            og_path = candidate
            break
    if og_path:
        print(f"\n[+] Found possible original image: {os.path.basename(og_path)}")
        try:
            og_exif = recover_exif(og_path)
            print("\n===== ORIGINAL IMAGE EXIF =====")
            for k, v in og_exif.items():
                print(f"{k:20}: {v}")
        except Exception as e:
            print(f"[!] Could not extract EXIF from original: {e}")
            og_exif = None
    else:
        og_exif = None
        print("\n[!] No original image found for automatic EXIF comparison.")
    print("\n===== SELECTED IMAGE EXIF (RAW) =====")
    try:
        before_exif = recover_exif(filepath)
        for k, v in before_exif.items():
            print(f"{k:20}: {v}")
    except Exception as e:
        print(f"[!] Could not extract EXIF from selected image: {e}")
        before_exif = None
    print("\n===== RECOVERED EXIF (ADVANCED) =====")
    try:
        recovered_exif = recover_exif(filepath)
        for k, v in recovered_exif.items():
            print(f"{k:20}: {v}")
    except Exception as e:
        print(f"[!] Could not recover EXIF: {e}")
    print(f"\n{CREDITS}\n---\n")
    print("Note: True EXIF cannot be restored if wiped, but this tool reconstructs as much as possible using only custom Python code.")
    print("\nPress Enter to exit.")
    input()

if __name__ == "__main__":
    main()
