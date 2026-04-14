#!/usr/bin/env python3
"""
Diagnostic tool for WD My Passport drive detection.
Run:  sudo python3 test_live.py [device]
e.g.  sudo python3 test_live.py sda

Tests sg devices directly (not the block device path /dev/sda)
because SCSI data only returns via /dev/sgX nodes.
"""
import sys, os, subprocess, struct, glob

sys.path.insert(0, os.path.dirname(__file__))

DEV      = sys.argv[1] if len(sys.argv) > 1 else "sda"
DEV_PATH = f"/dev/{DEV}"
WD_VID   = "1058"


def run_text(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip(), r.returncode
    except FileNotFoundError:
        return f"(command not found: {cmd[0]})", -1
    except subprocess.TimeoutExpired:
        return "(timed out)", -2


def sgraw(device, cdb_hex, recv=0, timeout=8):
    """Run sg_raw on a /dev/sgX device. Returns (data_bytes, stderr_str, returncode)."""
    cmd = ["sg_raw"]
    if recv:
        cmd += ["-r", str(recv)]
    cmd += [device] + cdb_hex.split()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout, r.stderr.decode(errors="replace"), r.returncode
    except FileNotFoundError:
        return b"", "sg_raw not found — install: sudo apt install sg3-utils", -1
    except subprocess.TimeoutExpired:
        return b"", f"timed out on {device}", -2


def sg_device_type(sg_name):
    """Return SCSI device type from sysfs (0=disk, 5=CD-ROM, -1=unknown)."""
    try:
        with open(f"/sys/class/scsi_generic/{sg_name}/device/type") as f:
            return int(f.read().strip())
    except Exception:
        return -1


def find_sg_for_vid(vid_str):
    """Return list of (sg_path, type_int) for all sg devices matching VID."""
    results = []
    for sg_path in sorted(glob.glob("/sys/class/scsi_generic/sg*")):
        sg_name = os.path.basename(sg_path)
        try:
            real = os.path.realpath(sg_path)
            parts = real.split(os.sep)
            for i in range(len(parts), 0, -1):
                candidate = os.sep.join(parts[:i])
                vf = os.path.join(candidate, "idVendor")
                if os.path.isfile(vf):
                    with open(vf) as f:
                        if f.read().strip().lower() == vid_str.lower():
                            results.append((f"/dev/{sg_name}", sg_device_type(sg_name)))
                    break
        except Exception:
            continue
    return results


sep = "=" * 62
print(sep)
print(f"  WD My Passport — Drive Diagnostics  ({DEV_PATH})")
print(sep)

# ── 1. lsblk overview ────────────────────────────────────────────────────────
print("\n[1] Block device overview (lsblk):")
out, rc = run_text(["lsblk", "-o", "NAME,MODEL,VENDOR,SIZE,TRAN,SERIAL,TYPE", DEV_PATH])
for line in out.splitlines():
    print(f"    {line}")

# ── 2. hdparm ATA security status ────────────────────────────────────────────
print(f"\n[2] ATA Security Status (hdparm -I {DEV_PATH}):")
out, rc = run_text(["hdparm", "-I", DEV_PATH], timeout=12)
if rc == -1:
    print("    hdparm not found — install: sudo apt install hdparm")
elif not out.strip():
    print("    (no output — USB bridge does not support ATA passthrough for hdparm)")
else:
    security_block = False
    for line in out.splitlines():
        ll = line.lower()
        if "security" in ll:
            security_block = True
        if security_block:
            print(f"    {line}")
            # Stop after a blank line following the security block
            if security_block and not line.strip() and "security" not in ll:
                break

# ── 3. Identify sg devices for WD VID ───────────────────────────────────────
print(f"\n[3] sg devices for WD VID=0x{WD_VID}:")
wd_sgs = find_sg_for_vid(WD_VID)
TYPE_NAMES = {0: "disk", 5: "CD-ROM", 13: "enclosure/bridge"}
if wd_sgs:
    for sg_path, dev_type in wd_sgs:
        type_name = TYPE_NAMES.get(dev_type, f"type={dev_type}")
        print(f"    {sg_path}  ({type_name})")
else:
    print("    No sg devices found for WD VID — is the drive plugged in?")

# Pick the primary disk-type sg device for further tests
primary_sg = next((p for p, t in wd_sgs if t == 0), None)
if primary_sg is None and wd_sgs:
    primary_sg = wd_sgs[0][0]

# ── 4. SCSI INQUIRY on primary sg device ─────────────────────────────────────
if primary_sg:
    print(f"\n[4] SCSI INQUIRY on {primary_sg}:")
    data, err, rc = sgraw(primary_sg, "12 00 00 00 60 00", recv=96)
    if rc == 0 and len(data) >= 8:
        vendor  = data[8:16].decode(errors="replace").strip()
        product = data[16:32].decode(errors="replace").strip()
        rev     = data[32:36].decode(errors="replace").strip()
        print(f"    Vendor : {vendor}")
        print(f"    Product: {product}")
        print(f"    Rev    : {rev}")
        print(f"    Raw    : {data[:36].hex().upper()}")
    else:
        first_err = err.splitlines()[0] if err else "no data"
        print(f"    FAIL (rc={rc}): {first_err}")

# ── 5. TEST UNIT READY ────────────────────────────────────────────────────────
if primary_sg:
    print(f"\n[5] TEST UNIT READY on {primary_sg}:")
    _, err, rc = sgraw(primary_sg, "00 00 00 00 00 00")
    if rc == 0:
        print("    OK — drive is ready")
    else:
        first_err = err.splitlines()[0] if err else ""
        print(f"    rc={rc}: {first_err}")

# ── 6. SECURITY PROTOCOL IN — probe supported protocols ──────────────────────
if primary_sg:
    print(f"\n[6] SECURITY PROTOCOL IN proto=0x00 (list supported) on {primary_sg}:")
    data, err, rc = sgraw(primary_sg, "A2 00 00 00 00 00 00 00 00 40 00 00", recv=64)
    if rc == 0 and data:
        print(f"    OK — raw: {data[:16].hex().upper()}")
        if len(data) >= 8:
            list_len = struct.unpack(">H", data[6:8])[0]
            protos   = list(data[8:8 + list_len])
            print(f"    Supported protocols: {[hex(p) for p in protos]}")
            if 0xC1 in protos:
                print("    ✓ WD proprietary (0xC1) supported — SCSI Security Protocol works!")
    else:
        first_err = err.splitlines()[0] if err else ""
        print(f"    FAIL (rc={rc}): {first_err}")
        if "Invalid command operation code" in err:
            print("    → opcode 0xA2 NOT supported on this device")

# ── 7. WD challenge block via SCSI Security Protocol ─────────────────────────
if primary_sg:
    print(f"\n[7] WD Security Protocol 0xC1 page 0x0E (challenge) on {primary_sg}:")
    data, err, rc = sgraw(primary_sg, "A2 C1 00 0E 00 00 00 00 00 28 00 00", recv=40)
    if rc == 0 and data:
        print(f"    SUCCESS! Raw ({len(data)} bytes): {data.hex().upper()}")
        iters = struct.unpack(">I", data[0:4])[0]
        salt  = data[8:40].hex().upper()
        print(f"    Iterations : {iters}")
        print(f"    Salt       : {salt}")
    else:
        first_err = err.splitlines()[0] if err else ""
        print(f"    FAIL (rc={rc}): {first_err}")

# ── 8. WD proprietary vendor command 0xD4 (older WD models ~2012) ────────────
if primary_sg:
    print(f"\n[8] WD Vendor Command 0xD4 (older WD My Passport ~2012) on {primary_sg}:")
    # 0xD4 is a WD vendor-specific opcode used on JMicron-bridged drives
    # page 0x05 = security status page for this class of drive
    for page in [0x05, 0x01, 0x0E]:
        cdb = f"D4 {page:02X} 00 00 00 00 00 00 28 00 00 00"
        data, err, rc = sgraw(primary_sg, cdb, recv=40)
        if rc == 0 and data:
            print(f"    page=0x{page:02X}: SUCCESS! Raw: {data.hex().upper()}")
        else:
            first_err = err.splitlines()[0] if err.strip() else "no output"
            print(f"    page=0x{page:02X}: FAIL (rc={rc}): {first_err[:60]}")

# ── 9. ATA IDENTIFY DEVICE via SAT passthrough ───────────────────────────────
if primary_sg:
    print(f"\n[9] ATA IDENTIFY DEVICE via SAT on {primary_sg}:")
    # ATA PASS-THROUGH(12) protocol=4 (PIO-in), command=0xEC (IDENTIFY)
    data, err, rc = sgraw(primary_sg, "A1 08 0E 00 01 00 00 00 00 EC 00 00", recv=512)
    if rc == 0 and data and len(data) >= 512:
        w128 = struct.unpack_from("<H", data, 128 * 2)[0]
        print(f"    ATA Security word 128 = 0x{w128:04X}")
        print(f"    Supported : {bool(w128 & 1)}")
        print(f"    Enabled   : {bool(w128 & 2)}")
        print(f"    Locked    : {bool(w128 & 4)}")
        print(f"    Frozen    : {bool(w128 & 8)}")
        if w128 & 4:
            print("    → Drive is ATA SECURITY LOCKED")
    else:
        first_err = err.splitlines()[0] if err else ""
        print(f"    FAIL (rc={rc}): {first_err}")
        if rc != 0:
            print("    → USB bridge does NOT support SAT ATA passthrough")

# ── 10. Probe all sg devices with 0xA2 ───────────────────────────────────────
print("\n[10] Probe all /dev/sg* with opcode 0xA2:")
for sg_path in sorted(glob.glob("/dev/sg*")):
    data, err, rc = sgraw(sg_path, "A2 00 00 00 00 00 00 00 00 40 00 00", recv=64)
    if rc == 0 and data:
        print(f"    {sg_path}: ACCEPTED 0xA2 ← this is the right device!")
        if len(data) >= 8:
            list_len = struct.unpack('>H', data[6:8])[0]
            protos = list(data[8:8 + list_len])
            print(f"    Protocols: {[hex(p) for p in protos]}")
    else:
        first_err = err.splitlines()[0] if err.strip() else "no output"
        print(f"    {sg_path}: {first_err[:70]}")

# ── 11. WD ECB protocol — full raw dump via py3_sg ───────────────────────────
print(f"\n[11] WD ECB raw dump via py3_sg on {DEV_PATH}:")

def hexdump(data, width=16, indent="    "):
    """Print a classic hex + ASCII dump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part  = " ".join(f"{b:02X}" for b in chunk)
        asc_part  = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{i:04X}  {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines)

try:
    import py3_sg
    dev = open(DEV_PATH, "r+b")
    print(f"    Opened {DEV_PATH} via py3_sg")

    # ── 11a. Opcode 0xC0 — encryption status ─────────────────────────────
    print(f"\n    [11a] 0xC0 Encryption Status (0x30 bytes):")
    cdb_c0 = struct.pack("10B", 0xC0, 0x45, 0, 0, 0, 0, 0, 0, 0x30, 0)
    try:
        raw_c0 = py3_sg.read_as_bin_str(dev, cdb_c0, 512)
        d = bytes(raw_c0)
        print(f"    Signature byte  : 0x{d[0]:02X} ({'OK' if d[0]==0x45 else 'unexpected'})")
        print(f"    Security Status : 0x{d[3]:02X}")
        _SS = {0x00:"Unprotected",0x01:"Unlocked",0x02:"Locked",
               0x06:"Locked (blocked)"}
        print(f"                      {_SS.get(d[3], 'unknown')}")
        print(f"    Cipher ID       : 0x{d[4]:02X}  "
              f"({'AES-256-ECB' if d[4]==0x10 else 'AES-128-ECB' if d[4]==0x20 else 'other'})")
        pw_len = struct.unpack("!H", bytes(d[6:8]))[0]
        print(f"    PW Block Length : {pw_len} bytes")
        key_reset = bytes(d[8:12]).hex().upper()
        print(f"    Key Reset Token : {key_reset}")
        print(f"    Full response   :")
        print(hexdump(d[:0x30]))
    except Exception as e:
        print(f"    FAIL: {e}")

    # ── 11b. Opcode 0xD8 page 0 — Handy Store Block 0 (unknown structure) ─
    print(f"\n    [11b] 0xD8 page=0 — Handy Store Block 0 (512 bytes):")
    page0_bytes = struct.pack("!I", 0)
    cdb_d8p0 = struct.pack("10B",
                            0xD8, 0x00,
                            page0_bytes[0], page0_bytes[1],
                            page0_bytes[2], page0_bytes[3],
                            0x00, 0x00, 0x01, 0x00)
    try:
        raw_p0 = py3_sg.read_as_bin_str(dev, cdb_d8p0, 512)
        p0 = bytes(raw_p0)
        print(f"    First 4 bytes   : {p0[:4].hex().upper()}  "
              f"(ASCII: {p0[:4].decode(errors='replace')!r})")
        print(f"    Bytes 4-7       : {p0[4:8].hex().upper()}")
        print(f"    Bytes 8-39 (32) : {p0[8:40].hex().upper()}  ← possible encrypted key")
        print(f"    Bytes 40-47     : {p0[40:48].hex().upper()}")
        print(f"    All-zero?       : {all(b == 0 for b in p0)}")
        print(f"    Non-zero bytes  : {sum(1 for b in p0 if b != 0)}/512")
        print(f"\n    Full 512-byte hex dump of Block 0:")
        print(hexdump(p0))

        # Check for known WD signatures
        WD_SIGS = {
            bytes([0x00, 0x01, 0x44, 0x57]): "WD Block1 signature (DW)",
            bytes([0x45, 0x00, 0x00, 0x00]): "WD ECB key-block signature",
            bytes([0x57, 0x44, 0x01, 0x00]): "WD alt signature",
        }
        for sig, name in WD_SIGS.items():
            pos = p0.find(sig)
            if pos >= 0:
                print(f"\n    ✓ Found '{name}' at offset {pos}")
    except Exception as e:
        print(f"    FAIL: {e}")

    # ── 11c. Opcode 0xD8 page 1 — Handy Store Block 1 (known structure) ───
    print(f"\n    [11c] 0xD8 page=1 — Handy Store Block 1 (known params):")
    page1_bytes = struct.pack("!I", 1)
    cdb_d8p1 = struct.pack("10B",
                            0xD8, 0x00,
                            page1_bytes[0], page1_bytes[1],
                            page1_bytes[2], page1_bytes[3],
                            0x00, 0x00, 0x01, 0x00)
    try:
        raw_p1 = py3_sg.read_as_bin_str(dev, cdb_d8p1, 512)
        p1 = bytes(raw_p1)
        sig_ok = p1[:4] == bytes([0x00, 0x01, 0x44, 0x57])
        print(f"    Signature       : {p1[:4].hex().upper()} ({'OK' if sig_ok else 'BAD'})")
        iters = struct.unpack_from("<I", p1, 8)[0]
        print(f"    Iterations      : {iters}")
        salt = p1[12:20]
        ascii_salt = ""
        for i in range(4):
            b0, b1 = salt[2*i], salt[2*i+1]
            if b1 == 0x00 and 32 <= b0 < 127:
                ascii_salt += chr(b0)
        print(f"    Salt (hex)      : {salt.hex().upper()}")
        print(f"    Salt (ASCII)    : {ascii_salt!r}")
        hint_raw = p1[24:226]
        try:
            hint = hint_raw.decode("utf-16-le").rstrip("\x00")
        except Exception:
            hint = hint_raw[:40].hex()
        print(f"    Hint            : {hint!r}")
        print(f"    Checksum byte   : 0x{p1[511]:02X}")
        print(f"\n    First 64 bytes of Block 1:")
        print(hexdump(p1[:64]))
    except Exception as e:
        print(f"    FAIL: {e}")

    # ── 11d. Opcode 0xD8 pages 2 and 3 — any additional blocks? ──────────
    for page_num in [2, 3]:
        print(f"\n    [11d-{page_num}] 0xD8 page={page_num} — Handy Store Block {page_num}:")
        pn_bytes = struct.pack("!I", page_num)
        cdb_pn = struct.pack("10B",
                              0xD8, 0x00,
                              pn_bytes[0], pn_bytes[1],
                              pn_bytes[2], pn_bytes[3],
                              0x00, 0x00, 0x01, 0x00)
        try:
            raw_pn = py3_sg.read_as_bin_str(dev, cdb_pn, 512)
            pn = bytes(raw_pn)
            non_zero = sum(1 for b in pn if b != 0)
            print(f"    Non-zero bytes  : {non_zero}/512")
            if non_zero > 0:
                print(f"    First 64 bytes  :")
                print(hexdump(pn[:64]))
            else:
                print(f"    (all zeros — page likely unused)")
        except Exception as e:
            print(f"    FAIL: {e}")

    dev.close()

except ImportError:
    print("    py3_sg not installed — run: pip install py3_sg")
    print("    (or: sudo pip3 install py3_sg)")
except PermissionError:
    print(f"    Permission denied opening {DEV_PATH} — run with sudo")
except FileNotFoundError:
    print(f"    Device {DEV_PATH} not found — is the drive connected?")
except Exception as e:
    print(f"    Unexpected error: {e}")

print("\n" + sep)
print("  SUMMARY")
print(sep)
if not wd_sgs:
    print("  No WD sg devices found. Check drive is connected and VID=0x1058.")
else:
    print(f"  Primary disk sg device: {primary_sg or 'none found'}")
    print()
    print("  Protocol determination:")
    print("  • If [6] or [10] succeeded with 0xC1 → SCSI Security Protocol works")
    print("  • If [8] 0xD4 succeeded → WD proprietary vendor command (2012-era drives)")
    print("  • If [9] succeeded → ATA Security via SAT works (use hdparm)")
    print("  • If all failed → drive uses a protocol not yet reverse-engineered")
    print()
    print("  Recommended models for live demo: WD My Passport 25E2, 25E1, 25E3")
    print("  These use SCSI Security Protocol and work with this app.")
print(sep)
