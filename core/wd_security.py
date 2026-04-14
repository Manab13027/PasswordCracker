"""
WD My Passport — Security Protocol Interface
=============================================
WD My Passport drives use the SCSI Security Protocol (SPC-4):
  - SECURITY PROTOCOL IN  (opcode 0xA2) — read security data from drive
  - SECURITY PROTOCOL OUT (opcode 0xB5) — send security data to drive

Protocol IDs used by WD:
  0x00  — Security Protocol Information (list supported protocols)
  0xC1  — WD Proprietary unlock / challenge-response

Unlock flow:
  1. SECURITY PROTOCOL IN (proto=0x00, page=0x00) → list supported protocols
  2. SECURITY PROTOCOL IN (proto=0xC1, page=0x0E) → 40-byte challenge block
       Bytes 0–3:  PBKDF2 iteration count (big-endian uint32)
       Bytes 4–7:  flags / reserved
       Bytes 8–39: 32-byte PBKDF2 salt
  3. Derive KEK: PBKDF2-HMAC-SHA256(password_utf16le, salt, iterations, dklen=32)
  4. SECURITY PROTOCOL OUT (proto=0xC1, page=0x0E) → send derived 32-byte KEK
  5. Drive checks KEK against stored value → unlocks if correct

macOS SCSI passthrough:
  sg3_utils is Linux-only; on macOS we use pyusb to speak USB BOT (Bulk-Only
  Transport) directly. libusb must be installed: brew install libusb
  The Python binding: pip3 install pyusb
"""

from __future__ import annotations

import os
import sys
import struct
import hashlib
import subprocess
import binascii
import shutil
from typing import Optional


# ── SCSI opcode constants ────────────────────────────────────────────────────
SECURITY_PROTOCOL_IN  = 0xA2
SECURITY_PROTOCOL_OUT = 0xB5
WD_PROTOCOL_ID        = 0xC1
WD_PAGE_CHALLENGE     = 0x0E
WD_PAGE_STATUS        = 0x06

WD_PBKDF2_ITERATIONS  = 1000
WD_SALT_LENGTH        = 32

# Western Digital USB Vendor ID
WD_VID = 0x1058


# ── Key derivation ───────────────────────────────────────────────────────────

def derive_wd_key(password: str, salt: bytes,
                  iterations: int = WD_PBKDF2_ITERATIONS) -> bytes:
    """
    Derive the 32-byte WD unlock key (KEK).
    WD encodes the password as UTF-16LE before PBKDF2.
    """
    pw_bytes = password.encode("utf-16-le")
    return hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, iterations, dklen=32)


def sha256_password_simple(password: str, salt: bytes) -> bytes:
    """Older pre-2014 WD scheme: SHA256(salt + password_utf16le)."""
    return hashlib.sha256(salt + password.encode("utf-16-le")).digest()


# ── SCSI CDB builders ────────────────────────────────────────────────────────

def _build_security_in_cdb(protocol_id: int, page_code: int,
                            length: int = 40) -> bytes:
    """
    Build a 12-byte SECURITY PROTOCOL IN CDB (opcode 0xA2).

    Byte  0   : Opcode (0xA2)
    Byte  1   : Security Protocol ID
    Bytes 2–3 : Security Protocol Specific (page code, big-endian 16-bit)
    Byte  4   : INC_512 flag (0)
    Byte  5   : Reserved
    Bytes 6–9 : Allocation Length (big-endian 32-bit)
    Byte  10  : Reserved
    Byte  11  : Control
    """
    return struct.pack(">BBBBBBIBB",
                       SECURITY_PROTOCOL_IN,   # opcode
                       protocol_id,             # security protocol
                       (page_code >> 8) & 0xFF, # page code MSB
                       page_code & 0xFF,        # page code LSB
                       0x00,                    # INC_512
                       0x00,                    # reserved
                       length,                  # allocation length (4 bytes)
                       0x00,                    # reserved
                       0x00)                    # control


# ── USB Bulk-Only Transport (BOT) SCSI passthrough ───────────────────────────

class USBSCSIError(Exception):
    pass


def _bot_send_command(dev, ep_out, ep_in,
                      cdb: bytes, data_length: int,
                      timeout: int = 5000) -> bytes:
    """
    Send a SCSI command via USB Bulk-Only Transport and return response data.

    CBW (31 bytes, little-endian):
      dCBWSignature       = 0x43425355
      dCBWTag             = arbitrary tag
      dCBWDataTransferLen = expected response length
      bmCBWFlags          = 0x80 (Data-In)
      bCBWLUN             = 0
      bCBWCBLength        = len(cdb)
      CBWCB               = cdb padded to 16 bytes
    """
    tag = 0xDEADBEEF

    # Pad CDB to 16 bytes
    cdb_padded = cdb + b"\x00" * (16 - len(cdb))

    cbw = struct.pack("<IIIBBB",
                      0x43425355,    # signature
                      tag,
                      data_length,
                      0x80,          # flags: Data-In
                      0x00,          # LUN 0
                      len(cdb)) + cdb_padded

    # 1. Send CBW
    written = ep_out.write(cbw, timeout=timeout)
    if written != len(cbw):
        raise USBSCSIError(f"CBW write incomplete: {written}/{len(cbw)}")

    # 2. Read data
    data = b""
    if data_length > 0:
        raw = ep_in.read(data_length, timeout=timeout)
        data = bytes(raw)

    # 3. Read CSW (13 bytes)
    csw_raw = ep_in.read(13, timeout=timeout)
    csw = bytes(csw_raw)
    if len(csw) >= 13:
        csw_sig, csw_tag, csw_residue, csw_status = struct.unpack("<IIIB", csw[:13])
        if csw_sig != 0x53425355:
            raise USBSCSIError(f"Bad CSW signature: 0x{csw_sig:08X}")
        if csw_status != 0:
            raise USBSCSIError(f"SCSI command failed, CSW status=0x{csw_status:02X}")

    return data


def _find_bulk_endpoints(interface):
    """Return (ep_out, ep_in) bulk endpoint objects from a USB interface."""
    import usb.util
    ep_out = usb.util.find_descriptor(
        interface,
        custom_match=lambda e: (
            usb.util.endpoint_direction(e.bEndpointAddress) ==
            usb.util.ENDPOINT_OUT
        ))
    ep_in = usb.util.find_descriptor(
        interface,
        custom_match=lambda e: (
            usb.util.endpoint_direction(e.bEndpointAddress) ==
            usb.util.ENDPOINT_IN
        ))
    return ep_out, ep_in


# ── Linux sg_raw passthrough ─────────────────────────────────────────────────

def _sg_device_type(sg_name: str) -> int:
    """
    Return the SCSI device type for /dev/sgX.
    Reads /sys/class/scsi_generic/sgX/device/type.
      0 = Direct-access block (disk)   ← we want this
      5 = CD-ROM / DVD                 ← skip (WD Unlocker virtual CD)
    Returns -1 if unreadable.
    """
    try:
        type_file = f"/sys/class/scsi_generic/{sg_name}/device/type"
        with open(type_file) as f:
            return int(f.read().strip())
    except Exception:
        return -1


def _all_sg_for_vid(vid: int) -> list:
    """Return list of (sg_name, device_type) for all sg devices with matching VID."""
    import glob as _glob
    results = []
    for sg_path in sorted(_glob.glob("/sys/class/scsi_generic/sg*")):
        sg_name = os.path.basename(sg_path)
        try:
            real = os.path.realpath(sg_path)
            parts = real.split(os.sep)
            for i in range(len(parts), 0, -1):
                candidate = os.sep.join(parts[:i])
                vendor_file = os.path.join(candidate, "idVendor")
                if os.path.isfile(vendor_file):
                    with open(vendor_file) as f:
                        found_vid = int(f.read().strip(), 16)
                    if found_vid == vid:
                        results.append((sg_name, _sg_device_type(sg_name)))
                    break
        except Exception:
            continue
    return results


def _find_sg_device_for_vid(vid: int) -> Optional[str]:
    """
    On Linux, find the /dev/sgX disk device matching a USB VID.
    Skips CD-ROM type devices (type=5) — the WD Unlocker virtual CD
    lives on a separate sg device and rejects Security Protocol commands.
    Returns the first type=0 (direct-access disk) match.
    """
    import glob as _glob
    candidates = []

    for sg_path in sorted(_glob.glob("/sys/class/scsi_generic/sg*")):
        sg_name = os.path.basename(sg_path)
        try:
            real = os.path.realpath(sg_path)
            parts = real.split(os.sep)
            for i in range(len(parts), 0, -1):
                candidate = os.sep.join(parts[:i])
                vendor_file = os.path.join(candidate, "idVendor")
                if os.path.isfile(vendor_file):
                    with open(vendor_file) as f:
                        found_vid = int(f.read().strip(), 16)
                    if found_vid == vid:
                        dev_type = _sg_device_type(sg_name)
                        candidates.append((sg_name, dev_type))
                    break
        except Exception:
            continue

    if not candidates:
        return None

    # Prefer type=0 (disk).  If none, fall back to whatever we found.
    for sg_name, dev_type in candidates:
        if dev_type == 0:
            return f"/dev/{sg_name}"

    return f"/dev/{candidates[0][0]}"


def _sg_for_block_device(block_name: str) -> Optional[str]:
    """
    Given a block device name like 'sda', return its /dev/sgX path.
    Uses /sys/block/sda/device/scsi_generic/ symlink.
    """
    import glob as _glob
    try:
        pattern = f"/sys/block/{block_name}/device/scsi_generic/sg*"
        matches = _glob.glob(pattern)
        if matches:
            return f"/dev/{os.path.basename(matches[0])}"
    except Exception:
        pass
    return None


def _sgraw(sg_device: str, cdb_hex: str, recv: int,
            timeout: int = 10) -> tuple[Optional[bytes], str, int]:
    """Run sg_raw on a /dev/sgX device. Returns (data, stderr, returncode)."""
    cmd = ["sg_raw", "-r", str(recv), sg_device] + cdb_hex.split()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout, r.stderr.decode(errors="replace"), r.returncode
    except subprocess.TimeoutExpired:
        return None, f"timed out on {sg_device}", -2
    except Exception as e:
        return None, str(e), -1


def get_challenge_sgraw(sg_device: str) -> tuple[Optional[bytes], str]:
    """
    On Linux: send SECURITY PROTOCOL IN (0xA2/0xC1) via sg_raw.
    Falls back to WD proprietary opcode 0xD4 for older ~2012 drives.
    Requires sg3-utils:  sudo apt install sg3-utils
    """
    if not shutil.which("sg_raw"):
        return None, "sg_raw not found — install: sudo apt install sg3-utils"

    # --- Primary: SCSI Security Protocol IN (0xA2, proto=0xC1, page=0x0E) ---
    cdb = _build_security_in_cdb(WD_PROTOCOL_ID, WD_PAGE_CHALLENGE, 40)
    cdb_hex = " ".join(f"{b:02x}" for b in cdb)
    data, stderr, rc = _sgraw(sg_device, cdb_hex, 40)
    if rc == 0 and data and len(data) >= 40:
        return data[:40], ""
    scsi_err = stderr.strip()

    # --- Fallback: WD proprietary vendor command 0xD4 (JMicron-bridged ~2012) ---
    if "Invalid command operation code" in scsi_err or rc != 0:
        for page in [0x05, 0x01, 0x0E]:
            wd_cdb = f"D4 {page:02X} 00 00 00 00 00 00 28 00 00 00"
            data, stderr2, rc2 = _sgraw(sg_device, wd_cdb, 40)
            if rc2 == 0 and data and len(data) >= 40:
                return data[:40], ""

    # Return the original SCSI error so callers can detect "opcode not supported"
    if rc != 0:
        return None, f"sg_raw failed (rc={rc}): {scsi_err}"
    return None, f"sg_raw returned only {len(data or b'')} bytes (expected 40)"


def _unmount_disk(disk_id: str) -> bool:
    """Unmount all volumes on a disk so macOS releases its USB interface claim."""
    if not disk_id or disk_id == "disk?":
        return False
    r = subprocess.run(
        ["diskutil", "unmountDisk", f"/dev/{disk_id}"],
        capture_output=True, text=True, timeout=8)
    return r.returncode == 0


def _remount_disk(disk_id: str):
    """Re-mount a disk after SCSI commands are done."""
    if not disk_id or disk_id == "disk?":
        return
    subprocess.run(
        ["diskutil", "mountDisk", f"/dev/{disk_id}"],
        capture_output=True, timeout=8)


def scsi_security_in_usb(vid: int, pid: int,
                          protocol_id: int, page_code: int,
                          length: int = 40,
                          disk_id: str = "") -> tuple[Optional[bytes], str]:
    """
    Send SECURITY PROTOCOL IN to a USB device identified by VID/PID.
    Returns (data_bytes, error_string).  error_string is "" on success.

    On macOS the kernel mass-storage driver holds the USB interface.
    We unmount the disk first to release that claim, send our command,
    then remount.  This is non-destructive for the WD Unlocker virtual CD.

    Requires: pip3 install pyusb  AND  brew install libusb
    """
    try:
        import usb.core
        import usb.util
    except ImportError:
        import sys
        return None, (
            f"pyusb not installed for THIS Python ({sys.executable}).\n\n"
            f"Fix — install pyusb for the correct interpreter:\n"
            f"  {sys.executable} -m pip install pyusb --break-system-packages\n\n"
            f"Then re-run with sudo using the FULL path:\n"
            f"  sudo {sys.executable} main.py --live"
        )

    dev = usb.core.find(idVendor=vid, idProduct=pid)
    if dev is None:
        return None, f"USB device VID=0x{vid:04X} PID=0x{pid:04X} not found"

    # macOS: unmount the disk so the kernel releases its interface claim
    unmounted = False
    if disk_id:
        unmounted = _unmount_disk(disk_id)

    try:
        dev.set_configuration()
    except Exception:
        pass

    intf = None
    try:
        cfg = dev.get_active_configuration()
        intf = cfg[(0, 0)]
    except Exception as e:
        if unmounted:
            _remount_disk(disk_id)
        return None, f"Could not read USB configuration: {e}"

    try:
        ep_out, ep_in = _find_bulk_endpoints(intf)
        if ep_out is None or ep_in is None:
            return None, "Could not find bulk endpoints on USB interface 0"

        cdb = _build_security_in_cdb(protocol_id, page_code, length)
        data = _bot_send_command(dev, ep_out, ep_in, cdb, length)
        return data, ""

    except Exception as e:
        err_str = str(e)
        if "13" in err_str or "Access denied" in err_str or "Permission" in err_str:
            return None, (
                "Permission denied — macOS requires root to send raw USB commands.\n\n"
                "Re-run the app with sudo:\n"
                "    sudo /opt/homebrew/bin/python3.13 main.py --live"
            )
        return None, f"SCSI command error: {e}"
    finally:
        try:
            usb.util.dispose_resources(dev)
        except Exception:
            pass
        if unmounted:
            _remount_disk(disk_id)


# ── ATA Security (alternative to SCSI Security Protocol) ────────────────────

def get_ata_security_status(disk_id: str) -> dict:
    """
    Read ATA Security status using hdparm -I.
    Many WD My Passport models (e.g. 0748) use ATA Security instead of
    SCSI Security Protocol 0xC1.  Unlike SCSI, ATA Security does NOT expose
    an extractable salt — the password is verified on-device only.

    Returns dict with keys:
      available, supported, enabled, locked, frozen, count_expired, raw, error
    """
    result = {
        "available":     False,
        "supported":     False,
        "enabled":       False,
        "locked":        False,
        "frozen":        False,
        "count_expired": False,
        "raw":           "",
        "error":         "",
    }
    if not shutil.which("hdparm"):
        result["error"] = "hdparm not found — install: sudo apt install hdparm"
        return result

    try:
        r = subprocess.run(
            ["hdparm", "-I", f"/dev/{disk_id}"],
            capture_output=True, text=True, timeout=10)
        output = r.stdout + r.stderr
        result["available"] = True
        result["raw"] = output

        for line in output.splitlines():
            ll = line.lower().strip()
            # hdparm output uses indented lines like "\t\tSupported: enhanced erase"
            # and security flags like "enabled", "locked", "frozen", "not frozen", etc.
            if "security" not in ll:
                continue
            if "not\tsupported" in ll or "not supported" in ll:
                continue
            if "supported" in ll:
                result["supported"] = True
            if "enabled" in ll and "not" not in ll:
                result["enabled"] = True
            if "locked" in ll and "not" not in ll:
                result["locked"] = True
            if "frozen" in ll and "not" not in ll:
                result["frozen"] = True
            if "count expired" in ll or "count\texpired" in ll:
                result["count_expired"] = True
        return result

    except subprocess.TimeoutExpired:
        result["error"] = "hdparm timed out"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def try_ata_unlock_hdparm(disk_id: str, password: str) -> tuple[bool, str]:
    """
    Attempt a single ATA SECURITY UNLOCK via hdparm.

    WARNING — ATA Security has a hardware attempt counter.
    After ~5 wrong attempts the drive enters "count expired" state
    and only a SECURITY ERASE (data-destructive) will reset it.
    Only call this when you intend to send the real password.

    Returns (unlocked: bool, message: str).
    """
    if not shutil.which("hdparm"):
        return False, "hdparm not found — install: sudo apt install hdparm"

    try:
        r = subprocess.run(
            ["hdparm", "--security-unlock", password, f"/dev/{disk_id}"],
            capture_output=True, text=True, timeout=15)
        output = r.stdout + r.stderr
        if r.returncode == 0 and "SECURITY_UNLOCK" in output.upper():
            return True, output.strip()
        elif "security count expired" in output.lower():
            return False, "Drive LOCKED OUT — security count expired. Only security erase can reset."
        else:
            return False, output.strip() or f"hdparm returned code {r.returncode}"
    except subprocess.TimeoutExpired:
        return False, "hdparm timed out"
    except Exception as e:
        return False, str(e)


# ── WD Proprietary ECB Protocol (~2012 era drives, opcode 0xC0/0xD8/0xC1) ────
#
# These drives (e.g. WD My Passport 0748) use WD vendor-specific SCSI opcodes
# via py3_sg (SG_IO ioctl on /dev/sda directly).  Standard opcode 0xA2 is NOT
# supported.  The security parameters are stored in a "Handy Store" block
# accessible via opcode 0xD8, and unlock is performed via opcode 0xC1/0xE1.

def _wd_ecb_open(disk_id: str):
    """
    Open the block device with py3_sg for WD ECB commands.
    Returns (file_handle, py3_sg_module) or raises ImportError / PermissionError.
    """
    try:
        import py3_sg
    except ImportError:
        raise ImportError(
            "py3_sg not installed.\n"
            "Fix: pip3 install git+https://github.com/crypto-universe/py_sg"
        )
    dev = open(f"/dev/{disk_id}", "r+b")
    return dev, py3_sg


def get_wd_ecb_status(disk_id: str) -> tuple[Optional[dict], str]:
    """
    Read WD encryption status via opcode 0xC0 (WD vendor command).
    Returns (status_dict, error).

    status_dict keys: sec_status, cipher_id, pw_length, key_reset (bytes)
    sec_status values: 0x00=No lock, 0x01=Locked, 0x02=Unlocked,
                       0x06=Locked/blocked, 0x07=No keys
    cipher_id values:  0x20=AES_256_ECB, 0x22=AES_256_CBC, etc.
    """
    try:
        dev, py3_sg = _wd_ecb_open(disk_id)
    except ImportError as e:
        return None, str(e)
    except PermissionError:
        return None, f"Permission denied on /dev/{disk_id} — run with sudo"
    except Exception as e:
        return None, str(e)

    try:
        cdb = struct.pack("10B", 0xC0, 0x45, 0, 0, 0, 0, 0, 0, 0x30, 0)
        data = py3_sg.read_as_bin_str(dev, cdb, 512)
        if not data or len(data) < 12:
            return None, f"opcode 0xC0 returned {len(data) if data else 0} bytes"
        if data[0] != 0x45:
            return None, f"Bad signature 0x{data[0]:02X} (expected 0x45)"
        return {
            "sec_status": data[3],
            "cipher_id":  data[4],
            "pw_length":  struct.unpack("!H", bytes(data[6:8]))[0],
            "key_reset":  bytes(data[8:12]),
        }, ""
    except Exception as e:
        return None, f"opcode 0xC0 error: {e}"
    finally:
        dev.close()


def get_wd_ecb_challenge(disk_id: str) -> dict:
    """
    Read WD Handy Store Block 1 via opcode 0xD8 (page 1).
    Contains: iteration count, 8-byte salt, password hint.

    Returns dict with keys: iterations, salt (bytes), salt_hex, hint, error.
    The salt is stored as UTF-16LE encoded ASCII characters.
    """
    try:
        dev, py3_sg = _wd_ecb_open(disk_id)
    except ImportError as e:
        return {"error": str(e)}
    except PermissionError:
        return {"error": f"Permission denied on /dev/{disk_id} — run with sudo"}
    except Exception as e:
        return {"error": str(e)}

    try:
        # opcode 0xD8, page=1 encoded as big-endian uint32 at bytes 2-5
        page_bytes = struct.pack("!I", 1)
        cdb = struct.pack("10B",
                          0xD8, 0x00,
                          page_bytes[0], page_bytes[1],
                          page_bytes[2], page_bytes[3],
                          0x00, 0x00, 0x01, 0x00)
        raw = py3_sg.read_as_bin_str(dev, cdb, 512)

        if not raw or len(raw) < 512:
            return {"error": f"Short read from Handy Store: {len(raw) if raw else 0} bytes"}

        raw = bytes(raw)

        # Verify WD signature [0x00, 0x01, 0x44, 0x57]
        if raw[:4] != bytes([0x00, 0x01, 0x44, 0x57]):
            sig = raw[:4].hex().upper()
            return {"error": f"No WD password parameters (sig={sig}). "
                             f"Drive may have no password or was set up differently."}

        # Verify checksum (byte 511)
        chk_sum = 0
        for i in range(510):
            chk_sum += raw[i]
        chk_sum += raw[0]          # WD double-counts byte 0
        expected = ((-chk_sum) & 0xFF)
        checksum_ok = (expected == raw[511])

        iterations = struct.unpack_from("<I", raw, 8)[0] or 1000
        salt       = bytes(raw[12:20])   # 8 bytes UTF-16LE-encoded ASCII
        hint_raw   = bytes(raw[24:226])

        # Decode hint: null-terminated UTF-16LE
        try:
            hint = hint_raw.decode("utf-16-le").split("\x00")[0].strip()
        except Exception:
            hint = hint_raw.rstrip(b"\x00").decode(errors="replace").strip()

        return {
            "iterations":   iterations,
            "salt":         salt,
            "salt_hex":     salt.hex().upper(),
            "hint":         hint,
            "checksum_ok":  checksum_ok,
        }
    except Exception as e:
        return {"error": f"Handy Store read error: {e}"}
    finally:
        dev.close()


def derive_wd_ecb_key(password: str, iterations: int, salt_bytes: bytes) -> bytes:
    """
    Derive the 32-byte WD ECB drive key.  Matches wdpassport-utils mk_password_block().

    Algorithm (from wdpassport-utils source):
      1. salt_bytes is 8 bytes of UTF-16LE-encoded ASCII.
         Extract ASCII chars by reading byte[0] of each UTF-16LE pair until null.
      2. Prepend ASCII salt to password: combined = ascii_salt + password
      3. Encode combined as UTF-16 (Python includes 2-byte BOM), strip BOM
      4. SHA-256 hash 'iterations' times
    """
    # Extract ASCII salt chars from UTF-16LE bytes
    extended  = salt_bytes + bytes([0x00, 0x00])
    ascii_salt = ""
    for i in range(len(extended) // 2):
        b0, b1 = extended[2 * i], extended[2 * i + 1]
        if b0 == 0x00 and b1 == 0x00:
            break
        ascii_salt += chr(b0)

    # Encode (salt + password) as UTF-16, strip 2-byte BOM
    key_bytes = (ascii_salt + password).encode("utf-16")[2:]

    # Iterated SHA-256
    for _ in range(iterations):
        key_bytes = hashlib.sha256(key_bytes).digest()

    return key_bytes  # 32 bytes


def try_wd_ecb_unlock(disk_id: str, derived_key: bytes,
                       pw_length: int) -> tuple[bool, str]:
    """
    Attempt WD ECB drive unlock via opcode 0xC1 subop 0xE1.

    Sends the pre-computed 32-byte key to the drive.
    Drive responds: no exception = correct key (unlocked),
                    exception    = wrong key.

    WARNING: Each wrong attempt may decrement the hardware counter.
    Returns (unlocked: bool, message: str).
    """
    try:
        dev, py3_sg = _wd_ecb_open(disk_id)
    except ImportError as e:
        return False, str(e)
    except PermissionError:
        return False, f"Permission denied on /dev/{disk_id} — run with sudo"
    except Exception as e:
        return False, str(e)

    try:
        # pw_block: 6-byte header + 2-byte big-endian pw_length
        pw_block = bytes([0x45, 0x00, 0x00, 0x00, 0x00, 0x00]) + \
                   struct.pack("!H", pw_length)
        payload  = pw_block + derived_key          # 8 + 32 = 40 bytes

        total    = len(payload)                     # 0x28
        cdb      = struct.pack("10B",
                               0xC1, 0xE1, 0, 0, 0, 0, 0, 0, total & 0xFF, 0)
        py3_sg.write(dev, cdb, payload)
        return True, ""
    except Exception as e:
        return False, str(e)
    finally:
        dev.close()


# Cipher ID → human-readable string (mirrors wdpassport-utils)
_CIPHER_NAMES = {
    0x10: "AES-128-ECB", 0x12: "AES-128-CBC", 0x18: "AES-128-XTS",
    0x20: "AES-256-ECB", 0x22: "AES-256-CBC", 0x28: "AES-256-XTS",
    0x30: "Full Disk Encryption",
}

_SEC_STATUS_NAMES = {
    0x00: "No lock",  0x01: "Locked",   0x02: "Unlocked",
    0x06: "Locked — unlock blocked",    0x07: "No keys",
}


class WDECBDrive:
    """
    Live WD My Passport ~2012 ECB-protocol drive.
    Implements the same try_password(candidate) → bool interface as SimulatedDrive
    so the Cracker engine can use it directly.

    Each call to try_password() sends one unlock attempt to the physical drive.

    CAUTION: Wrong attempts consume the hardware counter (typically ~5 limit).
    For classroom demos: set a simple password that appears early in the wordlist.
    """

    def __init__(self, disk_id: str, iterations: int, salt: bytes,
                 pw_length: int, cipher_id: int = 0x20, hint: str = ""):
        self.disk_id       = disk_id
        self.iterations    = iterations
        self.salt          = salt
        self.pw_length     = pw_length
        self.cipher_id     = cipher_id
        self.hint          = hint
        self.attempt_count = 0
        self.wrong_count   = 0
        self.locked        = True

    @property
    def salt_hex(self) -> str:
        return self.salt.hex().upper()

    @property
    def cipher_name(self) -> str:
        return _CIPHER_NAMES.get(self.cipher_id, f"0x{self.cipher_id:02X}")

    def try_password(self, candidate: str) -> bool:
        self.attempt_count += 1
        key = derive_wd_ecb_key(candidate, self.iterations, self.salt)
        ok, _err = try_wd_ecb_unlock(self.disk_id, key, self.pw_length)
        if ok:
            self.locked = False
            return True
        self.wrong_count += 1
        return False

    def get_status(self) -> dict:
        return {
            "disk_id":     self.disk_id,
            "locked":      self.locked,
            "attempts":    self.attempt_count,
            "wrong":       self.wrong_count,
            "iterations":  self.iterations,
            "salt_hex":    self.salt_hex,
            "cipher":      self.cipher_name,
            "hint":        self.hint,
        }


# ── High-level drive interface ───────────────────────────────────────────────

def probe_drive_usb(vid: int, pid: int) -> dict:
    """
    Probe the WD drive's supported security protocols.
    Returns dict with keys: supported_protocols, wd_protocol_available, error
    """
    data, err = scsi_security_in_usb(vid, pid, 0x00, 0x00, 64)
    if err:
        return {"error": err}

    result = {"raw_hex": binascii.hexlify(data).decode(), "error": ""}
    if len(data) >= 7:
        list_len = data[6]
        supported = list(data[7:7 + list_len])
        result["supported_protocols"] = [f"0x{p:02x}" for p in supported]
        result["wd_protocol_available"] = WD_PROTOCOL_ID in supported
    else:
        result["supported_protocols"] = []
        result["wd_protocol_available"] = False
    return result


def get_challenge_usb(vid: int, pid: int,
                       disk_id: str = "") -> tuple[Optional[bytes], str]:
    """
    Read the 40-byte WD challenge block from a live USB drive.

    On Linux:  tries sg_raw (/dev/sgX) first, then pyusb.
    On macOS:  tries pyusb with disk unmount trick.

    Returns (challenge_bytes, error_string).
    """
    if sys.platform.startswith("linux"):
        # --- Linux: try every candidate device, stop on first success ---
        # sg_raw accepts both /dev/sdX and /dev/sgX paths directly.
        # Build a priority list: block device first, then type=0 sg, then all sg.
        candidates = []

        # 1. Block device path directly (most reliable — user told us it's /dev/sda)
        if disk_id and not disk_id.startswith("disk"):
            candidates.append(f"/dev/{disk_id}")

        # 2. sg device derived from block device via sysfs
        if disk_id and not disk_id.startswith("disk"):
            sg = _sg_for_block_device(disk_id)
            if sg and sg not in candidates:
                candidates.append(sg)

        # 3. Type=0 (disk) sg devices matching VID
        for sg_name, dev_type in _all_sg_for_vid(vid):
            path = f"/dev/{sg_name}"
            if dev_type == 0 and path not in candidates:
                candidates.append(path)

        # 4. Any sg devices matching VID (CD-ROMs last resort)
        for sg_name, dev_type in _all_sg_for_vid(vid):
            path = f"/dev/{sg_name}"
            if path not in candidates:
                candidates.append(path)

        errors      = []   # full error strings (for all_illegal check)
        errors_disp = []   # first-line only (for display in UI)
        for device in candidates:
            data, err = get_challenge_sgraw(device)
            if not err:
                return data, ""
            errors.append(err)                        # full multi-line stderr
            errors_disp.append(f"{device}: {err.splitlines()[0]}")

        if not candidates:
            errors.append(f"No sg/block device found for VID=0x{vid:04X}")
            errors_disp.append(errors[-1])

        # If ALL devices returned "Illegal Request / Invalid command operation code"
        # OR "Check Condition" (rc=9) — sg_raw exit code 9 = SCSI Check Condition —
        # the opcode is not supported; try the WD ECB proprietary protocol instead.
        def _is_unsupported(e: str) -> bool:
            return ("Invalid command operation code" in e
                    or "Illegal Request" in e
                    or "Check Condition" in e
                    or "rc=9" in e)

        all_illegal = bool(errors) and all(_is_unsupported(e) for e in errors)
        if all_illegal:
            # Try WD proprietary ECB opcode 0xC0 (works on ~2012 drives like 0748)
            wd_status, wd_err = get_wd_ecb_status(disk_id)
            if wd_status and not wd_err:
                # WD ECB protocol confirmed → return sentinel so hash_panel
                # can call get_wd_ecb_challenge() and build a WDECBDrive
                return None, "WD_ECB_DETECTED"

            # If WD ECB also failed, try ATA Security via hdparm
            if shutil.which("hdparm"):
                ata = get_ata_security_status(disk_id)
                if ata.get("supported") or ata.get("enabled") or ata.get("locked"):
                    return None, "ATA_SECURITY_DETECTED"

            return None, "WD_PROPRIETARY_DETECTED"

        return None, "All extraction attempts failed:\n" + "\n".join(errors_disp)

    else:
        # --- macOS / other: pyusb with unmount trick ---
        return scsi_security_in_usb(
            vid, pid, WD_PROTOCOL_ID, WD_PAGE_CHALLENGE, 40, disk_id=disk_id)


def parse_challenge(data: bytes) -> dict:
    """
    Parse the 40-byte WD challenge block:
      Bytes 0–3:  iteration count (big-endian uint32)
      Bytes 4–7:  flags
      Bytes 8–39: 32-byte PBKDF2 salt
    """
    if len(data) < 40:
        return {"error": f"Challenge data too short ({len(data)} bytes, need 40)"}
    iterations = struct.unpack(">I", data[0:4])[0] or WD_PBKDF2_ITERATIONS
    flags      = struct.unpack(">I", data[4:8])[0]
    salt       = data[8:40]
    return {
        "iterations": iterations,
        "flags":      flags,
        "salt":       salt,
        "salt_hex":   binascii.hexlify(salt).decode(),
    }


# ── Get USB VID/PID for a disk identifier ───────────────────────────────────

def get_usb_ids_for_disk(disk_id: str) -> tuple[Optional[int], Optional[int]]:  # noqa: E501
    """
    Given a disk identifier like 'disk4', return (VID, PID) via ioreg.
    Returns (None, None) if not found.
    """
    if sys.platform.startswith("linux"):
        # Linux: use udevadm
        try:
            result = subprocess.run(
                ["udevadm", "info", "--query=all", f"--name=/dev/{disk_id}"],
                capture_output=True, text=True, timeout=5)
            vid = pid = None
            for line in result.stdout.splitlines():
                if "ID_VENDOR_ID=" in line:
                    vid = int(line.split("=", 1)[1].strip(), 16)
                if "ID_MODEL_ID=" in line:
                    pid = int(line.split("=", 1)[1].strip(), 16)
            return vid, pid
        except Exception:
            return None, None
    else:
        # macOS: use ioreg
        try:
            result = subprocess.run(
                ["ioreg", "-r", "-c", "IOUSBDevice", "-l"],
                capture_output=True, text=True, timeout=5)
            vid, pid = None, None
            in_wd_block = False
            for line in result.stdout.splitlines():
                if '"idVendor" = 4184' in line:
                    in_wd_block = True
                    vid = WD_VID
                if in_wd_block and '"idProduct"' in line:
                    try:
                        pid = int(line.split("=")[1].strip())
                        break
                    except (ValueError, IndexError):
                        pass
            return vid, pid
        except Exception:
            return None, None


# ── Simulation drive ─────────────────────────────────────────────────────────

class SimulatedDrive:
    """
    In-memory WD My Passport simulation for classroom demos.
    No real drive or root access required.
    """

    def __init__(self, password: str = "password123",
                 model: str = "WD My Passport 25E2"):
        self.password  = password
        self.model     = model
        # Fixed salt so the demo is reproducible across runs
        self.salt      = bytes.fromhex(
            "a3f1c2d4e5b6078192a3b4c5d6e7f8091a2b3c4d5e6f70819293a4b5c6d7e8f9"
        )[:32]
        self.iterations    = WD_PBKDF2_ITERATIONS
        self.correct_key   = derive_wd_key(password, self.salt, self.iterations)
        self.locked        = True
        self.attempt_count = 0

    @property
    def challenge(self) -> bytes:
        return struct.pack(">II", self.iterations, 0x00000001) + self.salt

    def try_password(self, candidate: str) -> bool:
        self.attempt_count += 1
        key = derive_wd_key(candidate, self.salt, self.iterations)
        if key == self.correct_key:
            self.locked = False
            return True
        return False

    def get_status(self) -> dict:
        return {
            "model":         self.model,
            "locked":        self.locked,
            "attempt_count": self.attempt_count,
            "salt_hex":      binascii.hexlify(self.salt).decode(),
            "iterations":    self.iterations,
        }


def make_demo_drive(password: str = "password123") -> SimulatedDrive:
    return SimulatedDrive(password=password)
