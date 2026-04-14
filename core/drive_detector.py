"""
Drive Detector — macOS + Linux
Detects WD My Passport drives.
  macOS : uses diskutil + ioreg
  Linux : uses lsblk + udevadm
"""

from __future__ import annotations

import sys
import subprocess
import plistlib


WD_IDENTIFIERS = [
    "WD", "MY PASSPORT", "MYPASSPORT", "WESTERN DIGITAL",
    "WD ELEMENTS", "WD MY CLOUD", "MY BOOK", "WD UNLOCKER",
]


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, timeout=8)
    return r.stdout, r.returncode


def _run_text(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    return r.stdout.strip(), r.returncode


# ── diskutil helpers ─────────────────────────────────────────────────────────

def _all_disks_plist():
    raw, rc = _run(["diskutil", "list", "-plist"])
    if rc != 0:
        return []
    try:
        return plistlib.loads(raw).get("AllDisksAndPartitions", [])
    except Exception:
        return []


def _disk_info_plist(disk_id: str) -> dict:
    try:
        r = subprocess.run(
            ["diskutil", "info", "-plist", f"/dev/{disk_id}"],
            capture_output=True, timeout=4)   # short timeout — locked drives hang
        if r.returncode != 0:
            return {}
        return plistlib.loads(r.stdout)
    except (subprocess.TimeoutExpired, Exception):
        return {}


# ── ioreg USB lookup ─────────────────────────────────────────────────────────

def _ioreg_usb_devices() -> list[dict]:
    """
    Return a list of USB device dicts with keys:
      product_name, vendor_name, vid, pid, serial
    parsed from ioreg -r -c IOUSBDevice.
    """
    out, _ = _run_text(["ioreg", "-r", "-c", "IOUSBDevice", "-l"])
    devices = []
    current: dict = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("+-o") and current:
            devices.append(current)
            current = {}
        def _extract(key):
            if f'"{key}"' in line:
                try:
                    val = line.split("=", 1)[1].strip().strip('"')
                    return val
                except Exception:
                    pass
            return None

        for field, key in [
            ("product_name", "USB Product Name"),
            ("vendor_name",  "USB Vendor Name"),
            ("serial",       "USB Serial Number"),
        ]:
            v = _extract(key)
            if v:
                current[field] = v

        if '"idVendor"' in line:
            try:
                current["vid"] = int(line.split("=")[1].strip())
            except Exception:
                pass
        if '"idProduct"' in line:
            try:
                current["pid"] = int(line.split("=")[1].strip())
            except Exception:
                pass

    if current:
        devices.append(current)
    return devices


def _find_wd_usb():
    """Return the first WD USB device entry from ioreg, or None."""
    for dev in _ioreg_usb_devices():
        vid = dev.get("vid", 0)
        name = (dev.get("product_name", "") + " " +
                dev.get("vendor_name", "")).upper()
        if vid == 0x1058 or any(k in name for k in WD_IDENTIFIERS):
            return dev
    return None


# ── Drive identification ──────────────────────────────────────────────────────

def _is_wd_disk(disk_plist: dict, info: dict) -> bool:
    media   = (info.get("MediaName", "") or "").upper()
    io_name = (info.get("IORegistryEntryName", "") or "").upper()
    vendor  = (info.get("VendorID", "") or "").upper()
    # Also check partition names (catches "WD Unlocker" when locked)
    part_names = " ".join(
        (p.get("VolumeName", "") or "") for p in disk_plist.get("Partitions", [])
    ).upper()

    combined  = f"{media} {io_name} {vendor} {part_names}"
    protocol  = info.get("BusProtocol", "")
    removable = info.get("Removable", False) or info.get("RemovableMedia", False)
    external  = protocol in ("USB", "Thunderbolt") or removable

    return external and any(kw in combined for kw in WD_IDENTIFIERS)


def _build_entry(disk_id: str, info: dict, disk_plist: dict,
                 usb_dev: dict | None = None, locked: bool = False) -> dict:
    size_bytes = info.get("TotalSize", 0) or 0
    size_gb    = round(size_bytes / (1024 ** 3), 1) if size_bytes else 0

    # Prefer USB product name (more human-readable) over diskutil MediaName
    media_name = info.get("MediaName", "")
    if usb_dev and usb_dev.get("product_name"):
        media_name = usb_dev["product_name"]

    parts = [
        {
            "id":   p.get("DeviceIdentifier", ""),
            "type": p.get("Content", ""),
            "name": p.get("VolumeName", ""),
        }
        for p in disk_plist.get("Partitions", [])
    ]

    vid = usb_dev.get("vid") if usb_dev else None
    pid = usb_dev.get("pid") if usb_dev else None

    return {
        "disk_id":    disk_id,
        "device_path":  f"/dev/{disk_id}",
        "raw_device":   f"/dev/r{disk_id}",
        "media_name":   media_name or "WD My Passport",
        "io_name":      info.get("IORegistryEntryName", ""),
        "vendor":       info.get("VendorID", "Western Digital"),
        "protocol":     info.get("BusProtocol", "USB"),
        "size_gb":      size_gb,
        "size_bytes":   size_bytes,
        "locked":       locked,
        "security_status": "locked" if locked else "unknown",
        "partitions":   parts,
        "usb_vid":      vid,
        "usb_pid":      pid,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def detect_drives(include_all_external: bool = False) -> list[dict]:
    """
    Detect WD My Passport drives — dispatches to Linux or macOS implementation.
    """
    if sys.platform.startswith("linux"):
        return _detect_drives_linux(include_all_external)
    return _detect_drives_macos(include_all_external)


def _detect_drives_macos(include_all_external: bool = False) -> list[dict]:
    disks   = _all_disks_plist()
    usb_dev = _find_wd_usb()
    results = []
    seen    = set()

    for disk in disks:
        disk_id = disk.get("DeviceIdentifier", "")
        if not disk_id or disk_id in seen:
            continue
        seen.add(disk_id)

        info = _disk_info_plist(disk_id)
        if not info or not info.get("WholeDisk", False):
            continue

        is_wd     = _is_wd_disk(disk, info)
        protocol  = info.get("BusProtocol", "")
        removable = info.get("Removable", False) or info.get("RemovableMedia", False)

        if not is_wd and not (include_all_external and protocol == "USB" and removable):
            continue

        part_names = [p.get("VolumeName", "") for p in disk.get("Partitions", [])]
        locked = any("unlocker" in n.lower() for n in part_names) and size_ok(info)

        results.append(_build_entry(disk_id, info, disk, usb_dev, locked=locked))

    if not results and usb_dev:
        results.append(_synthesise_from_ioreg(usb_dev))

    return results


# ── Linux detection ───────────────────────────────────────────────────────────

def _detect_drives_linux(include_all_external: bool = False) -> list[dict]:
    """
    Detect USB drives on Linux using lsblk + udevadm.
    Identifies WD drives by USB vendor/model strings.
    """
    results = []
    try:
        out, rc = _run_text([
            "lsblk", "-J", "-o",
            "NAME,SIZE,TYPE,TRAN,VENDOR,MODEL,SERIAL,RM,RO,MOUNTPOINTS"
        ])
        if rc != 0:
            return []
        import json
        data = json.loads(out)
    except Exception:
        return []

    for dev in data.get("blockdevices", []):
        if dev.get("type") != "disk":
            continue
        if dev.get("tran") != "usb" and not dev.get("rm"):
            continue

        name   = dev.get("name", "")
        vendor = (dev.get("vendor") or "").strip()
        model  = (dev.get("model")  or "").strip()
        combined = f"{vendor} {model}".upper()

        is_wd = any(k in combined for k in WD_IDENTIFIERS)
        if not is_wd and not include_all_external:
            continue

        # Get USB VID/PID via udevadm
        vid, pid = _udevadm_usb_ids(name)

        size_str = dev.get("size", "0")
        size_bytes = _parse_size(size_str)

        children = dev.get("children") or []
        partitions = [
            {
                "id":   c.get("name", ""),
                "type": c.get("type", ""),
                "name": ",".join(c.get("mountpoints") or []),
            }
            for c in children
        ]

        # Determine lock state: if no mountable partitions and size is non-zero → likely locked
        mounted = any(c.get("mountpoints") for c in children)
        locked  = not mounted and size_bytes > 0

        results.append({
            "disk_id":       name,
            "device_path":   f"/dev/{name}",
            "raw_device":    f"/dev/{name}",
            "media_name":    f"{vendor} {model}".strip() or "WD My Passport",
            "io_name":       model,
            "vendor":        vendor,
            "protocol":      "USB",
            "size_gb":       round(size_bytes / (1024 ** 3), 1) if size_bytes else 0,
            "size_bytes":    size_bytes,
            "locked":        locked,
            "security_status": "locked" if locked else "unlocked",
            "partitions":    partitions,
            "usb_vid":       vid,
            "usb_pid":       pid,
        })

    return results


def _udevadm_usb_ids(dev_name: str) -> tuple:
    """Return (vid, pid) for a block device using udevadm."""
    try:
        out, rc = _run_text(["udevadm", "info", "--query=all", f"--name=/dev/{dev_name}"])
        if rc != 0:
            return None, None
        vid = pid = None
        for line in out.splitlines():
            if "ID_VENDOR_ID=" in line:
                vid = int(line.split("=", 1)[1].strip(), 16)
            if "ID_MODEL_ID=" in line:
                pid = int(line.split("=", 1)[1].strip(), 16)
        return vid, pid
    except Exception:
        return None, None


def _parse_size(s: str) -> int:
    """Parse lsblk size string like '931.5G' → bytes."""
    s = s.strip().upper()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    for suffix, mult in multipliers.items():
        if s.endswith(suffix):
            try:
                return int(float(s[:-1]) * mult)
            except ValueError:
                return 0
    try:
        return int(s)
    except ValueError:
        return 0


def size_ok(info: dict) -> bool:
    """True if total size is small (≤50 MB) — typical of the Unlocker CD."""
    sz = info.get("TotalSize", 0) or 0
    return 0 < sz <= 50 * 1024 * 1024


def _synthesise_from_ioreg(usb_dev: dict) -> dict:
    """Create a minimal drive entry from ioreg data when diskutil gives nothing."""
    return {
        "disk_id":    "disk?",
        "device_path":  "/dev/disk?",
        "raw_device":   "/dev/rdisk?",
        "media_name":   usb_dev.get("product_name", "WD My Passport"),
        "io_name":      usb_dev.get("product_name", ""),
        "vendor":       usb_dev.get("vendor_name", "Western Digital"),
        "protocol":     "USB",
        "size_gb":      0,
        "size_bytes":   0,
        "locked":       True,
        "security_status": "locked",
        "partitions":   [],
        "usb_vid":      usb_dev.get("vid"),
        "usb_pid":      usb_dev.get("pid"),
    }


# ── Simulation data ───────────────────────────────────────────────────────────

DEMO_DRIVES = [
    {
        "disk_id":    "disk9",
        "device_path":  "/dev/disk9",
        "raw_device":   "/dev/rdisk9",
        "media_name":   "WD My Passport 25E2 Media",
        "io_name":      "WD My Passport 25E2",
        "vendor":       "Western Digital",
        "protocol":     "USB",
        "size_gb":      931.5,
        "size_bytes":   1000204886016,
        "locked":       True,
        "security_status": "locked",
        "partitions":   [
            {"id": "disk9s1", "type": "EFI",                   "name": ""},
            {"id": "disk9s2", "type": "Microsoft Basic Data",  "name": "WD Passport"},
        ],
        "usb_vid": 0x1058,
        "usb_pid": 0x25E2,
        "_demo":   True,
    }
]
