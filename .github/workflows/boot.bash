#!/bin/bash

set -o pipefail

TIMEOUT=60
TMPFILE=$(mktemp)

HEYSTACK=(
  "Starting syslogd: OK"
  "Starting klogd: OK"
  "Running sysctl: OK"
  "seedrng: applet not found"
)

function check_success()
{
  ret=0

  for needle in "${HEYSTACK[@]}"; do
    if ! grep -qF -- "$needle" "$TMPFILE"; then
      echo "[ERROR] Missing: '$needle'"
      ret=1
    fi
  done

  return $ret
}

function cleanup()
{
  rm -f "$TMPFILE"
  set +o pipefail
}

echo "[+] stdout/stderr will be saved to $TMPFILE"

echo "[+] Running Norn on QEMU..."
timeout --foreground $TIMEOUT  \
qemu-system-x86_64 \
  -m 512M \
  -bios /usr/share/ovmf/OVMF.fd \
  -drive file=fat:rw:zig-out/img,format=raw \
  -nographic \
  -serial mon:stdio \
  -no-reboot \
  -cpu host \
  -enable-kvm \
  2>&1 \
| tee "$TMPFILE"

ret=$?

echo ""

if [ $ret -eq 124 ]; then
  echo "[-] Timeout."
fi

echo "[+] Checking output..."
if ! check_success; then
  echo "[ERROR] Output does not contain expected strings."
  cleanup
  exit 1
fi
echo "[+] All expected strings found."

cleanup
