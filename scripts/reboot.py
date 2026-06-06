#!/usr/bin/env python3
# Reboot a Precursor over USB WITHOUT flashing: load the CSR map, hold the CPU in
# reset, then release it — the same halt()/unhalt() cycle usb_update.py runs at the
# end of a flash. Run via scripts/reboot.sh (sets the libusb path on NixOS).
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "xous-core", "tools"))
import usb.core
from usb_update import PrecursorUsb

dev = usb.core.find(idProduct=0x5BF0, idVendor=0x1209)
if dev is None:
    print("Precursor not found (1209:5bf0). Is it plugged in / in updater mode?")
    sys.exit(1)

dev.set_configuration()
pc = PrecursorUsb(dev)
pc.load_csrs()
print("SoC gitrev: {}".format(pc.gitrev))
print("Rebooting (halt -> unhalt)...")
pc.halt()
pc.unhalt()
print("Done. The USB core was reset; unplug/replug before running more USB commands.")
