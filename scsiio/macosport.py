import os
import re
import struct

import usb.core
import usb.util
import usb.backend.libusb1

from scsiio.common import SCSIDevBase, SCSIException

USB_VENDOR = 0x4c4a
USB_MSC_CLASS = 0x08
USB_MSC_SUBCLASS = 0x06
USB_BOT_PROTOCOL = 0x50
BOT_CBW_SIGNATURE = 0x43425355
BOT_CSW_SIGNATURE = 0x53425355
USB_TIMEOUT_MS = 5000


def _backend():
    library_path = os.environ.get('LIBUSB_LIBRARY')
    if library_path:
        backend = usb.backend.libusb1.get_backend(
            find_library=lambda _name: library_path)
    else:
        backend = usb.backend.libusb1.get_backend()
    if backend is None:
        raise ImportError(
            'libusb was not found; install it with Homebrew or set LIBUSB_LIBRARY')
    return backend


def _is_bot_interface(interface):
    return (interface.bInterfaceClass == USB_MSC_CLASS
            and interface.bInterfaceSubClass == USB_MSC_SUBCLASS
            and interface.bInterfaceProtocol == USB_BOT_PROTOCOL)


def _bulk_endpoints(interface):
    bulk_in = next((endpoint for endpoint in interface
                    if endpoint.bEndpointAddress & 0x80
                    and endpoint.bmAttributes & 0x03 == 0x02), None)
    bulk_out = next((endpoint for endpoint in interface
                     if not endpoint.bEndpointAddress & 0x80
                     and endpoint.bmAttributes & 0x03 == 0x02), None)
    if bulk_in is None or bulk_out is None:
        return None
    return bulk_in.bEndpointAddress, bulk_out.bEndpointAddress


def list_devices():
    """Return paths for JieLi USB Mass Storage Bulk-Only devices."""
    backend = _backend()
    paths = []
    devices = usb.core.find(find_all=True, idVendor=USB_VENDOR, backend=backend)
    for device in devices or ():
        try:
            configuration = device.get_active_configuration()
        except usb.core.USBError:
            continue
        if not any(_is_bot_interface(interface) and _bulk_endpoints(interface)
                   for interface in configuration):
            continue
        paths.append('usb:%04x:%04x:%s:%s' % (
            device.idVendor, device.idProduct, device.bus, device.address))
    return paths


class SCSIDev(SCSIDevBase):
    """USB Mass Storage SCSI transport using PyUSB and Bulk-Only Transport."""

    device_path = 'usb:4c4a:8057'

    def __init__(self, path=None):
        self._device = None
        self._interface_number = None
        self._bulk_in = None
        self._bulk_out = None
        self._kernel_driver_detached = False
        self._next_tag = 1
        super().__init__(path)

    def open(self, path=None):
        if self.is_open:
            return

        vendor_id, product_id, bus, address = self._parse_path(path)
        backend = _backend()
        candidates = list(usb.core.find(
            find_all=True, idVendor=vendor_id, idProduct=product_id, backend=backend) or ())
        if bus is not None:
            candidates = [device for device in candidates
                          if device.bus == bus and device.address == address]
        if not candidates:
            raise SCSIException('USB device %04x:%04x was not found' % (
                vendor_id, product_id))
        if len(candidates) != 1:
            raise SCSIException(
                'multiple USB devices match %04x:%04x; use a usb:VID:PID:BUS:ADDRESS path' % (
                    vendor_id, product_id))

        device = candidates[0]
        try:
            configuration = device.get_active_configuration()
        except usb.core.USBError as exc:
            raise SCSIException('could not read USB configuration: %s' % exc) from exc

        matches = [(interface, _bulk_endpoints(interface))
                   for interface in configuration if _is_bot_interface(interface)]
        matches = [(interface, endpoints) for interface, endpoints in matches
                   if endpoints is not None]
        if not matches:
            raise SCSIException('USB device has no Mass Storage Bulk-Only interface')
        if len(matches) != 1:
            raise SCSIException('USB device has multiple Bulk-Only interfaces')

        interface, endpoints = matches[0]
        detached = False
        try:
            try:
                active = device.is_kernel_driver_active(interface.bInterfaceNumber)
            except NotImplementedError:
                active = False
            if active:
                device.detach_kernel_driver(interface.bInterfaceNumber)
                detached = True
            usb.util.claim_interface(device, interface.bInterfaceNumber)
        except usb.core.USBError as exc:
            if detached:
                try:
                    device.attach_kernel_driver(interface.bInterfaceNumber)
                except (NotImplementedError, usb.core.USBError):
                    pass
            if getattr(exc, 'errno', None) == 13:
                raise PermissionError(
                    'USB access denied; retry with sudo or check macOS USB permissions') from exc
            raise SCSIException('could not claim USB interface %d: %s' % (
                interface.bInterfaceNumber, exc)) from exc

        self._device = device
        self._interface_number = interface.bInterfaceNumber
        self._bulk_in, self._bulk_out = endpoints
        self._kernel_driver_detached = detached
        self._next_tag = 1
        self.path = 'usb:%04x:%04x:%s:%s' % (
            device.idVendor, device.idProduct, device.bus, device.address)
        self.is_open = True

    @staticmethod
    def _parse_path(path):
        if path is None:
            path = SCSIDev.device_path
        match = re.fullmatch(
            r'usb:([0-9a-fA-F]{4}):([0-9a-fA-F]{4})(?::(\d+):(\d+))?', path)
        if not match:
            raise ValueError('USB device path must be usb:VID:PID[:BUS:ADDRESS]')
        vendor_id, product_id, bus, address = match.groups()
        return (int(vendor_id, 16), int(product_id, 16),
                int(bus) if bus is not None else None,
                int(address) if address is not None else None)

    def close(self):
        if not self.is_open:
            return
        try:
            usb.util.release_interface(self._device, self._interface_number)
        finally:
            if self._kernel_driver_detached:
                try:
                    self._device.attach_kernel_driver(self._interface_number)
                except (NotImplementedError, usb.core.USBError):
                    pass
            usb.util.dispose_resources(self._device)
            self._device = None
            self._interface_number = None
            self._bulk_in = None
            self._bulk_out = None
            self._kernel_driver_detached = False
            self.is_open = False

    def execute(self, cdb, data_out, data_in, max_sense_len=32, return_sense_buffer=False):
        del max_sense_len
        if not self.is_open or self._device is None:
            raise SCSIException('USB SCSI device is not open')
        out_bytes = bytes(data_out) if data_out else b''
        in_length = len(data_in) if data_in is not None else 0
        if out_bytes and in_length:
            raise ValueError('simultaneous SCSI data-out and data-in are unsupported')
        if len(cdb) == 0 or len(cdb) > 16:
            raise ValueError('SCSI CDB length must be between 1 and 16 bytes')

        transfer_length = len(out_bytes) if out_bytes else in_length
        tag = self._next_tag
        self._next_tag = (self._next_tag + 1) & 0xffffffff or 1
        cdb_bytes = bytes(cdb)
        cbw = struct.pack('<IIIBBB', BOT_CBW_SIGNATURE, tag, transfer_length,
                          0x80 if in_length else 0, 0, len(cdb_bytes))
        cbw += cdb_bytes.ljust(16, b'\x00')
        try:
            written = self._device.write(self._bulk_out, cbw, timeout=USB_TIMEOUT_MS)
            if written != len(cbw):
                raise SCSIException('short BOT command write: %d/%d bytes' % (
                    written, len(cbw)))

            transferred = 0
            if out_bytes:
                written = self._device.write(
                    self._bulk_out, out_bytes, timeout=USB_TIMEOUT_MS)
                if written != len(out_bytes):
                    raise SCSIException('short BOT data-out write: %d/%d bytes' % (
                        written, len(out_bytes)))
                transferred = written
            elif in_length:
                data = bytes(self._device.read(
                    self._bulk_in, in_length, timeout=USB_TIMEOUT_MS))
                transferred = len(data)
                if transferred > in_length:
                    raise SCSIException('USB returned more data than requested')
                data_in[:transferred] = data

            csw = bytes(self._device.read(self._bulk_in, 13, timeout=USB_TIMEOUT_MS))
        except usb.core.USBError as exc:
            raise SCSIException('USB BOT transfer failed: %s' % exc) from exc

        if len(csw) != 13:
            raise SCSIException('short BOT command status: %d/13 bytes' % len(csw))
        signature, returned_tag, residue, status = struct.unpack('<IIIB', csw)
        if signature != BOT_CSW_SIGNATURE or returned_tag != tag:
            raise SCSIException('invalid BOT command status signature/tag')
        if residue > transfer_length or transferred + residue != transfer_length:
            raise SCSIException('BOT transferred byte count does not match residue')
        if status != 0:
            raise SCSIException('SCSI command failed with BOT status %d' % status)
        if return_sense_buffer:
            return residue, b''
        return residue