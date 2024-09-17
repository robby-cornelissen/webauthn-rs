//! Linux [hidraw] USB HID implementation.
//!
//! [hidraw]: https://www.kernel.org/doc/Documentation/hid/hidraw.txt
mod wrapper;

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{Read, Write},
    mem::size_of,
    os::fd::AsRawFd,
    path::Path,
    time::Duration,
};

use async_trait::async_trait;
use futures::stream::BoxStream;
use nix::{
    poll::{ppoll, PollFd, PollFlags},
    sys::signalfd::SigSet,
};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, task::spawn_blocking};
use tokio_stream::wrappers::ReceiverStream;
use udev::{Device, Enumerator, EventType, MonitorBuilder};

use crate::{
    descriptors::is_fido_authenticator,
    traits::{USBDevice, USBDeviceInfo, USBDeviceManager, WatchEvent},
    HidError, HidReportBytes, HidSendReportBytes, Result,
};

use self::wrapper::{
    hid_ioc_raw_info, hid_ioc_rd_desc, hid_ioc_rd_desc_size, hidraw_devinfo,
    hidraw_report_descriptor, BusType, HID_MAX_DESCRIPTOR_SIZE,
};

#[derive(Debug)]
pub struct USBDeviceManagerImpl {}

#[async_trait]
impl USBDeviceManager for USBDeviceManagerImpl {
    type Device = USBDeviceImpl;
    type DeviceInfo = USBDeviceInfoImpl;
    type DeviceId = Box<Path>;

    async fn watch_devices(&self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>> {
        // udev only tells us about newly-connected devices, so we need to
        // explicitly look for any existing devices first!
        let existing_devices = self.get_devices().await?;

        // Our channel needs to be big enough to hold any existing devices *and*
        // the EnumerationComplete event without blocking, so that we make it
        // harder to miss something between get_devices() and
        // ppoll()'ing MonitorSocket. While it's unlikely someone will have
        // enough FIDO keys connected over USB to hit the default channel size,
        // we should still write this defensively.
        let (tx, rx) = mpsc::channel(16.max(existing_devices.len() + 2));

        // udev::MonitorSocket and tokio_udev::AsyncMonitorSocket are not
        // Send/Sync), so we have to use a thread and ppoll() the fd:
        // https://github.com/jeandudey/tokio-udev/issues/13
        spawn_blocking(move || {
            let monitor = match MonitorBuilder::new()
                .and_then(|b| b.match_subsystem("hidraw"))
                .and_then(|b| b.listen())
            {
                Ok(m) => m,
                Err(e) => {
                    error!("unable to create udev MonitorSocket: {e:?}");
                    return;
                }
            };

            // Keep a track of all known device paths, so we can notify only for
            // removed FIDO devices (rather than all removed HIDs).
            let mut known_devices = HashSet::new();

            for device in existing_devices {
                let id = device.path.to_owned();
                known_devices.insert(id.clone());

                if tx.blocking_send(WatchEvent::Added(id, device)).is_err() {
                    // Channel disappeared!
                    return;
                };
            }

            if tx.blocking_send(WatchEvent::EnumerationComplete).is_err() {
                // Channel disappeared!
                return;
            }

            let pollfd = PollFd::new(monitor.as_raw_fd(), PollFlags::POLLIN | PollFlags::POLLPRI);

            loop {
                // trace!("ppoll'ing for event");
                if let Err(e) = ppoll(
                    &mut [pollfd],
                    Some(Duration::from_secs(1).into()),
                    Some(SigSet::all()),
                ) {
                    error!("ppoll() failed: {e:?}");
                    return;
                }

                // No point in processing anything if the channel has gone away.
                if tx.is_closed() {
                    return;
                }

                for event in monitor.iter() {
                    // trace!("event: {event:?}");
                    let device = event.device();
                    match event.event_type() {
                        EventType::Add => {
                            match USBDeviceInfoImpl::new(&device) {
                                Some(i) => {
                                    let id = i.path.to_owned();
                                    known_devices.insert(id.clone());

                                    if tx.blocking_send(WatchEvent::Added(id, i)).is_err() {
                                        // Channel disappeared!
                                        return;
                                    }
                                }

                                // Not a FIDO device, ignore it.
                                None => continue,
                            };
                        }

                        EventType::Remove => {
                            if let Some(path) = device.devnode() {
                                if known_devices.remove(path) {
                                    // We knew this device once, notify watchers
                                    if tx.blocking_send(WatchEvent::Removed(path.into())).is_err() {
                                        // Channel disappeared!
                                        return;
                                    }
                                }
                            }
                        }

                        _ => (),
                    }
                }
            }
        });

        let stream: ReceiverStream<WatchEvent<USBDeviceInfoImpl>> = ReceiverStream::from(rx);
        Ok(Box::pin(stream))
    }

    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>> {
        let mut enumerator = Enumerator::new()?;
        enumerator.match_subsystem("hidraw")?;
        let devices = enumerator.scan_devices()?;
        let mut o = Vec::new();

        for device in devices {
            // trace!("device: {:?}", device);
            let info = match USBDeviceInfoImpl::new(&device) {
                Some(v) => v,
                None => continue,
            };
            o.push(info);
        }
        Ok(o)
    }

    async fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct USBDeviceInfoImpl {
    path: Box<Path>,
    vendor_id: u16,
    product_id: u16,
    version: Option<String>,
    manufacturer: Option<String>,
    product: Option<String>,
    name: Option<String>,
    serial: Option<String>,
}

impl USBDeviceInfoImpl {
    /// Try to open a [Device] as a USB HID FIDO token.
    ///
    /// Returns `None` on access errors (permissions), or if the device is not a
    /// USB HID FIDO token.
    fn new(device: &Device) -> Option<Self> {
        let path = device.devnode()?;
        let fd = match File::open(path) {
            Ok(fd) => fd,
            Err(e) => {
                // This isn't necessarily bad - raw HID access to other input
                // devices (eg: keyboards) may be blocked. But the udev rules
                // could be wrong, blocking FIDO tokens as well...
                warn!("cannot open {path:?}: {e}");
                return None;
            }
        };

        let mut info = hidraw_devinfo::default();
        unsafe {
            hid_ioc_raw_info(fd.as_raw_fd(), &mut info).ok()?;
        }

        // Drop unknown or non-USB BusTypes
        let bustype = BusType::from_u32(info.bustype);
        if bustype != Some(BusType::Usb) {
            // trace!(
            //     "{path:?} is not USB HID: {bustype:?} (0x{:x})",
            //     info.bustype
            // );
            return None;
        }

        let mut descriptor = hidraw_report_descriptor::default();
        unsafe {
            hid_ioc_rd_desc_size(fd.as_raw_fd(), &mut descriptor.size).ok()?;
            if descriptor.size < 1 {
                return None;
            }
            if descriptor.size > HID_MAX_DESCRIPTOR_SIZE {
                error!(
                    "HID descriptor exceeded maximum size ({} > {HID_MAX_DESCRIPTOR_SIZE})",
                    descriptor.size
                );
                return None;
            }
            hid_ioc_rd_desc(fd.as_raw_fd(), &mut descriptor).ok()?;
        }

        // trace!("raw descriptor: {}", hex::encode(descriptor.get_value()));
        if is_fido_authenticator(descriptor.get_value()) {
            // get additional information from the parent USB device
            let mut manufacturer: Option<String> = None;
            let mut product: Option<String> = None;
            let mut version: Option<String> = None;

            if let Ok(Some(usb_parent_device)) =
                device.parent_with_subsystem_devtype("usb", "usb_device")
            {
                manufacturer = attribute_as_string(&usb_parent_device, "manufacturer");
                product = attribute_as_string(&usb_parent_device, "product");
                version =
                    attribute_as_u16(&usb_parent_device, "bcdDevice").map(u16_to_version_string);
            }

            // get additional information from the parent HID device
            let mut name: Option<String> = None;
            let mut serial: Option<String> = None;

            if let Ok(Some(hid_parent_device)) = device.parent_with_subsystem("hid") {
                name = property_as_string(&hid_parent_device, "HID_NAME");
                serial = property_as_string(&hid_parent_device, "HID_UNIQ");
            }

            Some(USBDeviceInfoImpl {
                path: path.into(),
                // The userspace API lies: https://bugzilla.kernel.org/show_bug.cgi?id=217463
                vendor_id: info.vendor as u16,
                product_id: info.product as u16,
                version,
                manufacturer,
                product,
                name,
                serial,
            })
        } else {
            // trace!("{path:?} does not look like a FIDO authenticator");
            None
        }
    }
}

#[async_trait]
impl USBDeviceInfo for USBDeviceInfoImpl {
    type Device = USBDeviceImpl;
    type Id = Box<Path>;

    async fn open(self) -> Result<Self::Device> {
        let device = OpenOptions::new().read(true).write(true).open(&self.path)?;
        Ok(USBDeviceImpl { info: self, device })
    }
}

#[derive(Debug)]
pub struct USBDeviceImpl {
    info: USBDeviceInfoImpl,
    device: File,
}

#[async_trait]
impl USBDevice for USBDeviceImpl {
    type Info = USBDeviceInfoImpl;

    fn get_info(&self) -> &Self::Info {
        &self.info
    }

    async fn read(&mut self) -> Result<HidReportBytes> {
        // TODO: check for numbered reports?
        let mut o = [0; size_of::<HidReportBytes>()];
        let len = self.device.read(&mut o)?;
        if len != o.len() {
            error!("incomplete read: read {len} of {} bytes", o.len());
            Err(HidError::InvalidMessageLength)
        } else {
            Ok(o)
        }
    }

    async fn write(&mut self, data: HidSendReportBytes) -> Result<()> {
        let len = self.device.write(&data)?;
        if len != data.len() {
            error!("incomplete write: wrote {len} of {} bytes", data.len());
            Err(HidError::SendError)
        } else {
            Ok(())
        }
    }
}

fn property_as_string(device: &Device, property_name: &str) -> Option<String> {
    device
        .property_value(property_name)
        .and_then(OsStr::to_str)
        .map(str::to_string)
}

fn attribute_as_string(device: &Device, attribute_name: &str) -> Option<String> {
    device
        .attribute_value(attribute_name)
        .and_then(OsStr::to_str)
        .map(str::to_string)
}

fn attribute_as_u16(device: &Device, attribute_name: &str) -> Option<u16> {
    device
        .attribute_value(attribute_name)
        .and_then(OsStr::to_str)
        .and_then(|v| u16::from_str_radix(v, 16).ok())
}

/// Converts a BCD value of the format `0xJJMN` to a version string, where 
/// `JJ` represents the major version, `M` the minor version, and `N` the sub-minor version.
fn u16_to_version_string(u16: u16) -> String {
    let [major, minors] = u16.to_be_bytes();
    let minor = minors >> 4;
    let sub_minor = minors & 0x0F;

    format!("{major}.{minor}.{sub_minor}")
}
