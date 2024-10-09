use async_trait::async_trait;

#[cfg(all(feature = "usb", feature = "vendor-yubikey"))]
use crate::transport::yubikey::CMD_GET_CONFIG;

use crate::{
    prelude::WebauthnCError,
    transport::{
        types::{U2FError, U2FHID_ERROR},
        yubikey::{YubiKeyConfig, YubiKeyToken},
    },
    usb::{framing::U2FHIDFrame, USBToken},
};

#[async_trait]
impl YubiKeyToken for USBToken {
    async fn get_yubikey_config(&mut self) -> Result<YubiKeyConfig, WebauthnCError> {
        let mut yubikey_config = YubiKeyConfig::new();
        let mut page = 0;
        let mut more_data = true;

        while more_data {
            let cmd = U2FHIDFrame {
                cid: self.cid,
                cmd: CMD_GET_CONFIG,
                len: 1,
                data: vec![page],
            };
            self.send_one(&cmd).await?;

            let r = self.recv().await?;
            match r.cmd {
                CMD_GET_CONFIG => {
                    match yubikey_config.add_from_bytes(r.data.as_slice())? {
                        true => page += 1,
                        false => more_data = false,
                    }
                },
                U2FHID_ERROR => return Err(U2FError::from(r.data.as_slice()).into()),
                _ => return Err(WebauthnCError::UnexpectedState),
            }
        }

        Ok(yubikey_config)
    }
}
