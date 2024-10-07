use std::ops::Deref;

use async_trait::async_trait;

use crate::{
    error::WebauthnCError,
    nfc::{select_by_df_name, transmit, ISO7816LengthForm, ISO7816RequestAPDU},
    transport::yubikey::{YubiKeyConfig, YubiKeyToken},
};

use super::{NFCCard, APPLET_DF};

pub const APPLET_MGMT: [u8; 8] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

const GET_CONFIG_APDU: ISO7816RequestAPDU = ISO7816RequestAPDU {
    cla: 0x00,
    ins: 0x1D,
    p1: 0x00,
    p2: 0x00,
    data: vec![],
    ne: 256,
};

#[async_trait]
impl YubiKeyToken for NFCCard {
    async fn get_yubikey_config(&mut self) -> Result<YubiKeyConfig, WebauthnCError> {
        let guard = self.card.lock()?;
        
        // Select the YubiKey management applet.
        let mut resp = transmit(
            guard.deref(),
            &select_by_df_name(&APPLET_MGMT),
            &ISO7816LengthForm::ShortOnly,
        )?;

        if !resp.is_ok() {
            error!("Error selecting YubiKey management applet: {:02x} {:02x}", resp.sw1, resp.sw2);
            return Err(WebauthnCError::NotSupported);
        }

        // Transmit the APDU to get the YubiKey Config.
        resp = transmit(
            guard.deref(),
            &GET_CONFIG_APDU,
            &ISO7816LengthForm::ShortOnly,
        )?;

        if !resp.is_ok() {
            error!("Error getting YubiKey config: {:02x} {:02x}", resp.sw1, resp.sw2);
            return Err(WebauthnCError::NotSupported);
        }

        // Re-select the FIDO applet; this should not fail since the card was
        // already initialized successfully.
        transmit(
            guard.deref(),
            &select_by_df_name(&APPLET_DF),
            &ISO7816LengthForm::ShortOnly,
        )?;

        YubiKeyConfig::from_bytes(resp.data.as_slice())
    }
}
