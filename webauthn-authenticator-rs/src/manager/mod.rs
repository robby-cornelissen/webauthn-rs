use std::collections::HashMap;
use futures::StreamExt;

use crate::{prelude::WebauthnCError, transport::{AnyToken, AnyTransport, TokenEvent, Transport}};

pub struct TokenManager {
    tokens: HashMap<String, AnyToken>,
}

impl TokenManager {
    pub fn new() -> Result<Self, WebauthnCError> {
        Ok(TokenManager { tokens: HashMap::new() })
    }

    pub async fn manage(&mut self) {
        let watcher = AnyTransport::new().await.unwrap();

        match watcher.watch().await {
            Ok(mut tokens) => {
                while let Some(event) = tokens.next().await {
                    match event {
                        TokenEvent::Added(token_id, token) => {
                            println!("Added {}: {:?}", token_id, token);
                            
                            // Inserting an NFC card here will result in the token being
                            // exclusively locked...
                            // Should we store token info instead? Hmmm...
                            let _ = &self.tokens.insert(token_id.to_string(), token);
                        }

                        TokenEvent::EnumerationComplete => {
                            println!("Enumeration complete")
                        }

                        TokenEvent::Removed(token_id) => {
                            println!("Removed {:?}", token_id);
                        }
                    }
                }
            }
            Err(e) => panic!("Error: {e:?}"),
        };
    }
}
