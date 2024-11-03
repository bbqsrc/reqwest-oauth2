use async_trait::async_trait;
use http::{Extensions, HeaderValue};
use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenResponse,
};
use oauth2::{Client, EndpointMaybeSet, StandardRevocableToken, TokenResponse};
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result};
use std::sync::Arc;
use tokio::sync::RwLock;

type MaybeClient = Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointMaybeSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[async_trait]
pub trait TokenStorage {
    async fn get(&self) -> Option<BasicTokenResponse>;
    async fn set(&self, token: BasicTokenResponse) -> std::result::Result<(), anyhow::Error>;
}

pub struct OAuth2Middleware {
    client: MaybeClient,
    storage: Arc<RwLock<dyn TokenStorage + Sync + Send>>,
}

#[async_trait::async_trait]
impl Middleware for OAuth2Middleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        let guard = self.storage.read().await;

        let Some(record) = guard.get().await else {
            let res = next.run(req, extensions).await;
            return res;
        };

        drop(guard);

        if let Some(expires_in) = record.expires_in() {
            if expires_in.as_secs() < 60 {
                if let Some(refresh_token) = record.refresh_token() {
                    let http_client = reqwest::ClientBuilder::new()
                        // Following redirects opens the client up to SSRF vulnerabilities.
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .expect("Client should build");

                    let new_token = self
                        .client
                        .exchange_refresh_token(&refresh_token)
                        .unwrap()
                        .request_async(&http_client)
                        .await
                        .map_err(|e| anyhow::Error::new(e))?;

                    // Update the authorization header with the new access token.
                    let h = req.headers_mut();
                    h.insert(
                        http::header::AUTHORIZATION,
                        HeaderValue::from_str(&format!(
                            "Bearer {}",
                            new_token.access_token().secret()
                        ))
                        .expect("valid bearer token"),
                    );

                    self.storage
                        .write()
                        .await
                        .set(new_token)
                        .await
                        .expect("Failed to update token");
                }
            }
        } else {
            let h = req.headers_mut();
            h.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", record.access_token().secret()))
                    .expect("valid bearer token"),
            );
        }

        let res = next.run(req, extensions).await;
        res
    }
}
