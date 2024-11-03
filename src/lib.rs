use async_trait::async_trait;
use http::{Extensions, HeaderValue};
use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenResponse,
};
use oauth2::{Client, EndpointMaybeSet, StandardRevocableToken, TokenResponse};
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};
use std::sync::Arc;
use tokio::sync::RwLock;

pub type MaybeClient = Client<
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
    type Error: std::fmt::Debug + std::error::Error;

    async fn get(&self) -> Result<Option<BasicTokenResponse>, Self::Error>;
    async fn set(&self, token: BasicTokenResponse) -> std::result::Result<(), Self::Error>;
}

pub struct OAuth2Middleware<E> {
    pub client: MaybeClient,
    pub storage: Arc<RwLock<dyn TokenStorage<Error = E> + Sync + Send>>,
}

impl<E: std::fmt::Debug + std::error::Error + Send + Sync + 'static> OAuth2Middleware<E> {
    async fn bearer_token(&self) -> Result<Option<BasicTokenResponse>, anyhow::Error> {
        let guard = self.storage.read().await;

        let Some(record) = guard.get().await? else {
            return Ok(None);
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
                        .await?;

                    self.storage
                        .write()
                        .await
                        .set(new_token.clone())
                        .await
                        .expect("Failed to update token");

                    return Ok(Some(new_token));
                }
            }
        }

        Ok(Some(record))
    }
}

#[async_trait::async_trait]
impl<E: std::fmt::Debug + std::error::Error + Send + Sync + 'static> Middleware
    for OAuth2Middleware<E>
{
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let Some(token) = self
            .bearer_token()
            .await
            .map_err(|e| reqwest_middleware::Error::Middleware(e.into()))?
        else {
            let res = next.run(req, extensions).await;
            return res;
        };

        let h = req.headers_mut();
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token.access_token().secret()))
                .expect("valid bearer token"),
        );

        let res = next.run(req, extensions).await;
        res
    }
}
