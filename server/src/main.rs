#[allow(type_alias_bounds)]
use serde::{Deserialize, Serialize};
use serde_json::json;
use tide::{Body, Request, Response, Result, StatusCode};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use std::collections::HashMap;

use async_std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use rand::prelude::*;

const BCRYPT_COST: u32 = 12;
const JWT_SECRET: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const SITE_ID: &str = "localhost";
const SITE_URL: &str = "http://localhost:80";

lazy_static! {
    static ref WEBAUTHN: Webauthn = {
        let rp_origin = Url::parse(SITE_URL).expect("Invalid URL");
        let builder = WebauthnBuilder::new(SITE_ID, &rp_origin).expect("Invalid configuration");
        let builder = builder.rp_name("LocalHost");
        builder.build().expect("Invalid configuration")
    };
}

pub trait Identifiable {
    type Id: Eq + std::hash::Hash;
}

#[derive(Clone, Debug)]
pub struct User {
    id: Uuid,
    email: String,
    pw_hash: String,
    keys: Vec<SecurityKey>,
    key_reg_state: Option<SecurityKeyRegistration>,
    key_auth_state: Option<SecurityKeyAuthentication>,
    status: VerificationStatus,
}

impl User {
    fn new(email: String, password: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            email,
            pw_hash: bcrypt::hash(password, BCRYPT_COST).unwrap(),
            status: VerificationStatus::Unverified {
                code: thread_rng().gen_range(100000..999999),
            },
            keys: vec![],
            key_reg_state: None,
            key_auth_state: None,
        }
    }
}

impl Identifiable for User {
    type Id = Uuid;
}

#[derive(Clone, Debug, PartialEq)]
pub enum VerificationStatus {
    Verified,
    Unverified { code: u32 },
}

pub type Store<K, V> = Arc<Mutex<HashMap<K, V>>>;

#[derive(Clone, Debug)]
pub struct State {
    users: Store<<User as Identifiable>::Id, User>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

mod middleware {
    use super::State;
    use futures::Future;
    use std::pin::Pin;
    use tide::{Next, Request, StatusCode};

    pub fn authenticated<'a>(
        mut request: Request<State>,
        next: Next<'a, State>,
    ) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
        Box::pin(async {
            let token = match request.header(tide::http::headers::AUTHORIZATION) {
                Some(token) => token.as_str().trim_start_matches("Bearer ").to_string(),
                None => return Ok(StatusCode::Unauthorized.into()),
            };

            let user = match crate::auth::jwt::verify(token) {
                Ok(id) => {
                    let users = request.state().users.lock().await;
                    match users.get(&id) {
                        Some(user) => user.clone(),
                        None => return Ok(StatusCode::Gone.into()),
                    }
                }
                Err(err) => {
                    log::debug!("jwt error: {:?}", err);
                    return Ok(StatusCode::Unauthorized.into());
                }
            };

            request.set_ext(user);

            Ok(next.run(request).await)
        })
    }
}

mod auth {
    use super::*;

    pub mod jwt {
        use crate::JWT_SECRET;
        use chrono::{Duration, Utc};
        use jsonwebtoken::*;
        use serde::{Deserialize, Serialize};
        use uuid::Uuid;

        #[derive(Debug, Serialize, Deserialize)]
        pub struct Claims {
            sub: Uuid,
            exp: usize,
        }

        pub fn issue(sub: Uuid) -> String {
            encode(
                &Header::default(),
                &Claims {
                    sub,
                    exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
                },
                &EncodingKey::from_secret(&JWT_SECRET),
            )
            .unwrap()
        }

        pub fn verify(token: String) -> Result<Uuid, jsonwebtoken::errors::Error> {
            decode::<Claims>(
                &token,
                &DecodingKey::from_secret(&JWT_SECRET),
                &Validation::default(),
            )
            .map(|t| t.claims.sub)
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Credentials {
        email: String,
        password: String,
    }

    pub async fn signup(mut request: Request<State>) -> Result {
        let Credentials { email, password } = request.body_json().await?;
        log::info!("signup user {}", email);

        let mut users = request.state().users.lock().await;

        if let Some(_) = users.values().find(|user| user.email == email) {
            return Ok(StatusCode::Forbidden.into());
        }

        let user = User::new(email, password);

        log::info!("created {:#?}", user);
        users.insert(user.id, user.clone());

        Ok(Response::builder(StatusCode::Created)
            .body(Body::from_json(&UserDetails::new(&user))?)
            .build())
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct Verification {
        code: u32,
    }

    pub async fn verify(mut request: tide::Request<State>) -> tide::Result {
        let user = request
            .ext::<User>()
            .expect("User needs to be present by middleware")
            .clone();

        let Verification { code: provided } = request.body_json().await?;

        match user.status {
            VerificationStatus::Unverified { code } if code == provided => {
                let mut users = request.state().users.lock().await;

                users
                    .entry(user.id)
                    .and_modify(|user| user.status = VerificationStatus::Verified);

                Ok(StatusCode::Ok.into())
            }
            _ => Ok(StatusCode::Forbidden.into()),
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct UserDetails {
        token: String,
        verified: bool,
        keys: Vec<String>,
    }

    impl UserDetails {
        pub fn new(user: &User) -> Self {
            Self {
                token: jwt::issue(user.id),
                verified: user.status == VerificationStatus::Verified,
                keys: user
                    .keys
                    .clone()
                    .iter()
                    .map(|k| k.cred_id().to_string())
                    .collect(),
            }
        }
    }

    pub async fn login(mut request: Request<State>) -> Result {
        let Credentials { email, password } = request.body_json().await?;

        log::info!("login user {}", email);

        let mut users = request.state().users.lock().await;

        let user = users.values().find(|user| user.email == email);
        let user = match user {
            Some(user) => user.clone(),
            None => return Ok(StatusCode::BadRequest.into()),
        };

        if !bcrypt::verify(password, &user.pw_hash).unwrap() {
            log::warn!("wrong password");
            return Ok(StatusCode::BadRequest.into());
        }

        if !user.keys.is_empty() {
            log::info!("user has security keys registered");

            let res = match WEBAUTHN.start_securitykey_authentication(&user.keys) {
                Ok((rcr, status)) => {
                    log::info!("created challenge");

                    users
                        .entry(user.id)
                        .and_modify(|user| user.key_auth_state = Some(status));

                    Response::builder(StatusCode::Ok)
                        .body(Body::from_json(&rcr)?)
                        .build()
                }
                Err(e) => {
                    dbg!(e);
                    StatusCode::BadRequest.into()
                }
            };

            return Ok(res);
        }

        Ok(Response::builder(StatusCode::Ok)
            .body(Body::from_json(&UserDetails::new(&user))?)
            .build())
    }

    pub mod fido2 {
        use super::*;
        use crate::WEBAUTHN;

        pub async fn create_challenge(request: Request<State>) -> Result {
            let user = request
                .ext::<User>()
                .expect("User needs to be present by middleware");

            let exclude_credentials = user
                .keys
                .iter()
                .map(|sk| sk.cred_id().clone())
                .collect::<Vec<_>>();

            let res = match WEBAUTHN.start_securitykey_registration(
                &user.id.as_hyphenated().to_string(),
                Some(&user.email),
                Some(exclude_credentials),
                None,
            ) {
                Ok((ccr, state)) => {
                    let mut users = request.state().users.lock().await;

                    users
                        .entry(user.id)
                        .and_modify(|user| user.key_reg_state = Some(state));

                    Response::builder(tide::StatusCode::Ok)
                        .body(Body::from_json(&ccr)?)
                        .build()
                }
                Err(_) => StatusCode::BadRequest.into(),
            };

            Ok(res)
        }

        pub async fn store_key(mut request: Request<State>) -> Result {
            let user = request
                .ext::<User>()
                .expect("User needs to be present by middleware")
                .clone();

            let reg = request.body_json::<RegisterPublicKeyCredential>().await?;

            let state = match user.key_reg_state {
                Some(state) => state,
                None => return Ok(StatusCode::Forbidden.into()),
            };

            let res = match WEBAUTHN.finish_securitykey_registration(&reg, &state) {
                Ok(key) => {
                    let mut users = request.state().users.lock().await;

                    users.entry(user.id).and_modify(|user| {
                        user.keys.push(key.clone());
                        user.key_reg_state = None;
                    });

                    Response::builder(StatusCode::Created)
                        .body(json!({ "id": key.cred_id() }))
                        .build()
                }
                Err(e) => {
                    dbg!(e);
                    StatusCode::BadRequest.into()
                }
            };

            Ok(res)
        }

        pub async fn remove_key(request: Request<State>) -> Result {
            let user = request
                .ext::<User>()
                .expect("User needs to be present by middleware")
                .clone();

            let id = request.param("id").unwrap();

            if user
                .keys
                .iter()
                .find(|k| k.cred_id().to_string() == id)
                .is_none()
            {
                return Ok(StatusCode::NotFound.into());
            }

            let mut users = request.state().users.lock().await;

            users.entry(user.id).and_modify(|user| {
                user.keys = user
                    .keys
                    .iter()
                    .filter(|k| k.cred_id().to_string() != id)
                    .cloned()
                    .collect()
            });

            Ok(StatusCode::Ok.into())
        }

        pub async fn login(mut request: Request<State>) -> Result {
            let auth = request.body_json::<PublicKeyCredential>().await?;

            let users = request.state().users.lock().await;

            let user = users
                .values()
                .find(|user| {
                    if let Some(status) = user.key_auth_state.clone() {
                        let json = serde_json::to_value(&status).unwrap();
                        let credential_ids: Vec<String> = json["ast"]["credentials"]
                            .as_array()
                            .unwrap()
                            .into_iter()
                            .map(|v| v["cred_id"].as_str().unwrap().to_owned())
                            .collect();

                        return credential_ids.contains(&auth.id);
                    }

                    false
                })
                .clone();

            if user.is_none() {
                return Ok(StatusCode::BadRequest.into());
            }

            let user = user.unwrap().clone();
            drop(users);

            if user.key_auth_state.is_none() {
                return Ok(StatusCode::BadRequest.into());
            }

            let res = match WEBAUTHN
                .finish_securitykey_authentication(&auth, &user.key_auth_state.clone().unwrap())
            {
                Ok(auth_result) => {
                    let mut users = request.state().users.lock().await;

                    users.entry(user.id).and_modify(|user| {
                        user.keys.iter_mut().for_each(|sk| {
                            if sk.cred_id() == &auth_result.cred_id {
                                sk.update_credential_counter(auth_result.counter)
                            }
                        });
                        user.key_auth_state = None;
                    });

                    Response::builder(StatusCode::Ok)
                        .body(Body::from_json(&UserDetails::new(&user))?)
                        .build()
                }
                Err(e) => {
                    log::debug!("{:?}", e);
                    StatusCode::BadRequest.into()
                }
            };

            Ok(res)
        }
    }
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    simple_logger::SimpleLogger::default()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    use tide::http::headers::HeaderValue;
    use tide::security::{CorsMiddleware, Origin};

    let cors = CorsMiddleware::new()
        .allow_methods("GET, POST, DELETE, OPTIONS".parse::<HeaderValue>().unwrap())
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);

    let mut app = tide::with_state(State::default());

    app.with(tide::log::LogMiddleware::new());
    app.with(cors);

    app.at("/auth/login").post(auth::login);
    app.at("/auth/signup").post(auth::signup);
    app.at("/auth/verify")
        .with(middleware::authenticated)
        .post(auth::verify);

    app.at("/auth/fido2/login").post(auth::fido2::login);
    app.at("/auth/fido2/challenges")
        .with(middleware::authenticated)
        .post(auth::fido2::create_challenge);
    app.at("/auth/fido2/keys")
        .with(middleware::authenticated)
        .post(auth::fido2::store_key);
    app.at("/auth/fido2/keys/:id")
        .with(middleware::authenticated)
        .delete(auth::fido2::remove_key);

    app.listen("127.0.0.1:8080").await?;

    Ok(())
}
