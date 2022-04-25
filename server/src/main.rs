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
const JWT_SECRET: [u8; 0] = [];
const SITE_ID: &str = "localhost";
const SITE_URL: &str = "http://localhost:8080";

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
    keys: Option<Vec<SecurityKey>>,
    reg_state: Option<SecurityKeyRegistration>,
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
            keys: None,
            reg_state: None,
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
    use super::{State, User, VerificationStatus};
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

    pub fn verified<'a>(
        request: Request<State>,
        next: Next<'a, State>,
    ) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
        Box::pin(async {
            let user = request
                .ext::<User>()
                .expect("User needs to be present to check verification status");

            if user.status != VerificationStatus::Verified {
                return Ok(StatusCode::Forbidden.into());
            }

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

        log::debug!("before bcrypt");
        let user = User::new(email, password);
        let id = user.id;
        log::debug!("after bcrypt");

        log::info!("created {:#?}", user);
        users.insert(user.id, user);

        Ok(Response::builder(StatusCode::Created)
            .body(json!({ "token": jwt::issue(id) }))
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
                log::debug!("{:#?}", users);
                Ok(StatusCode::Ok.into())
            }
            _ => Ok(StatusCode::Forbidden.into()),
        }
    }

    pub async fn login(mut request: Request<State>) -> Result {
        let Credentials { email, password } = request.body_json().await?;
        log::info!("login user {}", email);

        let users = request.state().users.lock().await;

        let user = users.values().find(|user| user.email == email);
        let user = match user {
            Some(user) => user.clone(),
            None => return Ok(StatusCode::NotFound.into()),
        };

        if user.pw_hash != bcrypt::hash(password, BCRYPT_COST).unwrap() {
            return Ok(StatusCode::BadRequest.into());
        }

        if let Some(_) = user.keys {
            log::info!("user has security keys registered");
            return Ok(StatusCode::InternalServerError.into());
        }

        Ok(Response::builder(StatusCode::Ok)
            .body(json!({ "token": jwt::issue(user.id) }))
            .build())
    }

    pub mod fido2 {
        use super::*;
        use crate::WEBAUTHN;

        pub async fn create_challenge(request: Request<State>) -> Result {
            let user = request
                .ext::<User>()
                .expect("User needs to be present by middleware");

            let res = match WEBAUTHN.start_securitykey_registration(
                &user.id.as_hyphenated().to_string(),
                None,
                None,
                None,
            ) {
                Ok((ccr, state)) => {
                    let mut users = request.state().users.lock().await;

                    users
                        .entry(user.id)
                        .and_modify(|user| user.reg_state = Some(state));

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

            let reg_state = match user.reg_state {
                Some(state) => state,
                None => return Ok(StatusCode::Forbidden.into()),
            };

            let res = match WEBAUTHN.finish_securitykey_registration(&reg, &reg_state) {
                Ok(key) => {
                    let mut users = request.state().users.lock().await;

                    users.entry(user.id).and_modify(|user| {
                        let mut keys = user.keys.take().unwrap_or(vec![]);
                        keys.push(key);
                        user.keys = Some(keys);
                    });

                    StatusCode::Created.into()
                }
                Err(e) => {
                    dbg!(e);
                    StatusCode::BadRequest.into()
                }
            };

            Ok(res)
        }
    }
}

// 5. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

#[allow(unused)]
async fn start_authentication(_: tide::Request<State>) -> tide::Result {
    //log::info!("Start Authentication");
    //// We get the username from the URL, but you could get this via form submission or
    //// some other process.
    //let username: String = request.param("username")?.parse()?;

    //// Remove any previous authentication that may have occured from the session.
    //let session = request.session_mut();
    //session.remove("auth_state");

    //// Get the set of keys that the user possesses
    //let users_guard = request.state().users.lock().await;
    //let allow_credentials = users_guard
    //.get(&username)
    //.map(|user| &user.keys)
    //.ok_or_else(|| tide::Error::new(400u16, anyhow::Error::msg("User has no credentials")))?;

    //let res = match WEBAUTHN.start_securitykey_authentication(allow_credentials) {
    //Ok((rcr, auth_state)) => {
    //// Drop the mutex to allow the mut borrows below to proceed
    //drop(users_guard);

    //request
    //.session_mut()
    //.insert("auth_state", auth_state)
    //.expect("Failed to insert");
    //request
    //.session_mut()
    //.insert("username", username)
    //.expect("Failed to insert");
    //tide::Response::builder(tide::StatusCode::Ok)
    //.body(tide::Body::from_json(&rcr)?)
    //.build()
    //}
    //Err(e) => {
    //log::debug!("challenge_authenticate -> {:?}", e);
    //tide::Response::builder(tide::StatusCode::BadRequest).build()
    //}
    //};
    //Ok(res)
    //
    Ok(StatusCode::InternalServerError.into())
}

// 6. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.

#[allow(unused)]
async fn finish_authentication(_: tide::Request<State>) -> tide::Result {
    //let auth = request.body_json::<PublicKeyCredential>().await?;

    //let session = request.session_mut();

    //let username: String = session
    //.get("username")
    //.ok_or_else(|| tide::Error::new(500u16, anyhow::Error::msg("Corrupt Session")))?;

    //let auth_state = session
    //.get("auth_state")
    //.ok_or_else(|| tide::Error::new(500u16, anyhow::Error::msg("Corrupt Session")))?;

    //session.remove("username");
    //session.remove("auth_state");

    //let res = match WEBAUTHN.finish_securitykey_authentication(&auth, &auth_state) {
    //Ok(auth_result) => {
    //let mut users_guard = request.state().users.lock().await;

    //// Update the credential counter, if possible.

    //users_guard
    //.get_mut(&username)
    //.map(|user| {
    //user.keys.iter_mut().for_each(|sk| {
    //if sk.cred_id() == &auth_result.cred_id {
    //sk.update_credential_counter(auth_result.counter)
    //}
    //})
    //})
    //.ok_or_else(|| {
    //tide::Error::new(400u16, anyhow::Error::msg("User has no credentials"))
    //})?;

    //tide::Response::builder(tide::StatusCode::Ok).build()
    //}
    //Err(e) => {
    //log::debug!("challenge_register -> {:?}", e);
    //tide::Response::builder(tide::StatusCode::BadRequest).build()
    //}
    //};

    //Ok(res)
    //
    Ok(StatusCode::InternalServerError.into())
}

// 7. That's it! The user has now authenticated!

// =======
// Below is glue/stubs that are needed to make the above work, but don't really affect
// the work flow too much.

async fn index_view(_request: tide::Request<State>) -> tide::Result {
    let mut res = tide::Response::new(200);
    res.set_content_type("text/html;charset=utf-8");
    res.set_body(
        r#"
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WebAuthn-rs Tutorial</title>

    <script type="module">
        import init, { run_app } from './pkg/wasm.js';
        async function main() {
           await init('./pkg/wasm_bg.wasm');
           run_app();
        }
        main()
    </script>
  </head>
  <body>
  </body>
</html>
    "#,
    );
    Ok(res)
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
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
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

    app.at("/auth/fido2/challenges")
        .with(middleware::authenticated)
        .with(middleware::verified)
        .post(auth::fido2::create_challenge);
    app.at("/auth/fido2/keys")
        .with(middleware::authenticated)
        .with(middleware::verified)
        .post(auth::fido2::store_key);

    //app.at("/auth/keys/verify").post(finish_register);

    //app.at("/auth/login/").post(start_authentication);
    //app.at("/auth/login/verify").post(finish_authentication);

    app.at("/").get(index_view);
    app.at("/*").get(index_view);

    log::info!("Spawning on http://localhost:8080");

    app.listen("127.0.0.1:8080").await?;

    Ok(())
}