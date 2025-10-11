#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use chrono::prelude::*;
use getrandom::getrandom;
use rocket::http::{Cookies, Status};
use rocket::request::Form;
use rocket::response::Redirect;
use rocket::State;
use rocket_contrib::templates::Template;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

mod config;
mod db;
mod lichess;
mod session;

use config::Config;
use db::{AcwcDbClient, Registration};
use session::Session;

fn context<'a>(maybe_session: &'a Option<Session>) -> HashMap<&'static str, &'a str> {
    let mut ctx: HashMap<&'static str, &'a str> = HashMap::new();
    if let Some(session) = maybe_session {
        ctx.insert("username", &session.lichess_username);
    }
    ctx
}

fn registration_state() -> i32 {
    let register_start = Utc.ymd(2025, 10, 10).and_hms(0, 0, 0);
    let register_end = Utc.ymd(2025, 10, 26).and_hms(23, 59, 59);
    let now = Utc::now();
    if now >= register_end {
        2 // registration ended
    } else if now >= register_start {
        1 // registration open
    } else {
        0 // registration not yet open
    }
}

#[get("/")]
fn home(
    maybe_session: Option<Session>,
    db_client: State<AcwcDbClient>,
) -> Result<Template, Box<dyn std::error::Error>> {
    match registration_state() {
        0 => Ok(Template::render("home", &context(&maybe_session))),
        r => {
            if let Some(session) = &maybe_session {
                let maybe_registration = db_client.find_registration(&session.lichess_id)?;
                if let Some(registration) = maybe_registration {
                    let mut ctx = context(&maybe_session);
                    ctx.insert(
                        "registration_status",
                        match registration.status {
                            db::STATUS_PENDING => "pending",
                            db::STATUS_APPROVED => "approved",
                            db::STATUS_REJECTED => "rejected",
                            _ => unreachable!(),
                        },
                    );
                    ctx.insert("td_comment", &registration.td_comment);
                    Ok(Template::render("registered", &ctx))
                } else {
                    Ok(Template::render(
                        if r == 1 {
                            "registrationform"
                        } else {
                            "home_registrationclosed"
                        },
                        &context(&maybe_session),
                    ))
                }
            } else {
                Ok(Template::render(
                    if r == 1 {
                        "home_registrationopen"
                    } else {
                        "home_registrationclosed"
                    },
                    &context(&maybe_session),
                ))
            }
        }
    }
}

#[get("/oauth_redirect?<code>&<state>")]
fn oauth_redirect(
    mut cookies: Cookies<'_>,
    code: String,
    state: String,
    config: State<Config>,
    http_client: State<reqwest::Client>,
) -> Result<Result<Template, Status>, Box<dyn std::error::Error>> {
    match (
        session::pop_oauth_state(&mut cookies).map(|v| v == state),
        session::pop_oauth_code_verifier(&mut cookies),
    ) {
        (Some(true), Some(code_verifier)) => {
            println!("{}", code_verifier);
            let token = lichess::oauth_token_from_code(
                &code,
                &http_client,
                &config.oauth_client_id,
                &code_verifier,
                &format!("{}/oauth_redirect", config.server_url),
            )
            .unwrap();
            let user = lichess::get_user(&token.access_token, &http_client).unwrap();
            session::set_session(
                cookies,
                Session {
                    lichess_id: user.id,
                    lichess_username: user.username,
                },
            )?;
            Ok(Ok(Template::render("redirect", &context(&None))))
        }
        _ => Ok(Err(Status::BadRequest)),
    }
}

#[get("/oauth_redirect?<error>&<error_description>&<state>", rank = 2)]
fn oauth_redirect_error(
    mut cookies: Cookies<'_>,
    error: String,
    error_description: String,
    state: String,
) -> Redirect {
    println!("An OAuth error: {} - {}", error, error_description);
    session::pop_oauth_code_verifier(&mut cookies);
    session::pop_oauth_state(&mut cookies);
    Redirect::to("/")
}

#[derive(FromForm)]
struct OptionalCommentForm {
    #[form(field = "optional-comment")]
    comment: Option<String>,
}

#[post("/register", data = "<form>", rank = 1)]
fn register(
    form: Form<OptionalCommentForm>,
    session: Session,
    db_client: State<AcwcDbClient>,
) -> Result<Redirect, Box<dyn std::error::Error>> {
    if registration_state() == 1 && db_client.find_registration(&session.lichess_id)?.is_none() {
        db_client.insert_registration(&Registration {
            lichess_id: session.lichess_id,
            lichess_username: session.lichess_username,
            status: db::STATUS_PENDING,
            registrant_comment: form.comment.clone().unwrap_or_else(|| String::from("")),
            td_comment: String::from(""),
            special: false,
        })?;
    }

    Ok(Redirect::to(uri!(home)))
}

#[post("/register", rank = 2)]
fn register_needs_authentication() -> Redirect {
    Redirect::to(uri!(home))
}

const CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub fn random_string() -> Result<String, getrandom::Error> {
    let mut buffer = vec![0u8; 64];
    getrandom(&mut buffer)?;

    let bytes = CHARS.as_bytes();
    Ok(buffer
        .iter()
        .map(|b| {
            let index = *b as usize % CHARS.len();
            bytes[index] as char
        })
        .collect())
}

#[get("/auth")]
fn auth(
    config: State<Config>,
    mut cookies: Cookies<'_>,
) -> Result<Redirect, Box<dyn std::error::Error>> {
    let oauth_state = random_string()?;
    session::set_oauth_state_cookie(&mut cookies, &oauth_state);

    let code_verifier = random_string()?;
    session::set_oauth_code_verifier(&mut cookies, &code_verifier);

    let mut hasher = Sha256::default();
    hasher.update(code_verifier.as_bytes());
    let hash_result = base64::encode(hasher.finalize())
        .replace("=", "")
        .replace("+", "-")
        .replace("/", "_");

    let url = format!(
        "https://lichess.org/oauth?response_type=code\
        &client_id={}\
        &redirect_uri={}%2Foauth_redirect\
        &state={}&code_challenge_method=S256&code_challenge={}",
        urlencoding::encode(&config.oauth_client_id),
        urlencoding::encode(&config.server_url),
        oauth_state,
        &hash_result
    );

    Ok(Redirect::to(url))
}

#[post("/logout")]
fn logout(cookies: Cookies<'_>) -> Template {
    session::remove_session(cookies);
    Template::render("redirect", &context(&None))
}

fn is_admin(session: &Session, config: &State<Config>) -> bool {
    config.tournament_director.contains(&session.lichess_id)
}

#[get("/admin")]
fn admin(
    session: Session,
    config: State<Config>,
    db_client: State<AcwcDbClient>,
) -> Result<Template, Box<dyn std::error::Error>> {
    if is_admin(&session, &config) {
        let mut registrations = db_client.all_registrations()?;
        registrations.sort_by_key(|r| r.status);
        Ok(Template::render(
            "admin",
            &json!({
                "username": &session.lichess_username,
                "registrations": registrations
            }),
        ))
    } else {
        Ok(Template::render("accessdenied", &context(&Some(session))))
    }
}

#[get("/admin/review/<who>")]
fn admin_review(
    who: String,
    session: Session,
    config: State<Config>,
    db_client: State<AcwcDbClient>,
) -> Result<Template, Box<dyn std::error::Error>> {
    if is_admin(&session, &config) {
        let registration = db_client.find_registration(&who)?;
        Ok(Template::render(
            "adminreview",
            &json!({
                "username": &session.lichess_username,
                "registration": registration
            }),
        ))
    } else {
        Ok(Template::render("accessdenied", &context(&Some(session))))
    }
}

#[post("/admin/action/<what>/<who>", data = "<form>")]
fn admin_action(
    form: Form<OptionalCommentForm>,
    what: String,
    who: String,
    session: Session,
    config: State<Config>,
    db_client: State<AcwcDbClient>,
) -> Result<Redirect, Box<dyn std::error::Error>> {
    if is_admin(&session, &config) {
        let td_comment = form.comment.clone().unwrap_or_else(|| String::from(""));
        match what.as_ref() {
            "approve" => db_client.approve_registration(&who, &td_comment)?,
            "reject" => db_client.reject_registration(&who, &td_comment)?,
            "withdraw" => db_client.withdraw_registration(&who)?,
            _ => unreachable!(),
        };
        Ok(Redirect::to(uri!(admin)))
    } else {
        Ok(Redirect::to(uri!(home)))
    }
}

#[get("/rules/2019")]
fn rules_2019(session: Option<Session>) -> Template {
    Template::render("rules2019", &context(&session))
}

#[get("/rules/2020")]
fn rules_2020(session: Option<Session>) -> Template {
    Template::render("rules2020", &context(&session))
}

#[get("/rules/2021")]
fn rules_2021(session: Option<Session>) -> Template {
    Template::render("rules2021", &context(&session))
}

#[get("/rules/2022")]
fn rules_2022(session: Option<Session>) -> Template {
    Template::render("rules2022", &context(&session))
}

#[get("/rules/2023")]
fn rules_2023(session: Option<Session>) -> Template {
    Template::render("rules2023", &context(&session))
}

#[get("/rules/2024")]
fn rules_2024(session: Option<Session>) -> Template {
    Template::render("rules2024", &context(&session))
}

#[get("/rules/2025")]
fn rules_2025(session: Option<Session>) -> Template {
    Template::render("rules2025", &context(&session))
}

fn main() {
    let configuration = config::from_file("Config.toml").expect("failed to load config");

    let db_client = db::connect(&configuration.postgres_options).unwrap();

    rocket::ignite()
        .attach(Template::fairing())
        .manage(configuration)
        .manage(reqwest::Client::new())
        .manage(db_client)
        .mount(
            "/",
            routes![
                home,
                auth,
                oauth_redirect,
                oauth_redirect_error,
                register,
                register_needs_authentication,
                admin,
                admin_review,
                admin_action,
                logout,
                rules_2019,
                rules_2020,
                rules_2021,
                rules_2022,
                rules_2023,
                rules_2024,
            ],
        )
        .launch();
}
