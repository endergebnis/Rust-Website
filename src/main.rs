use axum::{
    routing::{get, post, get_service},
    extract::{Form, State},
    response::{Html, Json, IntoResponse},
    Router,
    http::{StatusCode, header},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use mongodb::{
    Client,
    Collection,
    options::{ClientOptions, ServerApi, ServerApiVersion},
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, env};
use tokio::net::TcpListener;
use dotenvy::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use chrono::Utc;
use tower_http::services::ServeDir;
use cookie::Cookie;
use axum::body::Body;

const JWT_SECRET: &str = "Endergebnisiserderallesbesteaufderweltlol";

#[derive(Clone)]
struct AppState {
    db: Collection<User>,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct RegisterInput {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginInput {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[axum::debug_handler]
async fn index_page() -> Html<&'static str> {
    Html(r#"
        <h1>Login</h1>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Benutzername" required>
            <input type="password" name="password" placeholder="Passwort" required>
            <button type="submit">Login</button>
        </form>
        <h2>Registrieren</h2>
        <form action="/register" method="post">
            <input type="text" name="username" placeholder="Benutzername" required>
            <input type="password" name="password" placeholder="Passwort" required>
            <button type="submit">Registrieren</button>
        </form>
    "#)
}

#[axum::debug_handler]
async fn register(
    State(state): State<Arc<AppState>>,
    Form(input): Form<RegisterInput>,
) -> Json<&'static str> {
    let hashed_password = hash(input.password, DEFAULT_COST).unwrap();
    let user = User {
        username: input.username,
        password: hashed_password,
    };

    state.db.insert_one(user).await.unwrap();
    Json("Registrierung erfolgreich")
}

#[axum::debug_handler]
async fn login(
    State(state): State<Arc<AppState>>,
    Form(input): Form<LoginInput>,
) -> Result<impl IntoResponse, Json<String>> {
    let user = state.db.find_one(mongodb::bson::doc! { "username": &input.username }).await.unwrap();

    if let Some(user) = user {
        if verify(&input.password, &user.password).unwrap() {
            let claims = Claims {
                sub: user.username.clone(),
                exp: (Utc::now().timestamp() + 3600) as usize,
            };
            let _token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
            ).unwrap();

            let cookie = Cookie::build("auth_token")
                .path("/")
                .http_only(true)
                .secure(true)
                .finish()
                .to_string();

            let response = axum::response::Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "/static/main.html")
                .header(header::SET_COOKIE, cookie)
                .body(Body::empty())
                .unwrap();
            Ok(response)
        } else {
            Err(Json("Falsches Passwort".to_string()))
        }
    } else {
        Err(Json("Benutzer nicht gefunden".to_string()))
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let mongo_uri = env::var("MONGO_URI").expect("MONGO_URI ist nicht gesetzt!");
    let mut client_options = ClientOptions::parse(&mongo_uri).await.unwrap();
    let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
    client_options.server_api = Some(server_api);
    let client = Client::with_options(client_options).unwrap();
    let db = client.database("rust_auth");
    let users_collection = db.collection::<User>("users");
    let state = Arc::new(AppState { db: users_collection });

    let app = Router::new()
        .route("/", get(index_page))
        .route("/register", post(register))
        .route("/login", post(login))
        .nest("/static", Router::new().fallback(get_service(ServeDir::new("static"))))
        .with_state(state);

    let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
    println!("Server läuft auf http://{}", addr);
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}
