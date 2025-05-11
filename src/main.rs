use actix_web::{get, http::{header::{self, CacheDirective, HeaderMap, HttpDate}, StatusCode}, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use whois_rust::{WhoIs, WhoIsLookupOptions};
use moka::future::Cache;
use std::{sync::Arc, time::{Duration, SystemTime}};

#[derive(Clone)]
struct CacheEntry {
    value: String,
    expires: HttpDate,
    status: StatusCode,
}

impl CacheEntry {
    fn ok(value: String, expires: HttpDate) -> Self {
        Self {
            value,
            expires,
            status: StatusCode::OK,
        }
    }

    fn bad_request(msg: String, expires: HttpDate) -> Self {
        Self {
            value: msg,
            expires,
            status: StatusCode::BAD_REQUEST,
        }
    }
}

const TTL: u32 = 24 * 60 * 60;
const TTL_DURATION: Duration = Duration::from_secs(TTL as u64);
static IP_HEADERS: &[&str] = &[
    "x-real-ip",
    "x-forwarded-for",
    "cf-connecting-ip",
    "fastly-client-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "forwarded-for",
    "forwarded",
];

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cache: Arc<Cache<String, CacheEntry>> = Arc::new(Cache::builder()
        .max_capacity(10_000)
        .time_to_live(TTL_DURATION)
        .build());

    let servers = include_str!("../resources/whois-servers.json");
    let whois = WhoIs::from_string(servers).expect("Error reading servers from json.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(cache.clone()))
            .app_data(web::Data::new(whois.clone()))
            .service(index)
    })
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}

fn get_first_header(headers_map: &HeaderMap, header_names: &[&str]) -> Option<String> {
    for &name in header_names {
        if let Some(val) = headers_map.get(name) {
            if let Ok(s) = val.to_str() {
                return Some(s.to_owned());
            }
        }
    }

    None
}

#[get("/")]
async fn index(req: HttpRequest, cache: web::Data<Arc<Cache<String, CacheEntry>>>, whois: web::Data<WhoIs>) -> impl Responder {
    let ip = get_first_header(req.headers(), IP_HEADERS)
        .or_else(|| req.connection_info().realip_remote_addr().map(|s| s.to_owned()));

    let ip = match ip {
        Some(ip2) => ip2,
        None => return HttpResponse::BadRequest().body("Could not determine client IP"),
    };

    let cached_data = cache.get_with(ip.clone(), async move {
        let expires = HttpDate::from(SystemTime::now() + TTL_DURATION);
        let options = match WhoIsLookupOptions::from_string(ip) {
            Ok(opts) => opts,
            Err(err) => {
                eprintln!("Lookup options failed. Reason: {}", err);

                return CacheEntry::bad_request(format!("Lookup options failed. Reason: {}", err), expires);
            }
        };
        
        // WHOIS lookup is async, so we can just await it
        match whois.lookup_async(options).await {
            Ok(value) => CacheEntry::ok(value, expires),
            Err(err) => {
                eprintln!("WHOIS lookup failed. Reason: {}", err);

                return CacheEntry::bad_request(format!("WHOIS lookup failed. Reason: {}", err), expires);
            },
        }
    }).await;

    HttpResponse::build(cached_data.status)
        .insert_header(header::CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::MaxAge(TTL),
        ]))
        .insert_header(header::Expires(cached_data.expires))
        .body(cached_data.value)
}
