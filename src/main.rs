use actix_web::{get, http::header::{self, CacheDirective, HttpDate}, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use whoiser::{cache::entry::CacheEntry, config::Config, headers::{get_first_header, IP_HEADERS}};
use whois_rust::{WhoIs, WhoIsLookupOptions};
use moka::future::Cache;
use std::{sync::Arc, time::SystemTime};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = Config::from_env();

    let cache: Arc<Cache<String, CacheEntry>> = Arc::new(Cache::builder()
        .max_capacity(10_000)
        .time_to_live(config.cache_duration)
        .build());

    let servers = include_str!("../resources/whois-servers.json");
    let whois = WhoIs::from_string(servers).expect("Error reading servers from json.");
    let addr = format!("0.0.0.0:{}", config.port);

    println!("Starting whoiser on {}", addr);
    println!("- Cache TTL (s): {}", config.cache_ttl);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(cache.clone()))
            .app_data(web::Data::new(whois.clone()))
            .app_data(web::Data::new(config.clone()))
            .service(index)
    })
        .bind(addr)?
        .run()
        .await
}

#[get("/")]
async fn index(req: HttpRequest, cache: web::Data<Arc<Cache<String, CacheEntry>>>, whois: web::Data<WhoIs>, config: web::Data<Config>) -> impl Responder {
    let ip = get_first_header(req.headers(), IP_HEADERS)
        .or_else(|| req.connection_info().realip_remote_addr().map(|s| s.to_owned()));

    let ip = match ip {
        Some(ip2) => ip2,
        None => return HttpResponse::BadRequest().body("Could not determine client IP"),
    };

    let cache_duration = config.cache_duration.clone();
    let cached_data = cache.get_with(ip.clone(), async move {
        let expires = HttpDate::from(SystemTime::now() + cache_duration);
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
            CacheDirective::MaxAge(config.cache_ttl),
        ]))
        .insert_header(header::Expires(cached_data.expires))
        .body(cached_data.value)
}
