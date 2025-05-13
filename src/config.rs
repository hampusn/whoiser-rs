use std::time::Duration;

const DEFAULT_TTL: u32 = 24 * 60 * 60;

#[derive(Clone)]
pub struct Config {
    pub cache_ttl: u32,
    pub cache_duration: Duration,
    pub port: String,
}

impl Config {
    pub fn from_env() -> Self {
        let cache_ttl = std::env::var("CACHE_TTL")
            .ok()
            .and_then(|val| val.parse::<u32>().ok())
            .unwrap_or(DEFAULT_TTL);

        let cache_duration: Duration = Duration::from_secs(cache_ttl as u64);

        let port = std::env::var("PORT")
            .unwrap_or(String::from("8080"));

        Self {
            cache_ttl,
            cache_duration,
            port,
        }
    }
}
