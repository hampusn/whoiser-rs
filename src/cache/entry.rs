use actix_web::http::{header::HttpDate, StatusCode};

#[derive(Clone)]
pub struct CacheEntry {
    pub value: String,
    pub expires: HttpDate,
    pub status: StatusCode,
}

impl CacheEntry {
    pub fn ok(value: String, expires: HttpDate) -> Self {
        Self {
            value,
            expires,
            status: StatusCode::OK,
        }
    }

    pub fn bad_request(msg: String, expires: HttpDate) -> Self {
        Self {
            value: msg,
            expires,
            status: StatusCode::BAD_REQUEST,
        }
    }
}