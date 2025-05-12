use actix_web::http::header::HeaderMap;

pub static IP_HEADERS: &[&str] = &[
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

pub fn get_first_header(headers_map: &HeaderMap, header_names: &[&str]) -> Option<String> {
    for &name in header_names {
        if let Some(val) = headers_map.get(name) {
            if let Ok(s) = val.to_str() {
                return Some(s.to_owned());
            }
        }
    }

    None
}