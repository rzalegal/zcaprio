use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

fn request(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn health_route_reports_ready() {
    let response = zkp_lab::app::router()
        .oneshot(request("/api/health"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
