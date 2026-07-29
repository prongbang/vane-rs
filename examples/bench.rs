//! Phase 0 baseline bench (PERFORMANCE_PLAN.md). Env-gated, no framework.
//!   VANE_TEST_BASE_URL=https://example.com cargo run --release --example bench
//!   VANE_BENCH_DOWNLOAD_URL=https://example.com/10mb.bin cargo run --release --example bench

use std::env;
use std::time::{Duration, Instant};

use vane::{VaneClient, VaneClientConfig, VaneError};

const WARM_REQUESTS: usize = 20;

fn main() {
    let base_url = match env::var("VANE_TEST_BASE_URL") {
        Ok(v) if !v.trim().is_empty() => v.trim_end_matches('/').to_string(),
        _ => {
            println!("vane bench: skipped (VANE_TEST_BASE_URL not set)");
            return;
        }
    };
    let target = format!("{base_url}/");

    // Fresh client, pool on: first request is "cold", next WARM_REQUESTS reuse the pool.
    let on = VaneClientConfig {
        connection_pool_enabled: true,
        ..VaneClientConfig::default()
    };
    let client_on = VaneClient::new(on).unwrap_or_else(|e| fail("build client pool=on", &e));
    let cold = time_request(&client_on, &target).unwrap_or_else(|e| fail("cold request", &e));
    let warm_on = run_batch(&client_on, &target, "warm pool=on");

    // Fresh client, pool off: every request pays a full connect.
    let off = VaneClientConfig {
        connection_pool_enabled: false,
        ..VaneClientConfig::default()
    };
    let client_off = VaneClient::new(off).unwrap_or_else(|e| fail("build client pool=off", &e));
    let warm_off = run_batch(&client_off, &target, "warm pool=off");

    println!("vane bench base_url={base_url}");
    println!("cold          n=1   latency_ms={:>8.2}", ms(cold));
    report("warm pool=on", &warm_on);
    report("warm pool=off", &warm_off);

    let Ok(dl_url) = env::var("VANE_BENCH_DOWNLOAD_URL") else {
        return;
    };
    if dl_url.trim().is_empty() {
        return;
    }
    let start = Instant::now();
    match client_on.get_request(dl_url) {
        Ok(resp) => {
            let secs = start.elapsed().as_secs_f64().max(1e-9);
            let mb = resp.body.len() as f64 / 1_048_576.0;
            println!(
                "download      n=1   bytes={:<10} secs={:>7.3} mb_s={:>8.2}",
                resp.body.len(),
                secs,
                mb / secs
            );
        }
        Err(e) => println!("download      error={e}"),
    }
}

fn run_batch(client: &VaneClient, url: &str, label: &str) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(WARM_REQUESTS);
    for i in 0..WARM_REQUESTS {
        let sample =
            time_request(client, url).unwrap_or_else(|e| fail(&format!("{label} #{i}"), &e));
        samples.push(sample);
    }
    samples.sort();
    samples
}

fn report(label: &str, sorted: &[Duration]) {
    println!(
        "{label:<13} n={:<3} p50_ms={:>8.2} p95_ms={:>8.2}",
        sorted.len(),
        ms(percentile(sorted, 50.0)),
        ms(percentile(sorted, 95.0))
    );
}

fn time_request(client: &VaneClient, url: &str) -> Result<Duration, VaneError> {
    let start = Instant::now();
    client.get_request(url.to_string())?;
    Ok(start.elapsed())
}

/// Nearest-rank percentile over an already-sorted slice. No stats crate.
fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn fail(stage: &str, err: &VaneError) -> ! {
    eprintln!("vane bench: failed at {stage}: {err}");
    std::process::exit(1);
}
