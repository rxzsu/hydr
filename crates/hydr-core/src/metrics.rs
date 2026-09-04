use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Лёгкие process-wide счётчики без внешних зависимостей.
///
/// Назначение — операционная видимость data-plane: auth по кодам ошибок,
/// replay vs bad-MAC в обфускации, стримы/датаграммы, UDP-сессии, дропы WS
/// и ожидания flow-control. Рендер в Prometheus-текст — через
/// [`Metrics::render_prometheus`], отдаётся серверным `/metrics`-эндпоинтом
/// (см. `hydr-server`), без pulls-библиотек.
pub struct Metrics {
    pub auth_ok: AtomicU64,
    pub auth_bad_credentials: AtomicU64,
    pub auth_replay: AtomicU64,
    pub auth_unsupported: AtomicU64,
    pub auth_rate_limited: AtomicU64,
    pub streams_opened: AtomicU64,
    pub datagrams_rx: AtomicU64,
    pub datagrams_tx: AtomicU64,
    pub udp_sessions_current: AtomicU64,
    pub udp_sessions_created: AtomicU64,
    pub udp_sessions_rejected: AtomicU64,
    pub ws_datagrams_dropped: AtomicU64,
    pub obfus_replay_dropped: AtomicU64,
    pub obfus_invalid: AtomicU64,
    pub ws_credit_waits: AtomicU64,
    pub cc_window_bytes: AtomicU64,
}

impl Metrics {
    const fn new() -> Self {
        const fn zero() -> AtomicU64 {
            AtomicU64::new(0)
        }
        Self {
            auth_ok: zero(),
            auth_bad_credentials: zero(),
            auth_replay: zero(),
            auth_unsupported: zero(),
            auth_rate_limited: zero(),
            streams_opened: zero(),
            datagrams_rx: zero(),
            datagrams_tx: zero(),
            udp_sessions_current: zero(),
            udp_sessions_created: zero(),
            udp_sessions_rejected: zero(),
            ws_datagrams_dropped: zero(),
            obfus_replay_dropped: zero(),
            obfus_invalid: zero(),
            ws_credit_waits: zero(),
            cc_window_bytes: zero(),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        MetricsSnapshot {
            auth_ok: load(&self.auth_ok),
            auth_bad_credentials: load(&self.auth_bad_credentials),
            auth_replay: load(&self.auth_replay),
            auth_unsupported: load(&self.auth_unsupported),
            auth_rate_limited: load(&self.auth_rate_limited),
            streams_opened: load(&self.streams_opened),
            datagrams_rx: load(&self.datagrams_rx),
            datagrams_tx: load(&self.datagrams_tx),
            udp_sessions_current: load(&self.udp_sessions_current),
            udp_sessions_created: load(&self.udp_sessions_created),
            udp_sessions_rejected: load(&self.udp_sessions_rejected),
            ws_datagrams_dropped: load(&self.ws_datagrams_dropped),
            obfus_replay_dropped: load(&self.obfus_replay_dropped),
            obfus_invalid: load(&self.obfus_invalid),
            ws_credit_waits: load(&self.ws_credit_waits),
            cc_window_bytes: load(&self.cc_window_bytes),
        }
    }

    /// Текст в формате Prometheus exposition (plain counters + 2 gauges).
    pub fn render_prometheus(&self) -> String {
        let s = self.snapshot();
        let mut out = String::with_capacity(1024);
        let counter = |out: &mut String, name: &str, help: &str, v: u64| {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" counter\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&v.to_string());
            out.push('\n');
        };
        let gauge = |out: &mut String, name: &str, help: &str, v: u64| {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" gauge\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&v.to_string());
            out.push('\n');
        };
        counter(
            &mut out,
            "hydr_auth_ok_total",
            "Successful tunnel authentications.",
            s.auth_ok,
        );
        counter(
            &mut out,
            "hydr_auth_bad_credentials_total",
            "Auth rejections: bad credentials.",
            s.auth_bad_credentials,
        );
        counter(
            &mut out,
            "hydr_auth_replay_total",
            "Auth rejections: nonce replay.",
            s.auth_replay,
        );
        counter(
            &mut out,
            "hydr_auth_unsupported_total",
            "Auth rejections: unsupported version.",
            s.auth_unsupported,
        );
        counter(
            &mut out,
            "hydr_auth_rate_limited_total",
            "Connections rejected by auth rate limiter.",
            s.auth_rate_limited,
        );
        counter(
            &mut out,
            "hydr_streams_opened_total",
            "Proxy streams accepted.",
            s.streams_opened,
        );
        counter(
            &mut out,
            "hydr_datagrams_rx_total",
            "Datagrams received from tunnels.",
            s.datagrams_rx,
        );
        counter(
            &mut out,
            "hydr_datagrams_tx_total",
            "Datagrams sent into tunnels.",
            s.datagrams_tx,
        );
        gauge(
            &mut out,
            "hydr_udp_sessions_current",
            "Currently tracked UDP sessions.",
            s.udp_sessions_current,
        );
        counter(
            &mut out,
            "hydr_udp_sessions_created_total",
            "UDP sessions created.",
            s.udp_sessions_created,
        );
        counter(
            &mut out,
            "hydr_udp_sessions_rejected_total",
            "UDP sessions rejected by caps (rate limited).",
            s.udp_sessions_rejected,
        );
        counter(
            &mut out,
            "hydr_ws_datagrams_dropped_total",
            "UDP datagrams dropped on WS outbound queue overflow.",
            s.ws_datagrams_dropped,
        );
        counter(
            &mut out,
            "hydr_obfus_replay_dropped_total",
            "WS frames silently dropped by anti-replay filter.",
            s.obfus_replay_dropped,
        );
        counter(
            &mut out,
            "hydr_obfus_invalid_total",
            "WS frames failed MAC/length check (connection torn down).",
            s.obfus_invalid,
        );
        counter(
            &mut out,
            "hydr_ws_credit_waits_total",
            "Times a WS stream paused on flow-control window exhaustion.",
            s.ws_credit_waits,
        );
        gauge(
            &mut out,
            "hydr_cc_window_bytes",
            "Last brutal congestion window in bytes.",
            s.cc_window_bytes,
        );
        out
    }
}

/// Плоский снимок [`Metrics`] (удобен для тестов и логов).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    pub auth_ok: u64,
    pub auth_bad_credentials: u64,
    pub auth_replay: u64,
    pub auth_unsupported: u64,
    pub auth_rate_limited: u64,
    pub streams_opened: u64,
    pub datagrams_rx: u64,
    pub datagrams_tx: u64,
    pub udp_sessions_current: u64,
    pub udp_sessions_created: u64,
    pub udp_sessions_rejected: u64,
    pub ws_datagrams_dropped: u64,
    pub obfus_replay_dropped: u64,
    pub obfus_invalid: u64,
    pub ws_credit_waits: u64,
    pub cc_window_bytes: u64,
}

static GLOBAL: Metrics = Metrics::new();

/// Process-wide счётчики.
pub fn global() -> &'static Metrics {
    &GLOBAL
}

/// Локальный набор счётчиков для юнит-тестов (без глобального состояния).
#[cfg(test)]
pub(crate) fn local() -> Metrics {
    Metrics::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reflects_increments() {
        let m = local();
        m.auth_ok.fetch_add(2, Ordering::Relaxed);
        m.udp_sessions_rejected.fetch_add(1, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.auth_ok, 2);
        assert_eq!(s.udp_sessions_rejected, 1);
        assert_eq!(s.streams_opened, 0);
    }

    #[test]
    fn prometheus_render_contains_keys() {
        let m = local();
        m.auth_ok.fetch_add(1, Ordering::Relaxed);
        let text = m.render_prometheus();
        assert!(text.contains("hydr_auth_ok_total 1"));
        assert!(text.contains("hydr_udp_sessions_current 0"));
        assert!(text.contains("# TYPE hydr_auth_ok_total counter"));
    }
}
