//! Brutal-подобный контроль перегрузки (congestion control) для quinn.
//!
//! В отличие от классических NewReno/CUBIC контроллер здесь не снижает
//! скорость при потерях: окно всегда вычисляется как `полоса × RTT`
//! (по аналогии с "brutal" в Hysteria 2), поэтому передача идёт с
//! фиксированной целевой скоростью независимо от загрузки канала.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// Минимальное окно — чтобы соединение не вставало до первого ack.
const MIN_WINDOW_BYTES: u64 = 2 * 1200;

/// Окно (в байтах), соответствующее целевой полосе: `rate / 8 * rtt`.
fn window_for(rate_bps: u64, rtt: Duration) -> u64 {
    let bytes_per_sec = rate_bps / 8;
    let w = (bytes_per_sec as u128 * rtt.as_nanos() / 1_000_000_000) as u64;
    w.max(MIN_WINDOW_BYTES)
}

/// Контроллер с фиксированной полосой: потери игнорируются,
/// окно пересчитывается только по целевой скорости и RTT.
#[derive(Clone)]
pub struct BrutalController {
    rate_bps: u64,
    window: u64,
    mtu: u16,
}

impl BrutalController {
    pub fn new(rate_bps: u64, mtu: u16) -> Self {
        Self {
            rate_bps,
            // стартовое окно по "угаданному" RTT до первого ack
            window: window_for(rate_bps, Duration::from_millis(50)),
            mtu,
        }
    }
}

impl Controller for BrutalController {
    fn on_ack(&mut self, _now: Instant, _sent: Instant, _bytes: u64, _app_limited: bool, rtt: &RttEstimator) {
        self.window = window_for(self.rate_bps, rtt.get());
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // brutal: не режем полосу при потерях
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        self.window.max(u64::from(self.mtu) * 2)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Фабрика, создающая `BrutalController` для каждого нового соединения.
#[derive(Clone, Debug)]
pub struct BrutalConfig {
    /// Целевая полоса в бит/с.
    pub rate_bps: u64,
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self.rate_bps, current_mtu))
    }
}

/// TransportConfig для quinn: brutal-контроллер при `rate_bps > 0`,
/// иначе стандартный конфиг.
pub fn transport_config(rate_bps: u64) -> quinn::TransportConfig {
    let mut cfg = quinn::TransportConfig::default();
    cfg.max_concurrent_bidi_streams(1024u32.into());
    cfg.keep_alive_interval(Some(Duration::from_secs(5)));
    // мёртвые соединения закрываются через 30с; keep_alive держит живые
    cfg.max_idle_timeout(Some(quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap()));
    if rate_bps > 0 {
        cfg.congestion_controller_factory(Arc::new(BrutalConfig { rate_bps }));
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_is_rate_by_rtt() {
        // 8 Mbps = 1e6 байт/с, RTT 100мс -> 100_000 байт
        assert_eq!(window_for(8_000_000, Duration::from_millis(100)), 100_000);
        // 20 Mbps, RTT 50мс -> 125_000 байт
        assert_eq!(window_for(20_000_000, Duration::from_millis(50)), 125_000);
    }

    #[test]
    fn window_never_below_minimum() {
        assert_eq!(window_for(1, Duration::from_millis(1)), MIN_WINDOW_BYTES);
    }

    #[test]
    fn controller_ignores_loss() {
        let mut c = BrutalController::new(8_000_000, 1200);
        let before = c.window();
        c.on_congestion_event(Instant::now(), Instant::now(), true, 1_000_000);
        assert_eq!(c.window(), before, "brutal не режет полосу при потерях");
    }

    #[test]
    fn factory_builds_brutal_controller() {
        let cfg = Arc::new(BrutalConfig { rate_bps: 8_000_000 });
        let c = cfg.build(Instant::now(), 1200);
        let any = c.into_any();
        assert!(
            any.downcast::<BrutalController>().is_ok(),
            "фабрика должна давать BrutalController"
        );
    }
}
