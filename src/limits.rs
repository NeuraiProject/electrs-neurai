//! Limits that keep one client from slowing down the others: the cost of
//! each IP's requests, its connections and bans, and how many heavy queries
//! run at once.

use parking_lot::{Condvar, Mutex};

use std::cell::Cell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

thread_local! {
    static WAITED: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Runs `f`, counting its duration as waiting (for a P2P connection, a heavy
/// query slot, another client's query of the same address) rather than work:
/// see `take_waited`.
pub(crate) fn waiting<T>(f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = f();
    let waited = start.elapsed();
    WAITED.with(|w| w.set(w.get() + waited));
    result
}

/// Time this thread spent in `waiting` since the last call.
pub(crate) fn take_waited() -> Duration {
    WAITED.with(|w| w.replace(Duration::ZERO))
}

/// At most `permits` holders at once.
pub(crate) struct Semaphore {
    available: Mutex<usize>,
    released: Condvar,
}

pub(crate) struct Permit<'a>(&'a Semaphore);

impl Semaphore {
    pub(crate) fn new(permits: usize) -> Self {
        Self {
            available: Mutex::new(permits.max(1)),
            released: Condvar::new(),
        }
    }

    /// Waits for a permit (counted as waiting).
    pub(crate) fn acquire(&self) -> Permit<'_> {
        waiting(|| {
            let mut available = self.available.lock();
            while *available == 0 {
                self.released.wait(&mut available);
            }
            *available -= 1;
        });
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.available.lock() += 1;
        self.0.released.notify_one();
    }
}

/// Settings of `RateLimits` (see the `rpc_*` options).
#[derive(Clone, Debug)]
pub struct LimitsConfig {
    /// Connections at once, all IPs together (0: no limit).
    pub max_connections: usize,
    /// Connections at once from one IP (0: no limit).
    pub max_connections_per_ip: usize,
    /// Over this cost, the requests of an IP are slowed down.
    pub cost_soft_limit: f64,
    /// Over this cost, an IP is banned (0: never).
    pub cost_hard_limit: f64,
    /// Cost forgiven per second.
    pub cost_decay_per_sec: f64,
    pub ban_duration: Duration,
    /// IPs without limits (local monitoring, a trusted proxy...).
    pub exempt: Vec<IpAddr>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_ip: 32,
            cost_soft_limit: 5_000.0,
            cost_hard_limit: 50_000.0,
            cost_decay_per_sec: 100.0,
            ban_duration: Duration::from_secs(600),
            exempt: Vec::new(),
        }
    }
}

/// Cost of a request, besides the time spent on it.
pub(crate) const CALL_COST: f64 = 1.0;
/// Cost of a millisecond of work for a client (waiting excluded).
pub(crate) const MILLISECOND_COST: f64 = 0.1;
/// Cost of a KiB sent to a client.
pub(crate) const KIB_COST: f64 = 1.0 / 64.0;
/// Cost of a connection, and of a refused one.
const CONNECT_COST: f64 = 10.0;
const REFUSED_COST: f64 = 100.0;
/// Longest throttling delay at once.
const MAX_DELAY: Duration = Duration::from_secs(30);

/// IPv4 addresses are limited one by one, IPv6 ones by /64 network: anybody
/// gets a whole /64.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct IpKey(IpAddr);

impl IpKey {
    pub(crate) fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => IpKey(ip),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpKey(IpAddr::V4(v4)),
                None => {
                    let mut segments = v6.segments();
                    segments[4..].fill(0);
                    IpKey(IpAddr::V6(segments.into()))
                }
            },
        }
    }
}

impl std::fmt::Display for IpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            IpAddr::V4(ip) => write!(f, "{}", ip),
            IpAddr::V6(ip) => write!(f, "{}/64", ip),
        }
    }
}

#[derive(Default)]
struct IpState {
    connections: usize,
    cost: f64,
    updated: Option<Instant>,
    banned_until: Option<Instant>,
}

impl IpState {
    /// The cost after the decay since its last change.
    fn decay(&mut self, now: Instant, decay_per_sec: f64) {
        if let Some(updated) = self.updated {
            let forgiven = now.saturating_duration_since(updated).as_secs_f64() * decay_per_sec;
            self.cost = (self.cost - forgiven).max(0.0);
        }
        self.updated = Some(now);
    }

    fn banned(&mut self, now: Instant) -> bool {
        match self.banned_until {
            Some(until) if until > now => true,
            Some(_) => {
                self.banned_until = None;
                false
            }
            None => false,
        }
    }

    fn forgettable(&self) -> bool {
        self.connections == 0 && self.cost == 0.0 && self.banned_until.is_none()
    }
}

/// What to do with a client after charging it.
#[derive(Debug, PartialEq)]
pub(crate) enum Verdict {
    Proceed,
    /// Wait this long before its next request.
    Throttle(Duration),
    /// Its IP was just banned: close its connections.
    Ban,
}

/// Why a connection is refused.
#[derive(Debug, PartialEq)]
pub(crate) enum Refusal {
    Banned,
    TooManyConnections,
    /// The IP was banned for trying too many connections.
    Ban,
}

/// The cost of the requests of each IP, ElectrumX-style: each request costs
/// `CALL_COST`, plus the time spent on it and the size of its reply, and the
/// cost decays with time. Over the soft limit, an IP's requests wait until
/// its cost is back to the limit; over the hard limit, it is banned.
pub(crate) struct RateLimits {
    config: LimitsConfig,
    ips: Mutex<HashMap<IpKey, IpState>>,
    connections: Mutex<usize>,
}

impl RateLimits {
    pub(crate) fn new(config: LimitsConfig) -> Self {
        Self {
            config,
            ips: Mutex::new(HashMap::new()),
            connections: Mutex::new(0),
        }
    }

    fn exempt(&self, ip: IpAddr) -> bool {
        self.config.exempt.contains(&ip)
    }

    /// Registers a new connection, unless it must be refused.
    pub(crate) fn connect(&self, ip: IpAddr) -> Result<(), Refusal> {
        if self.exempt(ip) {
            *self.connections.lock() += 1;
            return Ok(());
        }
        let now = Instant::now();
        let mut ips = self.ips.lock();
        let state = ips.entry(IpKey::of(ip)).or_default();
        if state.banned(now) {
            return Err(Refusal::Banned);
        }
        state.decay(now, self.config.cost_decay_per_sec);
        let max_total = self.config.max_connections;
        let max_per_ip = self.config.max_connections_per_ip;
        let mut connections = self.connections.lock();
        let too_many = (max_total > 0 && *connections >= max_total)
            || (max_per_ip > 0 && state.connections >= max_per_ip);
        if too_many {
            state.cost += REFUSED_COST;
            if self.over_hard_limit(state.cost) {
                self.ban(state, now);
                return Err(Refusal::Ban);
            }
            return Err(Refusal::TooManyConnections);
        }
        state.cost += CONNECT_COST;
        state.connections += 1;
        *connections += 1;
        Ok(())
    }

    pub(crate) fn disconnect(&self, ip: IpAddr) {
        {
            let mut connections = self.connections.lock();
            *connections = connections.saturating_sub(1);
        }
        if self.exempt(ip) {
            return;
        }
        let key = IpKey::of(ip);
        let mut ips = self.ips.lock();
        if let Some(state) = ips.get_mut(&key) {
            state.connections = state.connections.saturating_sub(1);
            state.decay(Instant::now(), self.config.cost_decay_per_sec);
            if state.forgettable() {
                ips.remove(&key);
            }
        }
        // forget the IPs that were quiet long enough to owe nothing
        if ips.len() > 10_000 {
            let now = Instant::now();
            let decay = self.config.cost_decay_per_sec;
            ips.retain(|_, state| {
                state.decay(now, decay);
                state.banned(now);
                !state.forgettable()
            });
        }
    }

    fn over_hard_limit(&self, cost: f64) -> bool {
        self.config.cost_hard_limit > 0.0 && cost > self.config.cost_hard_limit
    }

    fn ban(&self, state: &mut IpState, now: Instant) {
        state.banned_until = Some(now + self.config.ban_duration);
        state.cost = 0.0;
    }

    /// Adds `cost` to the IP's.
    pub(crate) fn charge(&self, ip: IpAddr, cost: f64) -> Verdict {
        if self.exempt(ip) {
            return Verdict::Proceed;
        }
        let now = Instant::now();
        let mut ips = self.ips.lock();
        let state = ips.entry(IpKey::of(ip)).or_default();
        if state.banned(now) {
            return Verdict::Ban;
        }
        state.decay(now, self.config.cost_decay_per_sec);
        state.cost += cost;
        if self.over_hard_limit(state.cost) {
            self.ban(state, now);
            return Verdict::Ban;
        }
        let excess = state.cost - self.config.cost_soft_limit;
        if excess > 0.0 && self.config.cost_decay_per_sec > 0.0 {
            let delay = Duration::from_secs_f64(excess / self.config.cost_decay_per_sec);
            return Verdict::Throttle(delay.min(MAX_DELAY));
        }
        Verdict::Proceed
    }

    /// Whether `ip` is banned now.
    pub(crate) fn is_banned(&self, ip: IpAddr) -> bool {
        if self.exempt(ip) {
            return false;
        }
        let now = Instant::now();
        self.ips
            .lock()
            .get_mut(&IpKey::of(ip))
            .is_some_and(|state| state.banned(now))
    }

    pub(crate) fn ban_duration(&self) -> Duration {
        self.config.ban_duration
    }

    /// Cost of a reply of `bytes` that took `work` (waiting excluded).
    pub(crate) fn request_cost(calls: usize, work: Duration, bytes: usize) -> f64 {
        calls as f64 * CALL_COST
            + work.as_secs_f64() * 1000.0 * MILLISECOND_COST
            + bytes as f64 / 1024.0 * KIB_COST
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(config: LimitsConfig) -> RateLimits {
        RateLimits::new(config)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv6_is_limited_by_64() {
        assert_eq!(
            IpKey::of(ip("2001:db8::1")),
            IpKey::of(ip("2001:db8::ffff:2"))
        );
        assert_ne!(
            IpKey::of(ip("2001:db8::1")),
            IpKey::of(ip("2001:db8:0:1::1"))
        );
        assert_eq!(IpKey::of(ip("::ffff:10.0.0.1")), IpKey::of(ip("10.0.0.1")));
        assert_ne!(IpKey::of(ip("10.0.0.1")), IpKey::of(ip("10.0.0.2")));
    }

    #[test]
    fn connections_per_ip() {
        let limits = limits(LimitsConfig {
            max_connections_per_ip: 2,
            ..Default::default()
        });
        assert_eq!(limits.connect(ip("10.0.0.1")), Ok(()));
        assert_eq!(limits.connect(ip("10.0.0.1")), Ok(()));
        assert_eq!(
            limits.connect(ip("10.0.0.1")),
            Err(Refusal::TooManyConnections)
        );
        assert_eq!(limits.connect(ip("10.0.0.2")), Ok(()));
        limits.disconnect(ip("10.0.0.1"));
        assert_eq!(limits.connect(ip("10.0.0.1")), Ok(()));
    }

    #[test]
    fn total_connections() {
        let limits = limits(LimitsConfig {
            max_connections: 2,
            ..Default::default()
        });
        assert_eq!(limits.connect(ip("10.0.0.1")), Ok(()));
        assert_eq!(limits.connect(ip("10.0.0.2")), Ok(()));
        assert_eq!(
            limits.connect(ip("10.0.0.3")),
            Err(Refusal::TooManyConnections)
        );
        limits.disconnect(ip("10.0.0.2"));
        assert_eq!(limits.connect(ip("10.0.0.3")), Ok(()));
    }

    #[test]
    fn soft_limit_throttles_and_hard_limit_bans() {
        let limits = limits(LimitsConfig {
            cost_soft_limit: 100.0,
            cost_hard_limit: 1000.0,
            cost_decay_per_sec: 10.0,
            ..Default::default()
        });
        let a = ip("10.0.0.1");
        assert_eq!(limits.charge(a, 90.0), Verdict::Proceed);
        match limits.charge(a, 20.0) {
            // 10 over the soft limit: about a second at 10 per second
            Verdict::Throttle(delay) => assert!(delay > Duration::from_millis(900), "{:?}", delay),
            other => panic!("{:?}", other),
        }
        assert_eq!(limits.charge(a, 1000.0), Verdict::Ban);
        assert!(limits.is_banned(a));
        assert_eq!(limits.connect(a), Err(Refusal::Banned));
        assert_eq!(limits.charge(a, 1.0), Verdict::Ban);
        // other IPs are not affected
        assert_eq!(limits.charge(ip("10.0.0.2"), 1.0), Verdict::Proceed);
    }

    #[test]
    fn bans_expire() {
        let limits = limits(LimitsConfig {
            cost_hard_limit: 10.0,
            ban_duration: Duration::from_millis(50),
            ..Default::default()
        });
        let a = ip("10.0.0.1");
        assert_eq!(limits.charge(a, 11.0), Verdict::Ban);
        assert!(limits.is_banned(a));
        std::thread::sleep(Duration::from_millis(60));
        assert!(!limits.is_banned(a));
        assert_eq!(limits.connect(a), Ok(()));
    }

    #[test]
    fn connection_storms_get_banned() {
        let limits = limits(LimitsConfig {
            max_connections_per_ip: 1,
            cost_hard_limit: 500.0,
            ..Default::default()
        });
        let a = ip("10.0.0.1");
        assert_eq!(limits.connect(a), Ok(()));
        let refusals: Vec<Refusal> = (0..10).filter_map(|_| limits.connect(a).err()).collect();
        assert!(refusals.contains(&Refusal::Ban), "{:?}", refusals);
        assert!(limits.is_banned(a));
    }

    #[test]
    fn cost_decays() {
        let limits = limits(LimitsConfig {
            cost_soft_limit: 10.0,
            cost_decay_per_sec: 1000.0,
            ..Default::default()
        });
        let a = ip("10.0.0.1");
        assert!(matches!(limits.charge(a, 20.0), Verdict::Throttle(_)));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(limits.charge(a, 1.0), Verdict::Proceed);
    }

    #[test]
    fn exempt_ips_have_no_limits() {
        let limits = limits(LimitsConfig {
            max_connections_per_ip: 1,
            cost_hard_limit: 10.0,
            exempt: vec![ip("127.0.0.1")],
            ..Default::default()
        });
        let local = ip("127.0.0.1");
        assert_eq!(limits.connect(local), Ok(()));
        assert_eq!(limits.connect(local), Ok(()));
        assert_eq!(limits.charge(local, 1e9), Verdict::Proceed);
        assert!(!limits.is_banned(local));
    }

    #[test]
    fn semaphore_limits_holders() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let semaphore = Arc::new(Semaphore::new(2));
        let inside = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (semaphore, inside, most) = (semaphore.clone(), inside.clone(), most.clone());
                std::thread::spawn(move || {
                    let _permit = semaphore.acquire();
                    let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(10));
                    inside.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        assert_eq!(most.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn waiting_is_counted_apart() {
        take_waited();
        waiting(|| std::thread::sleep(Duration::from_millis(20)));
        assert!(take_waited() >= Duration::from_millis(20));
        assert_eq!(take_waited(), Duration::ZERO);
    }
}
