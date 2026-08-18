//! Pluggable token-rate-limit state backends.

use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;

use super::ledger::{Budget, Decision, Ledger, Settlement};

#[derive(Debug, Clone)]
pub(crate) struct ReserveRequest {
    pub(crate) key: String,
    pub(crate) estimate: u64,
    pub(crate) now_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ReconcileRequest {
    pub(crate) key: String,
    pub(crate) reservation_id: u64,
    pub(crate) actual: Option<u64>,
    pub(crate) estimate: u64,
    pub(crate) now_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum BackendReserve {
    Admitted { reservation_id: u64, estimate: u64 },
    Denied { retry_after_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendSettlement {
    Applied { actual: u64, refund: u64, overage: u64 },
    Noop,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BackendError {
    #[error("shared quota backend unavailable: {0}")]
    Unavailable(String),
    #[error("shared quota backend returned an invalid response")]
    InvalidResponse,
}

#[async_trait]
pub(crate) trait TokenRateLimitStateBackend: Send + Sync {
    async fn reserve(&self, request: ReserveRequest) -> Result<BackendReserve, BackendError>;

    async fn reconcile(&self, request: ReconcileRequest) -> Result<BackendSettlement, BackendError>;

    fn enqueue_reconcile(&self, request: ReconcileRequest) -> Result<(), BackendError>;

    fn limit(&self) -> u64;

    fn local_state(&self) -> Option<(&Ledger, u64)> {
        None
    }
}

pub(crate) struct InMemoryTokenRateLimitBackend {
    ledger: Arc<Ledger>,
}

impl InMemoryTokenRateLimitBackend {
    pub(crate) fn new(ledger: Ledger) -> Self {
        Self {
            ledger: Arc::new(ledger),
        }
    }
}

#[async_trait]
impl TokenRateLimitStateBackend for InMemoryTokenRateLimitBackend {
    async fn reserve(&self, request: ReserveRequest) -> Result<BackendReserve, BackendError> {
        Ok(
            match self.ledger.reserve(&request.key, request.estimate, request.now_ms) {
                Decision::Admitted(reservation) => BackendReserve::Admitted {
                    reservation_id: reservation.id,
                    estimate: reservation.estimate,
                },
                Decision::Denied { retry_after_ms, .. } => BackendReserve::Denied { retry_after_ms },
            },
        )
    }

    async fn reconcile(&self, request: ReconcileRequest) -> Result<BackendSettlement, BackendError> {
        Ok(
            match self
                .ledger
                .reconcile(request.reservation_id, request.actual, request.now_ms)
            {
                Settlement::Applied {
                    actual,
                    refund,
                    overage,
                } => BackendSettlement::Applied {
                    actual,
                    refund,
                    overage,
                },
                Settlement::Noop => BackendSettlement::Noop,
            },
        )
    }

    fn enqueue_reconcile(&self, request: ReconcileRequest) -> Result<(), BackendError> {
        let _ = self
            .ledger
            .reconcile(request.reservation_id, request.actual, request.now_ms);
        Ok(())
    }

    fn limit(&self) -> u64 {
        self.ledger.limit()
    }

    fn local_state(&self) -> Option<(&Ledger, u64)> {
        Some((&self.ledger, 0))
    }
}

const RESERVE_SCRIPT: &str = "
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local timeout_ms = tonumber(ARGV[1])
local max_keys = tonumber(ARGV[2])
local max_active = tonumber(ARGV[3])
local estimate = tonumber(ARGV[4])
local budget_count = tonumber(ARGV[5])
local settled = KEYS[2]
local active = KEYS[3]

local active_total = tonumber(redis.call('GET', KEYS[5]) or '0')
local expired_global = redis.call('ZRANGE', KEYS[7], '-inf', now_ms, 'BYSCORE')
for i = 1, #expired_global do
  local member = expired_global[i]
  local split = string.find(member, '|')
  if split then
    local physical = string.sub(member, 1, split - 1)
    local reservation = string.sub(member, split + 1)
    local active_key = physical .. ':active'
    local value = redis.call('HGET', active_key, reservation)
    if value then
      local value_split = string.find(value, '|')
      local amount = tonumber(string.sub(value, 1, value_split - 1))
      local reserved_at = tonumber(string.sub(value, value_split + 1))
      redis.call('ZADD', physical .. ':settled', reserved_at, 'expired:' .. reservation .. ':' .. amount)
      redis.call('HDEL', active_key, reservation)
      active_total = math.max(0, active_total - 1)
    end
  end
  redis.call('ZREM', KEYS[7], member)
end
redis.call('SET', KEYS[5], active_total)

local max_window = 0
for i = 1, budget_count do
  local window = tonumber(ARGV[5 + (i * 2) - 1])
  if window > max_window then max_window = window end
  redis.call('ZREMRANGEBYSCORE', settled, '-inf', now_ms - window)
end

local expired = {}
local active_values = redis.call('HGETALL', active)
for i = 1, #active_values, 2 do
  local id = active_values[i]
  local value = active_values[i + 1]
  local sep = string.find(value, '|')
  local reserved_at = tonumber(string.sub(value, sep + 1))
  if now_ms - reserved_at >= timeout_ms then
    local amount = tonumber(string.sub(value, 1, sep - 1))
    redis.call('ZADD', settled, reserved_at, 'expired:' .. id .. ':' .. amount)
    redis.call('HDEL', active, id)
    active_total = math.max(0, active_total - 1)
  end
end
redis.call('SET', KEYS[5], active_total)

redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', now_ms)
local key_exists = redis.call('ZSCORE', KEYS[4], KEYS[1]) ~= false
if not key_exists and redis.call('ZCARD', KEYS[4]) >= max_keys then
  return {0, max_window}
end
if active_total >= max_active then
  return {0, max_window}
end

for i = 1, budget_count do
  local window = tonumber(ARGV[5 + (i * 2) - 1])
  local capacity = tonumber(ARGV[5 + (i * 2)])
  local settled_sum = 0
  local entries = redis.call('ZRANGE', settled, now_ms - window, '+inf', 'BYSCORE', 'WITHSCORES')
  for j = 1, #entries, 2 do
    local member = entries[j]
    local amount = string.match(member, ':(%d+)$')
    if amount then settled_sum = settled_sum + tonumber(amount) end
  end
  local active_values = redis.call('HGETALL', active)
  local active_sum = 0
  for j = 1, #active_values, 2 do
    local sep = string.find(active_values[j + 1], '|')
    active_sum = active_sum + tonumber(string.sub(active_values[j + 1], 1, sep - 1))
  end
  if settled_sum + active_sum + estimate > capacity then
    return {0, max_window}
  end
end

local id = redis.call('INCR', KEYS[6])
redis.call('HSET', active, id, estimate .. '|' .. now_ms)
redis.call('INCR', KEYS[5])
redis.call('ZADD', KEYS[7], now_ms + timeout_ms, KEYS[1] .. '|' .. id)
local ttl = math.max(max_window + timeout_ms, 1000)
redis.call('ZADD', KEYS[4], now_ms + ttl, KEYS[1])
redis.call('PEXPIRE', settled, ttl)
redis.call('PEXPIRE', active, ttl)
redis.call('PEXPIRE', KEYS[1], ttl)
return {1, id, estimate}
";

const RECONCILE_SCRIPT: &str = "
local value = redis.call('HGET', KEYS[3], ARGV[1])
if not value then return {0} end
local sep = string.find(value, '|')
local estimate = tonumber(string.sub(value, 1, sep - 1))
local actual = tonumber(ARGV[2])
redis.call('HDEL', KEYS[3], ARGV[1])
local active_total = math.max(0, tonumber(redis.call('GET', KEYS[5]) or '0') - 1)
redis.call('SET', KEYS[5], active_total)
redis.call('ZREM', KEYS[7], KEYS[1] .. '|' .. ARGV[1])
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
redis.call('ZADD', KEYS[2], now_ms, 'settled:' .. ARGV[1] .. ':' .. actual)
return {1, actual, math.max(0, estimate - actual), math.max(0, actual - estimate)}
";

pub(crate) struct ValkeyTokenRateLimitBackend {
    client: redis::Client,
    namespace: String,
    rule: String,
    budgets: Vec<Budget>,
    reservation_timeout_ms: u64,
    max_keys: usize,
    max_active_reservations: usize,
    limit: u64,
    reconcile_tx: mpsc::Sender<ReconcileRequest>,
    reconcile_rx: Mutex<Option<mpsc::Receiver<ReconcileRequest>>>,
    worker_started: OnceLock<()>,
}

pub(crate) struct ValkeyBackendConfig {
    pub(crate) url: String,
    pub(crate) namespace: String,
    pub(crate) rule: String,
    pub(crate) budgets: Vec<Budget>,
    pub(crate) reservation_timeout_ms: u64,
    pub(crate) max_keys: usize,
    pub(crate) max_active_reservations: usize,
}

impl ValkeyTokenRateLimitBackend {
    pub(crate) fn new(config: ValkeyBackendConfig) -> Result<Self, BackendError> {
        let client = redis::Client::open(config.url).map_err(|e| BackendError::Unavailable(e.to_string()))?;
        let limit = config.budgets.iter().map(|budget| budget.capacity).min().unwrap_or(0);
        let (reconcile_tx, reconcile_rx) = mpsc::channel(1024);
        let worker_backend = Self {
            client,
            namespace: config.namespace,
            rule: config.rule,
            budgets: config.budgets,
            reservation_timeout_ms: config.reservation_timeout_ms,
            max_keys: config.max_keys,
            max_active_reservations: config.max_active_reservations,
            limit,
            reconcile_tx: reconcile_tx.clone(),
            reconcile_rx: Mutex::new(Some(reconcile_rx)),
            worker_started: OnceLock::new(),
        };
        Ok(worker_backend)
    }

    fn clone_without_sender(&self) -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self {
            client: self.client.clone(),
            namespace: self.namespace.clone(),
            rule: self.rule.clone(),
            budgets: self.budgets.clone(),
            reservation_timeout_ms: self.reservation_timeout_ms,
            max_keys: self.max_keys,
            max_active_reservations: self.max_active_reservations,
            limit: self.limit,
            reconcile_tx: tx,
            reconcile_rx: Mutex::new(None),
            worker_started: OnceLock::new(),
        }
    }

    fn start_worker(&self) -> Result<(), BackendError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_error| BackendError::Unavailable("Valkey reconciliation requires a Tokio runtime".into()))?;
        self.worker_started.get_or_init(|| {
            let Some(mut receiver) = self.reconcile_rx.lock().ok().and_then(|mut guard| guard.take()) else {
                return;
            };
            let worker = self.clone_without_sender();
            runtime.spawn(async move {
                while let Some(request) = receiver.recv().await {
                    let mut attempts = 0;
                    loop {
                        match worker.reconcile(request.clone()).await {
                            Ok(_) => {
                                metrics::counter!("praxis_ai_token_rate_limit_backend_reconciliation_total", "backend" => "valkey", "result" => "completed").increment(1);
                                break;
                            },
                            Err(error) if attempts < 2 => {
                                attempts += 1;
                                tracing::warn!(attempts, %error, "token-rate-limit reconciliation retry");
                                tokio::time::sleep(std::time::Duration::from_millis(25 * attempts)).await;
                            },
                            Err(error) => {
                                metrics::counter!("praxis_ai_token_rate_limit_backend_errors_total", "backend" => "valkey", "operation" => "reconcile").increment(1);
                                tracing::error!(%error, "token-rate-limit reconciliation abandoned after retries");
                                break;
                            },
                        }
                    }
                }
            });
        });
        Ok(())
    }

    fn key_parts(&self, key: &str) -> [String; 7] {
        let mut digest = Sha256::new();
        digest.update(self.namespace.as_bytes());
        digest.update([0]);
        digest.update(self.rule.as_bytes());
        digest.update([0]);
        digest.update(key.as_bytes());
        let hash = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let prefix = format!("{}:v1:{}", self.namespace, hash);
        [
            prefix.clone(),
            format!("{prefix}:settled"),
            format!("{prefix}:active"),
            format!("{}:keys", self.namespace),
            format!("{}:active-count", self.namespace),
            format!("{}:reservation-seq", self.namespace),
            format!("{}:active-index", self.namespace),
        ]
    }

    async fn connection(&self) -> Result<MultiplexedConnection, BackendError> {
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_error| BackendError::Unavailable("Valkey connection timed out".into()))?
        .map_err(|e| BackendError::Unavailable(e.to_string()))
    }
}

#[async_trait]
impl TokenRateLimitStateBackend for ValkeyTokenRateLimitBackend {
    async fn reserve(&self, request: ReserveRequest) -> Result<BackendReserve, BackendError> {
        let keys = self.key_parts(&request.key);
        let mut args: Vec<String> = vec![
            self.reservation_timeout_ms.to_string(),
            self.max_keys.to_string(),
            self.max_active_reservations.to_string(),
            request.estimate.to_string(),
            self.budgets.len().to_string(),
        ];
        for budget in &self.budgets {
            args.push(budget.window_ms.to_string());
            args.push(budget.capacity.to_string());
        }
        let mut command = redis::cmd("EVAL");
        command.arg(RESERVE_SCRIPT).arg(7);
        for key in &keys {
            command.arg(key);
        }
        for arg in args {
            command.arg(arg);
        }
        let mut connection = self.connection().await?;
        let response: Vec<i64> = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            command.query_async(&mut connection),
        )
        .await
        .map_err(|_error| BackendError::Unavailable("Valkey reservation timed out".into()))?
        .map_err(|e| BackendError::Unavailable(e.to_string()))?;
        match response.as_slice() {
            [1, id, estimate] => Ok(BackendReserve::Admitted {
                reservation_id: u64::try_from(*id).map_err(|_error| BackendError::InvalidResponse)?,
                estimate: u64::try_from(*estimate).map_err(|_error| BackendError::InvalidResponse)?,
            }),
            [0, retry_after] => Ok(BackendReserve::Denied {
                retry_after_ms: u64::try_from(*retry_after).map_err(|_error| BackendError::InvalidResponse)?,
            }),
            _ => Err(BackendError::InvalidResponse),
        }
    }

    async fn reconcile(&self, request: ReconcileRequest) -> Result<BackendSettlement, BackendError> {
        let keys = self.key_parts(&request.key);
        let actual = request.actual.unwrap_or(request.estimate);
        let mut command = redis::cmd("EVAL");
        command.arg(RECONCILE_SCRIPT).arg(7);
        for key in &keys {
            command.arg(key);
        }
        command.arg(request.reservation_id).arg(actual);
        let mut connection = self.connection().await?;
        let response: Vec<i64> = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            command.query_async(&mut connection),
        )
        .await
        .map_err(|_error| BackendError::Unavailable("Valkey reconciliation timed out".into()))?
        .map_err(|e| BackendError::Unavailable(e.to_string()))?;
        match response.as_slice() {
            [0] => Ok(BackendSettlement::Noop),
            [1, actual, refund, overage] => Ok(BackendSettlement::Applied {
                actual: u64::try_from(*actual).map_err(|_error| BackendError::InvalidResponse)?,
                refund: u64::try_from(*refund).map_err(|_error| BackendError::InvalidResponse)?,
                overage: u64::try_from(*overage).map_err(|_error| BackendError::InvalidResponse)?,
            }),
            _ => Err(BackendError::InvalidResponse),
        }
    }

    fn enqueue_reconcile(&self, request: ReconcileRequest) -> Result<(), BackendError> {
        self.start_worker()?;
        self.reconcile_tx
            .try_send(request)
            .map_err(|error| BackendError::Unavailable(format!("reconciliation queue is full or stopped: {error}")))
    }

    fn limit(&self) -> u64 {
        self.limit
    }
}
