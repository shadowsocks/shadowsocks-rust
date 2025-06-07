//! Server latency statistic

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Interval between each check
pub const DEFAULT_CHECK_INTERVAL_SEC: u64 = 10;
/// Timeout of each check
pub const DEFAULT_CHECK_TIMEOUT_SEC: u64 = 5; // A common connection timeout of 5 seconds.

/// Statistic score
#[derive(Debug, Copy, Clone)]
pub enum Score {
    /// Unified latency
    Latency(u32),
    /// Request error
    Errored,
}

/// Server statistic data
#[derive(Debug, Clone, Copy)]
pub struct ServerStatData {
    /// Median of latency time (in millisec)
    ///
    /// Use median instead of average time,
    /// because probing result may have some really bad cases
    pub latency_median: u32,
    /// Total_Fail / Total_Probe
    pub fail_rate: f64,
    /// Score's standard deviation
    pub latency_stdev: f64,
    /// Score's average
    pub latency_mean: f64,
    /// Score's median absolute deviation
    pub latency_mad: u32,
}

/// Statistic of a remote server
#[derive(Debug)]
pub struct ServerStat {
    /// MAX server's RTT, normally the check timeout milliseconds
    max_server_rtt: u32,
    /// Recently probe data
    latency_queue: VecDeque<(Score, Instant)>,
    /// Score's standard deviation MAX
    max_latency_stdev: f64,
    /// User's customized weight
    user_weight: f32,
    /// Checking window size
    check_window: Duration,
    /// Statistic Data
    data: ServerStatData,
}

fn max_latency_stdev(max_server_rtt: u32) -> f64 {
    let mrtt = max_server_rtt as f64;
    let avg = (0.0 + mrtt) / 2.0;
    let diff1 = (0.0 - avg) * (0.0 - avg);
    let diff2 = (mrtt - avg) * (mrtt - avg);
    // (1.0 / (2.0 - 1.0)) * (diff1 + diff2).sqrt()
    (diff1 + diff2).sqrt()
}

impl ServerStat {
    pub fn new(user_weight: f32, max_server_rtt: u32, check_window: Duration) -> Self {
        assert!((0.0..=1.0).contains(&user_weight));

        let max_latency_stdev = max_latency_stdev(max_server_rtt);
        Self {
            max_server_rtt,
            latency_queue: VecDeque::new(),
            max_latency_stdev,
            user_weight,
            check_window,
            data: ServerStatData {
                latency_median: max_server_rtt,
                fail_rate: 1.0,
                latency_stdev: max_latency_stdev,
                latency_mean: max_server_rtt as f64,
                latency_mad: max_server_rtt,
            },
        }
    }

    fn score(&self) -> u32 {
        // Normalize rtt
        let nrtt = self.data.latency_median as f64 / self.max_server_rtt as f64;

        // Normalize stdev
        // let nstdev = self.data.latency_stdev / self.max_latency_stdev;
        // Mormalize mad
        let nmad = self.data.latency_mad as f64 / self.max_server_rtt as f64;

        const SCORE_RTT_WEIGHT: f64 = 1.0;
        const SCORE_FAIL_WEIGHT: f64 = 3.0;
        // const SCORE_STDEV_WEIGHT: f64 = 0.0;
        const SCORE_MAD_WEIGHT: f64 = 1.0;

        // [EPSILON, 1]
        // Just for avoiding divide by 0
        let user_weight = self.user_weight.max(f32::EPSILON);

        // Score = (norm_lat * 1.0 + prop_err * 3.0 + (stdev || mad) * 1.0) / 5.0 / user_weight
        //
        // 1. The lower latency, the better
        // 2. The lower errored count, the better
        // 3. The lower latency's stdev / mad, the better
        // 4. The higher user's weight, the better
        let score = (nrtt * SCORE_RTT_WEIGHT + self.data.fail_rate * SCORE_FAIL_WEIGHT + nmad * SCORE_MAD_WEIGHT)
            / (SCORE_RTT_WEIGHT + SCORE_FAIL_WEIGHT + SCORE_MAD_WEIGHT)
            / user_weight as f64;

        // Times 10000 converts to u32, for 0.0001 precision
        (score * 10000.0) as u32
    }

    pub fn push_score(&mut self, score: Score) -> u32 {
        let now = Instant::now();

        self.latency_queue.push_back((score, now));

        // Removes stats that are not in the check window
        while let Some((_, inst)) = self.latency_queue.front() {
            if now - *inst > self.check_window {
                self.latency_queue.pop_front();
            } else {
                break;
            }
        }

        self.recalculate_score()
    }

    fn recalculate_score(&mut self) -> u32 {
        if self.latency_queue.is_empty() {
            return self.score();
        }

        let mut vlat = Vec::with_capacity(self.latency_queue.len());
        let mut cerr = 0;
        for (s, _) in &self.latency_queue {
            match *s {
                Score::Errored => cerr += 1,
                Score::Latency(lat) => vlat.push(lat),
            }
        }

        // Error rate
        self.data.fail_rate = cerr as f64 / self.latency_queue.len() as f64;

        self.data.latency_median = self.max_server_rtt;
        self.data.latency_stdev = self.max_latency_stdev;
        self.data.latency_mean = self.max_server_rtt as f64;
        self.data.latency_mad = self.max_server_rtt;

        if !vlat.is_empty() {
            vlat.sort_unstable();

            // Find median of latency
            let mid = vlat.len() / 2;

            self.data.latency_median = if vlat.len() % 2 == 0 {
                (vlat[mid] + vlat[mid - 1]) / 2
            } else {
                vlat[mid]
            };

            if vlat.len() > 1 {
                let n = vlat.len() as f64;

                // mean
                let total_lat: u32 = vlat.iter().sum();
                self.data.latency_mean = total_lat as f64 / n;

                // STDEV
                let acc_mean_diff_square: f64 = vlat
                    .iter()
                    .map(|s| {
                        let diff = *s as f64 - self.data.latency_mean;
                        diff * diff
                    })
                    .sum();
                // Corrected Sample Standard Deviation
                self.data.latency_stdev = (acc_mean_diff_square / (n - 1.0)).sqrt();

                // MAD
                let mut vlat_abs_diff: Vec<u32> = vlat
                    .iter()
                    .map(|s| (*s as i32 - self.data.latency_median as i32).unsigned_abs())
                    .collect();
                vlat_abs_diff.sort_unstable();

                let abs_diff_median_mid = vlat_abs_diff.len() / 2;
                self.data.latency_mad = if vlat_abs_diff.len() % 2 == 0 {
                    (vlat_abs_diff[abs_diff_median_mid] + vlat_abs_diff[abs_diff_median_mid - 1]) / 2
                } else {
                    vlat_abs_diff[abs_diff_median_mid]
                };
            } else {
                self.data.latency_mean = vlat[0] as f64;
                self.data.latency_mad = 0;
            }
        }

        self.score()
    }

    pub fn data(&self) -> &ServerStatData {
        &self.data
    }
}
