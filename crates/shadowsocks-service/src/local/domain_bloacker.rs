use std::{marker::PhantomData, path::Path, str::FromStr};

use chrono::*;
#[derive(Debug)]
pub struct TimeRange<T, G>
where
    T: TimeZone,
{
    start: NaiveTime,
    end: NaiveTime,
    is_start_end_same_time: bool,
    _generator: PhantomData<G>,
    _tz: PhantomData<T>,
}

#[derive(Debug)]
pub struct LocalTime {
    tz: DateTime<Local>,
}
impl DateTimeGenerator<Local> for LocalTime {
    fn now() -> DateTime<Local> {
        Local::now()
    }
}

pub trait DateTimeGenerator<T: TimeZone> {
    fn now() -> DateTime<T>;
}
// 案件期間が重要になってきたら、案件期間はDateTimeで判定する
// その日中の時刻についてはNaiveTimeで処理する
// 案件期間とその日中の時間で優先すべきは案件期間の時刻とする。
//
impl<T, G> TimeRange<T, G>
where
    T: TimeZone,
    G: DateTimeGenerator<T>,
{
    fn new(start: NaiveTime, end: NaiveTime) -> Self {
        TimeRange {
            start,
            end,
            is_start_end_same_time: start == end,
            _generator: PhantomData,
            _tz: PhantomData,
        }
    }

    fn with_in_range(&self) -> bool {
        if self.is_start_end_same_time {
            return true;
        }
        let now = G::now();
        let start = self.start.clone();
        let (s_h, s_m) = (start.hour(), start.minute());
        let end = self.end.clone();
        let (mut e_h, e_m) = (end.hour(), end.minute());
        let (mut h, m) = (now.hour(), now.minute());
        // 終了時刻よりも開始時刻のほうが大きい場合（23時00分～09時00分）が指定されていた場合は、終了時刻に24時間を足し、23時00分～33時00分と扱うようにする。
        // 現在時刻も合わせて24足して考える。
        let serialize_start = s_h * 60 + s_m;
        let serialize_end = e_h * 60 + e_m;
        if serialize_start > serialize_end {
            e_h += 24;
            // 開始時刻よりも現在時刻が小さいなら、24足す
            // 0時なら、24となるため、22時開始の場合、現在時刻が24時となる。
            // 逆に、現在時刻が21時かつ、開始時刻が22時の場合、21+24=45となり、範囲超過判定されるようになる。
            // 開始時刻が9時の場合も同様で、現在時刻が8時の場合は、8+24=32となるため範囲超過判定される。
            if h < s_h {
                h += 24;
            }
        }
        let serialize_now = h * 60 + m;
        let serialize_end = e_h * 60 + e_m;
        if serialize_start <= serialize_now && serialize_now < serialize_end {
            true
        } else {
            false
        }
    }
}
#[derive(Debug)]
pub struct Domain {
    domain_str: String,
    allow_time: TimeRange<Local, LocalTime>,
}
impl Domain {
    fn new<S: Into<String>>(domain: S, start_time: NaiveTime, end_time: NaiveTime) -> Self {
        Domain {
            domain_str: domain.into(),
            allow_time: TimeRange::new(start_time, end_time),
        }
    }
}
pub fn get_config_path() -> String {
    "domains.toml".to_owned()
}
use notify::{event::ModifyKind, windows::*, *};
use once_cell::sync::*;
use std::sync::Mutex;
static mut EVENT_CHATTER: Lazy<Mutex<usize>> = Lazy::new(|| Mutex::new(0));
pub static TRAFFIC_CONTROLLER: Lazy<std::sync::RwLock<TrafficController>> =
    once_cell::sync::Lazy::new(|| std::sync::RwLock::new(TrafficController::new()));
pub static mut CONFIG_WATCHER: Lazy<Mutex<ReadDirectoryChangesWatcher>> = Lazy::new(|| {
    Mutex::new(
        notify::recommended_watcher(|res: std::result::Result<Event, Error>| match res {
            Ok(event) => {
                let config_path = get_config_path();
                let conf = std::fs::canonicalize(Path::new(&config_path)).unwrap();
                let mut do_reload = false;
                match event.kind {
                    EventKind::Modify(ModifyKind::Any) => {
                        for path in event.paths {
                            if path.cmp(&conf) == std::cmp::Ordering::Equal {
                                do_reload = true;
                            }
                        }
                    }
                    t => {
                        println!("{t:?}");
                    }
                }
                if do_reload {
                    // ファイル変更イベントはアホみたいに来るので、最後の1個だけ処理するようにする。
                    // チャタリング対策というやつ
                    unsafe {
                        let mut chatter_cnt = EVENT_CHATTER.lock().unwrap();
                        *chatter_cnt += 1;
                    }
                    async_std::task::spawn(wait_flush());
                }
            }
            Err(e) => {
                eprintln!("設定ファイルの監視/リロードに失敗しました。\n{e:?}");
            }
        })
        .unwrap(),
    )
});
use toolbox::config_loader::ConfigLoader;
fn show_config(domain: DomainSet) {
    eprintln!(
        "domain.start_time:{}\ndomain.end_time:{}\ndomain.domain{}",
        domain.start_time, domain.end_time, domain.domain
    );
}
const NAIVE_TIME_FORMAT: &str = "%H:%M";
// ファイルがフラッシュされるであろう時まで待つ
// 100msも待てばまぁ良いでしょう。
async fn wait_flush() {
    let wait_time = 100;
    std::thread::sleep(std::time::Duration::from_millis(wait_time));
    unsafe {
        let mut chatter_cnt = EVENT_CHATTER.lock().unwrap();
        *chatter_cnt -= 1;
        if *chatter_cnt == 0 {
            // 100ms（チャタリング判定時間）以内に到達したイベントの一番最後なので設定ファイルをロードする
            load_config();
            println!("設定ファイルをリロードしました。");
        }
    }
}
pub fn load_config() {
    let config: TrafficControllerConfig = ConfigLoader::load_file(&get_config_path());
    let mut ctl = TRAFFIC_CONTROLLER.write().unwrap();
    ctl.ban_domain_list.clear();
    for domain in config.domain_list {
        let start = match NaiveTime::parse_from_str(&domain.start_time, NAIVE_TIME_FORMAT) {
            Ok(time) => time,
            Err(_) => {
                show_config(domain);
                continue;
            }
        };
        let end = match NaiveTime::parse_from_str(&domain.end_time, NAIVE_TIME_FORMAT) {
            Ok(time) => time,
            Err(_) => {
                show_config(domain);
                continue;
            }
        };
        ctl.ban_domain_list.push(Domain::new(domain.domain, start, end));
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DomainSet {
    start_time: String,
    end_time: String,
    domain: String,
}
impl Default for DomainSet {
    fn default() -> Self {
        DomainSet {
            start_time: "09:30".to_owned(),
            end_time: "17:30".to_owned(),
            domain: "example.com".to_owned(),
        }
    }
}

use ::serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficControllerConfig {
    domain_list: Vec<DomainSet>,
}
impl Default for TrafficControllerConfig {
    fn default() -> Self {
        TrafficControllerConfig {
            domain_list: vec![DomainSet::default()],
        }
    }
}

pub struct TrafficController {
    ban_domain_list: Vec<Domain>,
}
impl TrafficController {
    pub fn new() -> Self {
        TrafficController {
            ban_domain_list: Vec::new(),
        }
    }
    pub fn allow_access<S: Into<String>>(&self, domain_string: S) -> std::result::Result<(), std::io::Error> {
        let domain_string = domain_string.into();
        for domain in &self.ban_domain_list {
            // 部分一致すればブロックする。
            if !domain.allow_time.with_in_range() && domain_string.contains(&domain.domain_str) {
                let s = format!("診断時間を超過しているため、 {} への通信をブロックしました。", domain_string);
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, s));
            }
        }
        Ok(())
    }
    pub fn allow_access_for_buffer(&self, buff: &[u8]) -> std::result::Result<(), std::io::Error> {
        let mut s = Vec::new();
        const REQUEST_LINE_MAX: usize = 2048;
        let mut cnt = 0;
        for d in buff {
            if *d != 0x0a && *d != 0x0d {
                if cnt <= REQUEST_LINE_MAX {
                    s.push(*d as u8);
                    cnt += 1;
                } else {
                    // 1行が2048バイト以上に成ったらリクエストラインではないと判断して全部捨てる。
                    s.clear();
                    break;
                }
            } else {
                if let Ok(mut s1) = String::from_utf8(s.clone()) {
                    s.clear();
                    let mut is_http_traffic = false;
                    // HTTP メソッドっぽいやつが来た
                    for method in [
                        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
                    ] {
                        if s1.starts_with(method) {
                            is_http_traffic = true;
                        }
                    }
                    if is_http_traffic {
                        loop {
                            let s1_new = s1.replace("  ", " ");
                            if s1 == s1_new {
                                s1 = s1_new;
                                break;
                            }
                        }
                        let split = s1.split(" ").collect::<Vec<&str>>();
                        if split.len() == 3 {
                            return self.allow_access(split[1]);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
