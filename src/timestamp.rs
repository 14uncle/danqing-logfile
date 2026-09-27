//! @author 十四叔
//! @date 2026/09/27
//!
//! 行首时间戳解析 (.log) 与 JSONL 时间戳取值 —— merge-timeline (腿一) 的引擎前置
//! (SPEC-v1x-merge-timeline 腿 A, T0 原型)。
//!
//! T0 范围: ISO-8601 / log4j 逗号毫秒 / epoch 秒/毫秒四种**手写**解析 + 行级
//! `probe_format` 探测雏形 —— 目标是支撑 T0c 的逐行提取成本实测 (plan R6 拆雷)。
//! 采样格式探测 (512 行/字节预算) 与 JSONL 字段名发现在 T1 完整化。
//!
//! 统一口径: 输出 i64 epoch **毫秒** (UTC)。无 tz 的时间戳按调用方给的
//! `local_offset_ms` 解释 —— 源时区/时钟偏移在解析边界**单源施加** (SPEC 腿 D),
//! 排序与显示必须同源, 不许两处各算一遍。

use crate::scan::{FieldKind, scan_field};

/// 首版格式集 (SPEC D2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsFormat {
    /// ISO-8601: `2026-09-27T14:32:01.123Z` —— 日期时间分隔 T 或空格, 小数 1–9 位
    /// (截/补到毫秒), 时区 Z / ±hh:mm / ±hhmm / 无 (无 = `local_offset_ms`)。
    Iso8601,
    /// log4j 系: `2026-09-27 14:32:01,123` —— 逗号毫秒恰好 3 位, 无 tz。
    Log4j,
    /// epoch 秒 (10 位量级)。
    EpochSecs,
    /// epoch 毫秒 (13 位量级)。
    EpochMillis,
}

impl TsFormat {
    /// 源管理弹层/真值表展示用名。
    pub fn label(&self) -> &'static str {
        match self {
            TsFormat::Iso8601 => "ISO-8601",
            TsFormat::Log4j => "log4j (,ms)",
            TsFormat::EpochSecs => "epoch 秒",
            TsFormat::EpochMillis => "epoch 毫秒",
        }
    }
}

/// 解析 .log 行首时间戳 → (epoch 毫秒, 消耗字节数); 行首不是该格式 → None。
pub fn parse_prefix(line: &[u8], fmt: TsFormat, local_offset_ms: i64) -> Option<(i64, usize)> {
    match fmt {
        TsFormat::Iso8601 => parse_iso(line, local_offset_ms),
        TsFormat::Log4j => parse_log4j(line, local_offset_ms),
        TsFormat::EpochSecs => parse_epoch(line, 1_000),
        TsFormat::EpochMillis => parse_epoch(line, 1),
    }
}

/// 行级格式探测 (T0 雏形 —— T1 换采样探测): 取行首试 log4j → ISO → epoch,
/// 首个命中的格式胜出。**log4j 必须先于 ISO**: log4j 逗号毫秒行的前 19 字节
/// 在 ISO「无小数+无 tz」口径下也合法, ISO 先探会把 `,123` 毫秒吃掉
/// (亚秒序全错); 反向无冲突 —— log4j 只收逗号, 不碰 ISO 的点小数。
/// 全不中 → None (调用方按「探测失败拒绝加入并明示」处理, SPEC D2)。
pub fn probe_format(line: &[u8]) -> Option<TsFormat> {
    if parse_log4j(line, 0).is_some() {
        return Some(TsFormat::Log4j);
    }
    if parse_iso(line, 0).is_some() {
        return Some(TsFormat::Iso8601);
    }
    // epoch: 行首一串数字 + 跟空白, 按位数分档 (T0 粗判, T1 钉边界)。
    let n = count_digits(line);
    if n > 0 && line.get(n).is_none_or(|&b| b == b' ' || b == b'\t') {
        match n {
            9..=11 => return Some(TsFormat::EpochSecs),
            12..=14 => return Some(TsFormat::EpochMillis),
            _ => {}
        }
    }
    None
}

/// JSONL 时间戳取值 (T0 雏形 —— 字段名固定在调用侧, 名发现在 T1):
/// 复用腿二 `scan_field` 通路; Str 必须整体是 ISO/log4j 时间串, Num 按量级分档
/// (≥1e12 判毫秒, 否则判秒; 浮点 epoch 不支持 —— T1 钉)。
pub fn parse_jsonl_field(line: &[u8], field: &str, local_offset_ms: i64) -> Option<i64> {
    let v = scan_field(line, field)?;
    match v.kind {
        FieldKind::Num => {
            let s = std::str::from_utf8(v.raw).ok()?;
            if let Ok(n) = s.parse::<i64>() {
                Some(if n.abs() >= 1_000_000_000_000 {
                    n
                } else {
                    n * 1000
                })
            } else {
                // 浮点 epoch (T1 钉): 量级分档同上, 小数截到毫秒。
                let f: f64 = s.parse().ok()?;
                let ms = if f.abs() >= 1e12 { f } else { f * 1000.0 };
                Some(ms as i64)
            }
        }
        FieldKind::Str => parse_time_str(v.raw, local_offset_ms),
        _ => None,
    }
}

/// 时间串解析 (ISO 或 log4j, **整串必须消完** —— 前缀命中尾巴带字的不是时间字段)。
fn parse_time_str(raw: &[u8], local_offset_ms: i64) -> Option<i64> {
    let (t, used) =
        parse_iso(raw, local_offset_ms).or_else(|| parse_log4j(raw, local_offset_ms))?;
    (used == raw.len()).then_some(t)
}

// ─── 内部: 手写解析 (零依赖, 不动 chrono —— SPEC 腿 A 决策) ───

/// 读 `n` 位定宽数字。
fn ndigits(line: &[u8], i: usize, n: usize) -> Option<u32> {
    let s = line.get(i..i + n)?;
    let mut v = 0u32;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(b - b'0');
    }
    Some(v)
}

/// 行首连续数字位数。
fn count_digits(line: &[u8]) -> usize {
    line.iter().take_while(|b| b.is_ascii_digit()).count()
}

/// 日期合法性 (月份/日/时分秒范围; 2 月 30 日这类「日对月错」不查 ——
/// 日志格式探测只要排除明显非日期, 日历真值由量级保证, T1 如需再紧)。
fn valid_hms(h: u32, m: u32, s: u32) -> bool {
    h < 24 && m < 60 && s <= 60 // 闰秒 60 容忍
}

/// days-from-civil (Howard Hinnant 算法, 无依赖): 公历日期 → 1970-01-01 起天数。
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m as i64 + 9) % 12; // [0, 11] (3 月 = 0)
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// 公历日期时间 → epoch 毫秒 (UTC 口径, 调用方已把本地时间折算成「伪 UTC」)。
fn civil_to_epoch_ms(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32, ms: u32) -> i64 {
    let days = days_from_civil(y, mo, d);
    ((days * 24 + i64::from(h)) * 60 + i64::from(mi)) * 60_000
        + i64::from(s) * 1_000
        + i64::from(ms)
}

/// ISO-8601 行首: `YYYY-MM-DD[T| ]HH:MM:SS[.f{1,9}][Z|±hh:mm|±hhmm]`。
fn parse_iso(line: &[u8], local_offset_ms: i64) -> Option<(i64, usize)> {
    if line.len() < 19 {
        return None;
    }
    let y = i64::from(ndigits(line, 0, 4)?);
    if *line.get(4)? != b'-' {
        return None;
    }
    let mo = ndigits(line, 5, 2)?;
    if *line.get(7)? != b'-' {
        return None;
    }
    let d = ndigits(line, 8, 2)?;
    if !matches!(line.get(10), Some(b'T') | Some(b' ')) {
        return None;
    }
    let h = ndigits(line, 11, 2)?;
    if *line.get(13)? != b':' {
        return None;
    }
    let mi = ndigits(line, 14, 2)?;
    if *line.get(16)? != b':' {
        return None;
    }
    let s = ndigits(line, 17, 2)?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || !valid_hms(h, mi, s) {
        return None;
    }
    let mut i = 19;
    // 小数秒: 1–9 位, 截/补到毫秒。
    let mut ms = 0u32;
    if line.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        let mut frac = 0u32;
        while i < line.len() && line[i].is_ascii_digit() && i - start < 9 {
            frac = frac * 10 + u32::from(line[i] - b'0');
            i += 1;
        }
        let ndig = i - start;
        if ndig == 0 {
            return None;
        }
        // 归一到毫秒: 少补多截。
        ms = match ndig {
            1 => frac * 100,
            2 => frac * 10,
            3 => frac,
            n => frac / 10u32.pow((n - 3) as u32),
        };
    }
    // 时区: Z / ±hh:mm / ±hhmm / 无。
    let tz_ms = match line.get(i) {
        Some(b'Z') => {
            i += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            i += 1;
            let th = ndigits(line, i, 2)?;
            i += 2;
            let tm = if line.get(i) == Some(&b':') {
                i += 1;
                let v = ndigits(line, i, 2)?;
                i += 2;
                v
            } else {
                let v = ndigits(line, i, 2)?;
                i += 2;
                v
            };
            if th > 23 || tm > 59 {
                return None;
            }
            let v = (i64::from(th) * 60 + i64::from(tm)) * 60_000;
            if *sign == b'-' { -v } else { v }
        }
        _ => local_offset_ms,
    };
    Some((civil_to_epoch_ms(y, mo, d, h, mi, s, ms) - tz_ms, i))
}

/// log4j 行首: `YYYY-MM-DD HH:MM:SS,mmm` (逗号毫秒恰好 3 位, 无 tz)。
fn parse_log4j(line: &[u8], local_offset_ms: i64) -> Option<(i64, usize)> {
    if line.len() < 23 {
        return None;
    }
    let y = i64::from(ndigits(line, 0, 4)?);
    if *line.get(4)? != b'-' {
        return None;
    }
    let mo = ndigits(line, 5, 2)?;
    if *line.get(7)? != b'-' {
        return None;
    }
    let d = ndigits(line, 8, 2)?;
    if *line.get(10)? != b' ' {
        return None;
    }
    let h = ndigits(line, 11, 2)?;
    if *line.get(13)? != b':' {
        return None;
    }
    let mi = ndigits(line, 14, 2)?;
    if *line.get(16)? != b':' {
        return None;
    }
    let s = ndigits(line, 17, 2)?;
    if *line.get(19)? != b',' {
        return None;
    }
    let ms = ndigits(line, 20, 3)?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || !valid_hms(h, mi, s) {
        return None;
    }
    Some((
        civil_to_epoch_ms(y, mo, d, h, mi, s, ms) - local_offset_ms,
        23,
    ))
}

/// epoch 行首: 一串数字, `scale` 毫秒/单位 (秒 = 1000, 毫秒 = 1)。
fn parse_epoch(line: &[u8], scale: i64) -> Option<(i64, usize)> {
    let n = count_digits(line);
    if n == 0 {
        return None;
    }
    let s = std::str::from_utf8(&line[..n]).ok()?;
    let v: i64 = s.parse().ok()?;
    Some((v * scale, n))
}

// ─── T1: 采样探测与每源通路结论 ───

use crate::logfile::LogFile;

/// 每源时间戳通路结论 (T1): 探测产物 —— 源管理弹层显示与提取调用同源一份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsRoute {
    /// .log 行首格式。
    LogPrefix(TsFormat),
    /// JSONL 顶层字段名。
    JsonlField(String),
}

/// 探测失败原因 (SPEC D2「拒绝加入并明示」的文案原料)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailure {
    /// 采样内命中的行首时间戳太少或为零 (.log)。
    NoTimestamp,
    /// 行首时间戳格式不一致 (同一文件命中 >1 种格式)。
    Inconsistent,
    /// JSONL 但常见时间字段名一个都没中 (或值全非时间形态)。
    NoTimeField,
}

impl ProbeFailure {
    /// 源管理弹层的明示文案 (单一出处, 措辞改动只动这里)。
    pub fn label(&self) -> &'static str {
        match self {
            ProbeFailure::NoTimestamp => "采样内未找到可解析的行首时间戳",
            ProbeFailure::Inconsistent => "行首时间戳格式不一致（命中多种格式）",
            ProbeFailure::NoTimeField => {
                "JSONL 未找到时间字段（试过的常见名: ts/timestamp/time/@timestamp）"
            }
        }
    }
}

/// JSONL 时间字段名优先序 (SPEC D2)。
const TS_FIELD_CANDIDATES: &[&str] = &["ts", "timestamp", "time", "@timestamp"];
/// 采样行数上限 (对齐 jsonl.rs SCHEMA_SAMPLE 纪律)。
const SAMPLE_LINES: u64 = 512;
/// 采样字节预算 (同 SCHEMA_SAMPLE_BYTES: 行宽无界时防探测吃掉打开路径)。
const SAMPLE_BYTES: usize = 4 << 20;
/// 最少采样行数 (证据不足不判)。
const SAMPLE_MIN_LINES: u64 = 6;
/// 命中率下限: 采样行中 ≥50% 命中才算通路成立 (其余行走 D1 继承)。
const SAMPLE_HIT_RATE: f64 = 0.5;

/// 采样探测每源通路 (SPEC 腿 A): JSONL → 字段名优先序; .log → 行首格式。
/// 失败给原因, **不静默猜** (D2: 猜错的时间线比没有更糟)。
pub fn detect_route(file: &LogFile) -> Result<TsRoute, ProbeFailure> {
    if crate::jsonl::detect(file) {
        return detect_jsonl_field(file);
    }
    detect_log_prefix(file)
}

/// JSONL 半: 按候选名优先序试, 首个命中率过线的字段胜出。
fn detect_jsonl_field(file: &LogFile) -> Result<TsRoute, ProbeFailure> {
    for name in TS_FIELD_CANDIDATES {
        let mut sampled = 0u64;
        let mut hit = 0u64;
        let mut bytes = 0usize;
        for (_no, line) in file.lines_from(0) {
            if sampled >= SAMPLE_LINES || (sampled >= SAMPLE_MIN_LINES && bytes >= SAMPLE_BYTES) {
                break;
            }
            bytes += line.len();
            if line.is_empty() {
                continue;
            }
            sampled += 1;
            if parse_jsonl_field(line, name, 0).is_some() {
                hit += 1;
            }
        }
        if sampled >= 3 && hit as f64 >= sampled as f64 * SAMPLE_HIT_RATE {
            return Ok(TsRoute::JsonlField((*name).to_string()));
        }
    }
    Err(ProbeFailure::NoTimeField)
}

/// .log 半: 行首 probe (continuation 行不参评), 命中率过线且格式单一才成立。
fn detect_log_prefix(file: &LogFile) -> Result<TsRoute, ProbeFailure> {
    let mut sampled = 0u64;
    let mut hits: Vec<TsFormat> = Vec::new();
    let mut bytes = 0usize;
    for (_no, line) in file.lines_from(0) {
        if sampled >= SAMPLE_LINES || (sampled >= SAMPLE_MIN_LINES && bytes >= SAMPLE_BYTES) {
            break;
        }
        bytes += line.len();
        // continuation (空白开头) 不参评 —— stack trace 行没有行首时间戳是常态。
        if line.is_empty() || matches!(line[0], b' ' | b'\t') {
            continue;
        }
        sampled += 1;
        if let Some(fmt) = probe_format(line) {
            hits.push(fmt);
        }
    }
    if hits.is_empty() || sampled < 3 || (hits.len() as f64) < sampled as f64 * SAMPLE_HIT_RATE {
        return Err(ProbeFailure::NoTimestamp);
    }
    if hits.iter().any(|f| *f != hits[0]) {
        return Err(ProbeFailure::Inconsistent);
    }
    Ok(TsRoute::LogPrefix(hits[0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 已知真值: 2026-09-27T00:00:00Z (2026-01-01 = 1767225600 + 269 天)。
    const BASE_S: i64 = 1_790_467_200;
    const BASE_MS: i64 = BASE_S * 1000;

    // ─── ISO-8601 ───

    #[test]
    fn iso_zulu_basic() {
        let (t, used) = parse_iso(b"2026-09-27T00:00:00Z INFO boot", 0).unwrap();
        assert_eq!(t, BASE_MS);
        assert_eq!(
            &line_at(b"2026-09-27T00:00:00Z INFO boot", used),
            b" INFO boot"
        );
    }

    #[test]
    fn iso_fraction_and_space_separator() {
        let (t, _) = parse_iso(b"2026-09-27 01:02:03.456 x", 0).unwrap();
        assert_eq!(t, BASE_MS + 3_723_000 + 456);
        // 1 位小数 = .4 秒
        let (t2, _) = parse_iso(b"2026-09-27T00:00:00.4Z", 0).unwrap();
        assert_eq!(t2, BASE_MS + 400);
        // 9 位小数截到毫秒
        let (t3, _) = parse_iso(b"2026-09-27T00:00:00.123456789Z", 0).unwrap();
        assert_eq!(t3, BASE_MS + 123);
    }

    #[test]
    fn iso_explicit_tz_offsets() {
        // +08:00 的 08:00 = UTC 00:00
        let (t, _) = parse_iso(b"2026-09-27T08:00:00+08:00", 999).unwrap();
        assert_eq!(t, BASE_MS);
        // -0230 (= -2:30) 的 前一日 21:30 = UTC 00:00
        let (t2, _) = parse_iso(b"2026-09-26T21:30:00-0230", 0).unwrap();
        assert_eq!(t2, BASE_MS);
    }

    #[test]
    fn iso_no_tz_uses_local_offset() {
        // 无 tz: 按调用方给的源时区解释 (东八区 = -8h 的偏移施加方向)。
        let (t, _) = parse_iso(b"2026-09-27T08:00:00", 8 * 3_600_000).unwrap();
        assert_eq!(t, BASE_MS);
    }

    #[test]
    fn iso_rejects_garbage() {
        assert!(parse_iso(b"2026-13-27T00:00:00Z", 0).is_none()); // 月 13
        assert!(parse_iso(b"2026-09-27T25:00:00Z", 0).is_none()); // 时 25
        assert!(parse_iso(b"2026-09-27X00:00:00Z", 0).is_none()); // 分隔符错
        assert!(parse_iso(b"not a timestamp at all", 0).is_none());
        assert!(parse_iso(b"2026-09-27T00:00:00.Z", 0).is_none()); // 空小数
    }

    // ─── log4j ───

    #[test]
    fn log4j_comma_millis() {
        let (t, used) = parse_log4j(b"2026-09-27 00:00:00,123 ERROR boom", 0).unwrap();
        assert_eq!(t, BASE_MS + 123);
        assert_eq!(used, 23);
    }

    #[test]
    fn log4j_rejects_dot_and_short() {
        // 点毫秒归 ISO (空格分隔同构), log4j 口径只收逗号
        assert!(parse_log4j(b"2026-09-27 00:00:00.123", 0).is_none());
        assert!(parse_log4j(b"2026-09-27 00:00:00,12", 0).is_none());
    }

    // ─── epoch ───

    #[test]
    fn epoch_secs_and_millis() {
        let (t, used) = parse_epoch(b"1790467200 INFO", 1_000).unwrap();
        assert_eq!(t, BASE_MS);
        assert_eq!(used, 10);
        let (t2, _) = parse_epoch(b"1790467200123 INFO", 1).unwrap();
        assert_eq!(t2, BASE_MS + 123);
    }

    // ─── probe / jsonl ───

    #[test]
    fn probe_routes_by_shape() {
        assert_eq!(
            probe_format(b"2026-09-27T00:00:00Z INFO"),
            Some(TsFormat::Iso8601)
        );
        assert_eq!(
            probe_format(b"2026-09-27 00:00:00,123 ERROR"),
            Some(TsFormat::Log4j)
        );
        assert_eq!(probe_format(b"1790467200 INFO"), Some(TsFormat::EpochSecs));
        assert_eq!(
            probe_format(b"1790467200123 INFO"),
            Some(TsFormat::EpochMillis)
        );
        assert_eq!(probe_format(b"INFO no ts here"), None);
    }

    #[test]
    fn jsonl_field_str_and_num() {
        let line = br#"{"ts":"2026-09-27T00:00:00.5Z","level":"INFO"}"#;
        assert_eq!(parse_jsonl_field(line, "ts", 0), Some(BASE_MS + 500));
        let line2 = br#"{"ts":1790467200,"level":"INFO"}"#;
        assert_eq!(parse_jsonl_field(line2, "ts", 0), Some(BASE_MS));
        let line3 = br#"{"ts":1790467200123,"level":"INFO"}"#;
        assert_eq!(parse_jsonl_field(line3, "ts", 0), Some(BASE_MS + 123));
        // 无 ts 字段 / 值不是时间 → None (继承上一行, merge 侧语义)
        let line4 = br#"{"level":"INFO","msg":"no ts"}"#;
        assert_eq!(parse_jsonl_field(line4, "ts", 0), None);
        // 字符串前缀像时间但尾巴带字 → 不是时间字段
        let line5 = br#"{"ts":"2026-09-27T00:00:00Z and then some","level":"INFO"}"#;
        assert_eq!(parse_jsonl_field(line5, "ts", 0), None);
    }

    // ─── T1: 采样探测 (detect_route) ───

    /// 临时 fixture (每用例独立名, 收尾删)。
    fn temp_file(name: &str, content: &[u8]) -> (std::path::PathBuf, LogFile) {
        let p = std::env::temp_dir().join(format!("danqing-ts-test-{name}.log"));
        std::fs::write(&p, content).unwrap();
        let f = LogFile::open(&p).unwrap();
        (p, f)
    }

    #[test]
    fn ts_route_jsonl_field_priority_order() {
        // 同时有 time (epoch 数) 与 ts (ISO 串): 优先序 ts 胜出。
        let (p, f) = temp_file(
            "prio",
            br#"{"time":1790467200123,"ts":"2026-09-27T00:00:00Z","level":"INFO"}
{"time":1790467200456,"ts":"2026-09-27T00:00:01Z","level":"INFO"}
{"time":1790467200789,"ts":"2026-09-27T00:00:02Z","level":"INFO"}
"#,
        );
        let route = detect_route(&f).unwrap();
        assert_eq!(route, TsRoute::JsonlField("ts".to_string()));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn ts_route_jsonl_epoch_num_and_float() {
        let (p, f) = temp_file(
            "epochnum",
            br#"{"timestamp":1790467200,"level":"INFO"}
{"timestamp":1790467201,"level":"INFO"}
{"timestamp":1790467202,"level":"INFO"}
"#,
        );
        assert_eq!(
            detect_route(&f).unwrap(),
            TsRoute::JsonlField("timestamp".to_string())
        );
        std::fs::remove_file(&p).ok();
        // 浮点 epoch (T1 钉): 秒.小数 → 毫秒。
        let line = br#"{"ts":1790467200.5,"level":"INFO"}"#;
        assert_eq!(parse_jsonl_field(line, "ts", 0), Some(BASE_MS + 500));
    }

    #[test]
    fn ts_route_log_iso_and_log4j() {
        let (p, f) = temp_file(
            "logiso",
            b"2026-09-27T00:00:00Z INFO a\n2026-09-27T00:00:01Z INFO b\n2026-09-27T00:00:02Z INFO c\n",
        );
        assert_eq!(
            detect_route(&f).unwrap(),
            TsRoute::LogPrefix(TsFormat::Iso8601)
        );
        std::fs::remove_file(&p).ok();
        let (p2, f2) = temp_file(
            "loglog4j",
            b"2026-09-27 00:00:00,123 INFO a\n2026-09-27 00:00:01,456 INFO b\n2026-09-27 00:00:02,789 INFO c\n",
        );
        assert_eq!(
            detect_route(&f2).unwrap(),
            TsRoute::LogPrefix(TsFormat::Log4j)
        );
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn ts_route_no_timestamp_rejected() {
        let (p, f) = temp_file(
            "nots",
            b"INFO boot\nhello world\njust text\nmore plain lines\n",
        );
        assert_eq!(detect_route(&f), Err(ProbeFailure::NoTimestamp));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn ts_route_jsonl_no_time_field_rejected() {
        let (p, f) = temp_file(
            "nofield",
            br#"{"level":"INFO","msg":"a"}
{"level":"WARN","msg":"b"}
{"level":"ERROR","msg":"c"}
"#,
        );
        assert_eq!(detect_route(&f), Err(ProbeFailure::NoTimeField));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn ts_route_inconsistent_rejected() {
        // ISO 与 epoch 前缀交替 → Inconsistent (不猜)。
        let (p, f) = temp_file(
            "mixed",
            b"2026-09-27T00:00:00Z INFO a\n1790467201 INFO b\n2026-09-27T00:00:02Z INFO c\n1790467203 INFO d\n",
        );
        assert_eq!(detect_route(&f), Err(ProbeFailure::Inconsistent));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn ts_route_hit_rate_with_continuations() {
        // 4 条行首 ts + 4 条 continuation (不参评) + 1 条无 ts 行首 → 命中 4/5 ≥ 50% 成立。
        let (p, f) = temp_file(
            "hitrate",
            b"2026-09-27T00:00:00Z INFO a\n    at stack.X(F.java:1)\n2026-09-27T00:00:01Z INFO b\n    at stack.Y(F.java:2)\n2026-09-27T00:00:02Z INFO c\nno timestamp here\n2026-09-27T00:00:03Z INFO d\n    at stack.Z(F.java:3)\n    at stack.W(F.java:4)\n",
        );
        assert_eq!(
            detect_route(&f).unwrap(),
            TsRoute::LogPrefix(TsFormat::Iso8601)
        );
        std::fs::remove_file(&p).ok();
        // 命中率 <50% (1/4) → NoTimestamp。
        let (p2, f2) = temp_file(
            "lowhit",
            b"2026-09-27T00:00:00Z INFO a\nplain one\nplain two\nplain three\n",
        );
        assert_eq!(detect_route(&f2), Err(ProbeFailure::NoTimestamp));
        std::fs::remove_file(&p2).ok();
    }

    fn line_at(line: &[u8], i: usize) -> &[u8] {
        &line[i..]
    }
}
