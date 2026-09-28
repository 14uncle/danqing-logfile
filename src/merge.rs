//! @author 十四叔
//! @date 2026/09/27
//!
//! 合并索引 —— 多源按时间戳归并成一条时间线 (merge-timeline 腿一, T0 原型)。
//!
//! 归并语义 (SPEC-v1x-merge-timeline D1): k-way **min-head 游标** ——
//! 每步取各源游标头里时间戳最小者出列。两个推论直接落地 D1:
//! - **文件内行序严格保持** (同一源后行永不超越前行) = 「乱序超窗钉住」的自然形态,
//!   乱序行只在成为游标头时按当时最小值找位, 不回头重排已出列的行;
//! - **等时间戳 tie-break 源序号小者先**, 同源保文件行序 —— 稳定可复现, 测试可断言。
//!
//! 无时间戳行 (stack trace continuation): 提取时**继承上一行时间戳** (D1);
//! 文件首行段全无 ts 的, 回填**第一个已知时间戳** (首行继承第二行)。
//!
//! 乱序窗口语义细化与增量 append (live-tail 合流) 在 T2 完整化;
//! 显式窗口是否必要以 T0c 实测与乱序 fixture 对拍后裁定 (spec Q5)。

use crate::logfile::LogFile;

/// 合并行: 时间戳 + 源序号 + 文件行号 —— 16B 物化 (D10 红线口径 = 总行数 ×16B)。
///
/// 行号用 u32: 单源 ≤ 10GB (SPEC D7) ≈ 6.4 千万行, 离 u32 上界两个量级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeRow {
    /// epoch 毫秒 (提取口径, 已含源时区/时钟偏移)。
    pub ts: i64,
    /// 源序号 (归并输入序)。
    pub src: u32,
    /// 文件行号 (0-based)。
    pub line: u32,
}

/// 物化合并索引 —— 时间线第 `pos` 行 = `rows[pos]`。
pub struct MergeIndex {
    rows: Vec<MergeRow>,
}

impl MergeIndex {
    /// 时间线行数。
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// 时间线行数是否为 0 (clippy: len_without_is_empty)。
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// 第 pos 行。
    pub fn row(&self, pos: usize) -> MergeRow {
        self.rows[pos]
    }

    /// 全行切片 (测试与小范围消费; 大索引别拿来遍历玩)。
    pub fn rows(&self) -> &[MergeRow] {
        &self.rows
    }

    /// 驻留字节 (D10 口径 = 行数 ×16B)。**不含**建索引时为增量追加留的位
    /// ([`APPEND_SLACK_DIV`], ≤6.25%) —— 口径仍是「16 B/行」, 超募单列。
    pub fn index_bytes(&self) -> usize {
        self.rows.len() * size_of::<MergeRow>()
    }
}

/// 一个源的归并原料: 每行时间戳 (无 ts 行已继承)。
pub struct SourceTimeline<'a> {
    /// 源文件 (行内容经它随机访问)。
    pub file: &'a LogFile,
    /// 每行 epoch 毫秒, 下标 = 文件行号。
    pub ts: Vec<i64>,
}

impl SourceTimeline<'_> {
    /// ts 向量的驻留字节 (实测报告用 —— 归并完成后它退役, 峰值内存的另一半)。
    pub fn ts_bytes(&self) -> usize {
        self.ts.len() * size_of::<i64>()
    }
}

/// 逐行提取建时间线: 无 ts 行继承上一行; 前导无 ts 段回填第一个已知值。
///
/// `extract` 返回 None 的行 = continuation (stack trace / 无 ts 字段的 JSONL 行)。
/// 全文件零 ts → 全 0 (探测层在 SPEC D2 已拒绝这种源, 这里不猜不炸)。
pub fn extract_timeline(file: &LogFile, mut extract: impl FnMut(&[u8]) -> Option<i64>) -> Vec<i64> {
    let mut ts: Vec<i64> = Vec::with_capacity(file.line_count() as usize);
    let mut last = 0i64;
    let mut seen_any = false;
    for (_line_no, line) in file.lines_from(0) {
        match extract(line) {
            Some(t) => {
                if !seen_any {
                    // 首行段回填: 前面的占位全改成本值 (首行继承第二行, D1 边界)。
                    for slot in ts.iter_mut() {
                        *slot = t;
                    }
                    seen_any = true;
                }
                last = t;
                ts.push(t);
            }
            None => ts.push(last),
        }
    }
    ts
}

/// 增量提取 (live-tail, T2): 从 `from_line` 起把新行追加进既有 ts 向量。
/// 继承语义同 [`extract_timeline`]: 无 ts 新行继承向量末值。
/// `from_line` 必须 == ts.len() —— 增量拼接不跳行, 断言即锁。
pub fn extract_append(
    file: &LogFile,
    ts: &mut Vec<i64>,
    from_line: u64,
    mut extract: impl FnMut(&[u8]) -> Option<i64>,
) {
    assert_eq!(
        ts.len(),
        from_line as usize,
        "增量提取跳行: ts {} 行 vs from_line {from_line}",
        ts.len()
    );
    let mut last = ts.last().copied().unwrap_or(0);
    for (_line_no, line) in file.lines_from(from_line) {
        match extract(line) {
            Some(t) => {
                last = t;
                ts.push(t);
            }
            None => ts.push(last),
        }
    }
}

/// 摘除回找上限 (文档化兜底): 目标是**该源最后一行**, 天然近尾; 超此帽即判
/// 找不到 → 调用方兜底全量重建 (诚实, 不静默留幽灵)。**只用于 [`MergeIndex::remove_row`]**
/// —— 插入侧 T9 起不再设帽 (见 [`MergeIndex::insert_rows`])。
const WALK_CAP: usize = 1_000_000;

/// 排序键 (与归并 tie-break 同规则): (ts, src, line) 字典序。
fn key_of(r: &MergeRow) -> (i64, u32, u32) {
    (r.ts, r.src, r.line)
}

/// 索引容量追加留位分母 (T9): 建索引时多留 `total / 此值` 个槽位, live-tail
/// 的增量插入不撞容量上限 —— 否则 `Vec` 的翻倍重分配会让一次追加拷整个索引
/// (17M 行实测 ~80 ms) 且驻留翻倍。1/16 = 6.25% 超募, 掉出留位时才重分配一次。
pub const APPEND_SLACK_DIV: usize = 16;

impl MergeIndex {
    /// 单源增量合流 (live-tail 腿 F 引擎半): 新行 (ts, 文件行号) 按**源行序**给,
    /// **整批一次归并插入**。排序键 = (ts, src, line) 字典序 —— 与归并 tie-break
    /// 同规则 (等 ts: 源序号小者先, 同源行号小者先); 等键时新行插在既有行**之后**
    /// (与逐行插入同语义)。
    ///
    /// **为什么整批单遍** (T9 实测 3×1GiB 定案): 逐行 `Vec::insert` 每行付两笔 ——
    /// 回找距离 + 该位置到尾部的位移, 都随**回找深度**走。批量追尾时新行互为障碍
    /// (Σ 深度 ≈ k²/2: 4 MiB / 2.6 万行实测 **~750 ms**); 慢时钟源更糟 (深度触帽,
    /// 每行常数 **2.45 ms**: 2 万行实测 **48 s**, 且落的是近似位)。整批形态把两笔
    /// 合一: 一次回找定位 + **一趟反向合并** (写指针恒 ≥ 读指针, 原地覆盖安全),
    /// 代价 O(批行数 + 回找深度)。
    ///
    /// **回找不再设帽** (T9 改判): 单遍下深回找只付一次 (2M 行 ≈ 数 ms), 于是
    /// **插入位精确** —— 旧的「超帽插在近似位」语义退役 (spec Q5 回写)。
    ///
    /// 注意: 索引在乱序下不保证全局 ts 有序 (D1 钉住), 故不能用二分 ——
    /// 从尾部线性回找是唯一诚实形态。
    pub fn insert_rows(&mut self, src: u32, new_rows: &[(i64, u32)]) {
        if new_rows.is_empty() {
            return;
        }
        // 批序 = (ts, line) 稳定序 (同源, 故 = 全键序); 等 ts 保文件行序。
        let mut batch: Vec<MergeRow> = new_rows
            .iter()
            .map(|&(ts, line)| MergeRow { ts, src, line })
            .collect();
        batch.sort_by_key(|r| (r.ts, r.line));

        let start = self.slot_of(batch[0]);
        let (len, k) = (self.rows.len(), batch.len());
        // 容量留位 (见 [`APPEND_SLACK_DIV`]): 走 `reserve_exact` 而非 `resize`
        // 的翻倍增长 —— 一次追加拷整个索引是 UI 线程上 80 ms 级的可见代价。
        if self.rows.capacity() < len + k {
            self.rows.reserve_exact(k + len / APPEND_SLACK_DIV);
        }
        // 反向单遍合并: 结果区间 [start, len + k)。不变式 w == ti + bi ⇒ 写指针
        // 恒 ≥ 读指针, 原地覆盖不丢数据; bi 归零时剩余头部已在正确位置。
        self.rows.resize(len + k, batch[0]);
        let (mut w, mut ti, mut bi) = (len + k, len, k);
        while bi > 0 {
            let take_batch = ti == start || key_of(&self.rows[ti - 1]) <= key_of(&batch[bi - 1]);
            if take_batch {
                self.rows[w - 1] = batch[bi - 1];
                bi -= 1;
            } else {
                self.rows[w - 1] = self.rows[ti - 1];
                ti -= 1;
            }
            w -= 1;
        }
    }

    /// 插入位: 末行起回找, 首个排序键 ≤ 给定行的位置**之后**。
    /// 不设帽 (T9): 插入的深回找只付一次, 换来精确位。
    fn slot_of(&self, r: MergeRow) -> usize {
        let k = key_of(&r);
        let mut i = self.rows.len();
        while i > 0 && key_of(&self.rows[i - 1]) > k {
            i -= 1;
        }
        i
    }

    /// 单源单行摘除 (live-tail 末行补全重提的另一半, T7): 追加把**无换行结尾**的
    /// 旧末行补全后, 该行的 ts 可能改判 (残行解析失败曾继承上一行) —— 旧条目
    /// 必须先摘再插, 否则同一 (src,line) 在索引里两条 (旧 ts 幽灵)。
    ///
    /// 尾端回找 (目标天然近尾 —— 它是该源最后一行); **超 [`WALK_CAP`] 没找到 =
    /// false**, 调用方兜底全量重建 (诚实, 不静默留幽灵)。`Vec::remove` 的
    /// 尾部位移是常数级。
    pub fn remove_row(&mut self, src: u32, line: u32) -> bool {
        let mut i = self.rows.len();
        let mut walked = 0usize;
        while i > 0 && walked < WALK_CAP {
            let r = self.rows[i - 1];
            if r.src == src && r.line == line {
                self.rows.remove(i - 1);
                return true;
            }
            i -= 1;
            walked += 1;
        }
        false
    }
}

/// k-way min-head 归并: 输入各源时间线, 出物化合并索引。
///
/// 每步扫 k 个游标头取 (ts, src) 最小 —— k ≤ 8 (SPEC D7) 时线性扫比堆
/// 缓存友好, 复杂度 O(总行数 × k), 千万行级是几十毫秒的事 (T0c 实测:
/// 17M 行 215ms / 9.3M 行 k=8 时 229ms)。
pub fn build_index(timelines: &[SourceTimeline<'_>]) -> MergeIndex {
    let items: Vec<(&[i64], u32)> = timelines
        .iter()
        .enumerate()
        .map(|(i, t)| (t.ts.as_slice(), i as u32))
        .collect();
    merge_from(&items)
}

/// 源掩码重归并 (显隐/移除源): 被藏源不参与, **源序号保持原值** ——
/// 行上的 src 引用不随显隐漂移 (恢复隐藏时旧行的源指认不变)。
pub fn build_index_masked(timelines: &[SourceTimeline<'_>], visible: &[bool]) -> MergeIndex {
    let items: Vec<(&[i64], u32)> = timelines
        .iter()
        .enumerate()
        .filter(|(i, _)| visible.get(*i).copied().unwrap_or(true))
        .map(|(i, t)| (t.ts.as_slice(), i as u32))
        .collect();
    merge_from(&items)
}

/// min-head 归并核: (源时间戳切片, **原源序号**) 序列 —— build 两个入口共用。
fn merge_from(items: &[(&[i64], u32)]) -> MergeIndex {
    let total: usize = items.iter().map(|(ts, _)| ts.len()).sum();
    // 容量 = 精确行数 + 追加留位 [`APPEND_SLACK_DIV`] (T9): live-tail 增量插入
    // 若撞容量上限, `Vec::resize` 会按**翻倍**重分配 —— 17M 行索引一次追加即
    // 从 259 MiB 翻到 519 MiB (破 D10「每行 16B」的模型 + 一次 80 ms 拷贝)。
    // 预留守位让小追加零重分配, 驻留超募 ≤ 1/16 (D10 口径 = 行数×16B 仍精确,
    // 超募单列)。
    let mut rows: Vec<MergeRow> = Vec::with_capacity(total + total / APPEND_SLACK_DIV);
    let mut cur: Vec<usize> = vec![0; items.len()];
    loop {
        let mut best: Option<(i64, usize)> = None;
        for (s, (ts, _)) in items.iter().enumerate() {
            let c = cur[s];
            if c < ts.len() {
                let t = ts[c];
                // tie-break 比**原源序号** (第二元), 不是 items 下标。
                if best.is_none_or(|(bt, bs)| t < bt || (t == bt && items[s].1 < items[bs].1)) {
                    best = Some((t, s));
                }
            }
        }
        let Some((t, s)) = best else { break };
        rows.push(MergeRow {
            ts: t,
            src: items[s].1,
            line: cur[s] as u32,
        });
        cur[s] += 1;
    }
    MergeIndex { rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// 临时 fixture 文件 (每用例独立名, 收尾删)。
    fn temp_log(name: &str, content: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("danqing-merge-test-{name}.log"));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    fn open(p: &std::path::Path) -> LogFile {
        LogFile::open(p).unwrap()
    }

    fn timeline_of(file: &LogFile, ts: Vec<i64>) -> SourceTimeline<'_> {
        // 测试快捷构造: 直接给 ts 向量 (extract 通路另有 extract_timeline 专测)。
        assert_eq!(ts.len() as u64, file.line_count());
        SourceTimeline { file, ts }
    }

    #[test]
    fn merge_two_monotonic_interleaved() {
        let pa = temp_log("mono-a", b"l\nl\nl\n");
        let pb = temp_log("mono-b", b"l\nl\n");
        let fa = open(&pa);
        let fb = open(&pb);
        let idx = build_index(&[
            timeline_of(&fa, vec![100, 300, 500]),
            timeline_of(&fb, vec![200, 400]),
        ]);
        let got: Vec<(i64, u32, u32)> = idx.rows().iter().map(|r| (r.ts, r.src, r.line)).collect();
        assert_eq!(
            got,
            vec![
                (100, 0, 0),
                (200, 1, 0),
                (300, 0, 1),
                (400, 1, 1),
                (500, 0, 2),
            ]
        );
        std::fs::remove_file(&pa).ok();
        std::fs::remove_file(&pb).ok();
    }

    #[test]
    fn merge_equal_ts_tiebreak_src_then_file_order() {
        let pa = temp_log("tie-a", b"l\nl\n");
        let pb = temp_log("tie-b", b"l\n");
        let fa = open(&pa);
        let fb = open(&pb);
        // 等 ts: 源 0 两行都在源 1 之前, 且源内保行序。
        let idx = build_index(&[
            timeline_of(&fa, vec![100, 100]),
            timeline_of(&fb, vec![100]),
        ]);
        let got: Vec<(u32, u32)> = idx.rows().iter().map(|r| (r.src, r.line)).collect();
        assert_eq!(got, vec![(0, 0), (0, 1), (1, 0)]);
        std::fs::remove_file(&pa).ok();
        std::fs::remove_file(&pb).ok();
    }

    #[test]
    fn merge_out_of_order_keeps_file_order() {
        // 源内乱序: 后行 ts 更小, 仍不许超越前行 (D1 钉住语义)。
        let pa = temp_log("ooo-a", b"l\nl\n");
        let pb = temp_log("ooo-b", b"l\n");
        let fa = open(&pa);
        let fb = open(&pb);
        let idx = build_index(&[
            timeline_of(&fa, vec![500, 100]),
            timeline_of(&fb, vec![300]),
        ]);
        let got: Vec<(i64, u32, u32)> = idx.rows().iter().map(|r| (r.ts, r.src, r.line)).collect();
        // min-head 全局序: src1 的 300 先出列 (它比 src0 游标头 500 小);
        // 源 0 出列序恒为 (行0=500, 行1=100) —— 乱序行 100 不回头重排,
        // 只在成为游标头时按当时最小值找位 (D1 钉住)。
        assert_eq!(got, vec![(300, 1, 0), (500, 0, 0), (100, 0, 1)]);
        std::fs::remove_file(&pa).ok();
        std::fs::remove_file(&pb).ok();
    }

    #[test]
    fn extract_inherits_and_backfills_leading() {
        // 行 0 无 ts (继承行 1), 行 3 无 ts (继承行 2)。
        let p = temp_log(
            "inh",
            b"    at stack.Trace(one:1)\n2026-09-27T00:00:00Z a\n2026-09-27T00:00:01Z b\n    at stack.Trace(two:2)\n",
        );
        let f = open(&p);
        let ts = extract_timeline(&f, |line| {
            crate::timestamp::parse_prefix(line, crate::timestamp::TsFormat::Iso8601, 0)
                .map(|(t, _)| t)
        });
        assert_eq!(ts.len(), 4);
        assert_eq!(ts[0], ts[1], "首行继承第二行 (回填)");
        assert_eq!(ts[3], ts[2], "continuation 继承上一行");
        assert!(ts[1] < ts[2]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn index_bytes_is_16_per_row() {
        let pa = temp_log("bytes-a", b"l\nl\n");
        let fa = open(&pa);
        let idx = build_index(&[timeline_of(&fa, vec![1, 2])]);
        assert_eq!(idx.index_bytes(), 2 * 16);
        assert_eq!(idx.len(), 2);
        assert!(!idx.is_empty());
        std::fs::remove_file(&pa).ok();
    }

    // ─── T2: 增量合流与掩码 ───

    #[test]
    fn extract_append_continues_and_inherits() {
        let p = temp_log("app", b"2026-09-27T00:00:00Z a\n2026-09-27T00:00:01Z b\n");
        let f = open(&p);
        let mut ts = extract_timeline(&f, |line| {
            crate::timestamp::parse_prefix(line, crate::timestamp::TsFormat::Iso8601, 0)
                .map(|(t, _)| t)
        });
        assert_eq!(ts.len(), 2);
        // 模拟 live-tail 增长: 追写一条带 ts + 一条 continuation。
        {
            let mut w = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
            w.write_all(b"2026-09-27T00:00:02Z c\n    at stack.X(F.java:1)\n")
                .unwrap();
        }
        let f2 = LogFile::append_from(&f, &p).unwrap();
        extract_append(&f2, &mut ts, 2, |line| {
            crate::timestamp::parse_prefix(line, crate::timestamp::TsFormat::Iso8601, 0)
                .map(|(t, _)| t)
        });
        assert_eq!(ts.len(), 4);
        assert!(ts[2] > ts[1]);
        assert_eq!(ts[3], ts[2], "增量 continuation 继承上一行");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn insert_rows_tail_fastpath_appends_in_order() {
        let pa = temp_log("ins-a", b"l\nl\n");
        let fa = open(&pa);
        let mut idx = build_index(&[timeline_of(&fa, vec![100, 200])]);
        idx.insert_rows(0, &[(300, 2), (400, 3)]);
        let got: Vec<(i64, u32)> = idx.rows().iter().map(|r| (r.ts, r.line)).collect();
        assert_eq!(got, vec![(100, 0), (200, 1), (300, 2), (400, 3)]);
        std::fs::remove_file(&pa).ok();
    }

    #[test]
    fn insert_rows_walkback_for_late_clock() {
        // 慢时钟源: 新行 ts 落后尾部 → 回找插入 ((ts,src,line) 字典序位)。
        let pa = temp_log("walk-a", b"l\nl\n");
        let pb = temp_log("walk-b", b"l\n");
        let fa = open(&pa);
        let fb = open(&pb);
        let mut idx = build_index(&[
            timeline_of(&fa, vec![100, 300]),
            timeline_of(&fb, vec![200]),
        ]);
        idx.insert_rows(0, &[(250, 2)]); // src0 行2, ts=250 < 尾行 300
        let got: Vec<(i64, u32, u32)> = idx.rows().iter().map(|r| (r.ts, r.src, r.line)).collect();
        assert_eq!(
            got,
            vec![(100, 0, 0), (200, 1, 0), (250, 0, 2), (300, 0, 1)]
        );
        std::fs::remove_file(&pa).ok();
        std::fs::remove_file(&pb).ok();
    }

    #[test]
    fn insert_rows_equal_ts_tiebreak_consistent_with_merge() {
        // 等 ts 插入: 同源既有行之后 (行号大), 源序号更大者之前 —— 与归并同规则。
        let pa = temp_log("eqi-a", b"l\n");
        let pb = temp_log("eqi-b", b"l\n");
        let pc = temp_log("eqi-c", b"l\n");
        let fa = open(&pa);
        let fb = open(&pb);
        let fc = open(&pc);
        let mut idx = build_index(&[
            timeline_of(&fa, vec![100]),
            timeline_of(&fb, vec![100]),
            timeline_of(&fc, vec![100]),
        ]);
        idx.insert_rows(1, &[(100, 1)]);
        let got: Vec<(u32, u32)> = idx.rows().iter().map(|r| (r.src, r.line)).collect();
        assert_eq!(got, vec![(0, 0), (1, 0), (1, 1), (2, 0)]);
        std::fs::remove_file(&pa).ok();
        std::fs::remove_file(&pb).ok();
        std::fs::remove_file(&pc).ok();
    }

    /// 末行补全重提的索引半 (T7): 摘掉 (src,line) 旧条目再插新 ts ——
    /// 不摘会留双条 (旧 ts 幽灵)。摘不存在的行 = false (调用方兜底重建)。
    #[test]
    fn remove_row_then_reinsert_corrects_tail_ts() {
        let pa = temp_log("rm-a", b"l\nl\n");
        let pb = temp_log("rm-b", b"l\n");
        let fa = open(&pa);
        let fb = open(&pb);
        // 源0 行1 曾以**继承 ts** (200, 残行改判前) 进索引
        let mut idx = build_index(&[
            timeline_of(&fa, vec![100, 200]),
            timeline_of(&fb, vec![150]),
        ]);
        assert!(idx.remove_row(0, 1), "末行补全: 旧条目摘得到");
        idx.insert_rows(0, &[(400, 1)]); // 补全后真 ts
        let got: Vec<(i64, u32, u32)> = idx.rows().iter().map(|r| (r.ts, r.src, r.line)).collect();
        assert_eq!(
            got,
            vec![(100, 0, 0), (150, 1, 0), (400, 0, 1)],
            "摘旧插新, 无幽灵条目"
        );
        // 摘得到 (条目以新 ts 在索引里): 再摘成功, 剩两行; 越界行 false
        assert!(idx.remove_row(0, 1), "新条目同样可摘");
        assert_eq!(idx.rows().len(), 2);
        assert!(!idx.remove_row(1, 99), "越界行 false");
        std::fs::remove_file(&pa).ok();
        std::fs::remove_file(&pb).ok();
    }

    #[test]
    fn build_index_masked_keeps_original_src_ids() {
        let pa = temp_log("mask-a", b"l\n");
        let pb = temp_log("mask-b", b"l\n");
        let pc = temp_log("mask-c", b"l\n");
        let fa = open(&pa);
        let fb = open(&pb);
        let fc = open(&pc);
        let tls = vec![
            timeline_of(&fa, vec![100]),
            timeline_of(&fb, vec![200]),
            timeline_of(&fc, vec![300]),
        ];
        let idx = build_index_masked(&tls, &[true, false, true]);
        let got: Vec<(i64, u32)> = idx.rows().iter().map(|r| (r.ts, r.src)).collect();
        // 源 1 被藏: 不参与; 源 2 的 src 仍是 2 (不漂移成 1)。
        assert_eq!(got, vec![(100, 0), (300, 2)]);
        std::fs::remove_file(&pa).ok();
        std::fs::remove_file(&pb).ok();
        std::fs::remove_file(&pc).ok();
    }

    /// T9 整批插入与**逐行插入**逐位等价 (差分对拍): 参考实现 = 旧逐行语义
    /// (每行对当时的数组算「首个键 ≤ 它的位置之后」)。覆盖尾追、深回找、
    /// 批内乱序 (ts 逆序)、等 ts 相邻、索引内乱序多源 —— 整批是优化不改语义。
    #[test]
    fn insert_rows_batch_matches_per_row_reference() {
        /// 旧逐行语义的参考实现 (与 T9 前的 `find_slot` 同判据)。
        fn reference(rows: &mut Vec<(i64, u32, u32)>, src: u32, batch: &[(i64, u32)]) {
            for &(ts, line) in batch {
                let k = (ts, src, line);
                let mut i = rows.len();
                while i > 0 && rows[i - 1] > k {
                    i -= 1;
                }
                rows.insert(i, k);
            }
        }
        // (各源 ts 向量, 批目标源, 批行)
        type Case = (Vec<Vec<i64>>, u32, Vec<(i64, u32)>);
        let cases: Vec<Case> = vec![
            // 尾追 (快路)
            (vec![vec![100, 200, 300]], 0, vec![(400, 2), (500, 3)]),
            // 深回找 (慢时钟源)
            (vec![vec![100, 200, 300]], 0, vec![(50, 2), (60, 3)]),
            // 批内 ts 逆序 (乱序行; 批按文件序给)
            (
                vec![vec![100, 300, 500]],
                0,
                vec![(400, 1), (200, 2), (600, 3)],
            ),
            // 等 ts 相邻 (批内三种关系: 小于/等于/大于既有同行 ts)
            (vec![vec![100, 100, 100]], 0, vec![(100, 1), (100, 2)]),
            // 多源 + 索引内乱序 (D1: 同源后行 ts 可回跳)
            (
                vec![vec![100, 400, 300], vec![250, 350]],
                0,
                vec![(320, 2), (450, 3)],
            ),
            // 批插中段 (首行不在尾也不在头)
            (
                vec![vec![100, 500, 900], vec![200, 600]],
                1,
                vec![(300, 2), (700, 3)],
            ),
        ];
        for (bases, src, batch) in cases {
            let mut files: Vec<(PathBuf, LogFile)> = Vec::new();
            for (i, ts) in bases.iter().enumerate() {
                let p = temp_log(&format!("diff-{i}"), &b"l\n".repeat(ts.len()));
                let f = open(&p);
                files.push((p, f));
            }
            let tls: Vec<SourceTimeline<'_>> = files
                .iter()
                .zip(bases.iter())
                .map(|((_, f), ts)| timeline_of(f, ts.clone()))
                .collect();
            let mut idx = build_index(&tls);
            let mut want: Vec<(i64, u32, u32)> =
                idx.rows().iter().map(|r| (r.ts, r.src, r.line)).collect();
            reference(&mut want, src, &batch);
            idx.insert_rows(src, &batch);
            let got: Vec<(i64, u32, u32)> =
                idx.rows().iter().map(|r| (r.ts, r.src, r.line)).collect();
            assert_eq!(got, want, "整批 == 逐行 (src={src}, batch={batch:?})");
            for (p, _) in files {
                std::fs::remove_file(&p).ok();
            }
        }
    }

    /// T9 容量留位: 建索引多留 `APPEND_SLACK_DIV` 之一, 小追加**不重分配**
    /// (指针/容量不变) —— 否则 Vec 翻倍增长会让一次追加拷整个索引。
    #[test]
    fn insert_rows_uses_reserved_slack_without_realloc() {
        let pa = temp_log("slack-a", &b"l\n".repeat(1000));
        let fa = open(&pa);
        let ts: Vec<i64> = (0..1000).map(|i| 100 + i as i64).collect();
        let mut idx = build_index(&[timeline_of(&fa, ts)]);
        let cap0 = idx.rows.capacity();
        assert!(
            cap0 > idx.rows.len(),
            "建索引须留追加位: cap {cap0} vs len {}",
            idx.rows.len()
        );
        idx.insert_rows(0, &[(5000, 1000), (6000, 1001)]);
        assert_eq!(idx.rows.capacity(), cap0, "留位内追加不重分配");
        assert_eq!(idx.len(), 1002);
        std::fs::remove_file(&pa).ok();
    }

    /// T9 深回找**精确位** (旧帽语义退役): 新行真值位在 120 万行之外 ——
    /// 旧实现超帽即插在 len-1M 的近似位, 现按真值位落最前。
    #[test]
    fn insert_rows_deep_walkback_is_exact_not_capped() {
        // ts 向量直喂, 但 fixture 行数须与 ts 等长 (timeline_of 断言)
        let n = 1_200_000usize;
        let pa = temp_log("deep-a", &b"l\n".repeat(n));
        let fa = open(&pa);
        let ts: Vec<i64> = (0..n).map(|i| 100 + i as i64).collect();
        let mut idx = build_index(&[timeline_of(&fa, ts)]);
        assert_eq!(idx.len(), n);
        // 源0 追加行 n, ts 比现存全部行都小 → 真值位 0
        idx.insert_rows(0, &[(50, n as u32)]);
        let first = idx.rows()[0];
        assert_eq!(
            (first.ts, first.src, first.line),
            (50, 0, n as u32),
            "深回找落真值位 (超帽近似位已退役)"
        );
        assert_eq!(idx.len(), n + 1);
        std::fs::remove_file(&pa).ok();
    }
}
