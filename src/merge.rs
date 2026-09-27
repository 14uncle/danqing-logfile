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

    /// 驻留字节 (D10 实测口径 = 行数 ×16B; Vec 精确容量, 无超募)。
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

/// 增量插入回找上限 (文档化兜底): 新行天然近尾 (live-tail 追加), 回找是常数级;
/// 慢时钟源深回找超此帽即插在当前位置 —— 近似位, 注释即声明, 不静默错。
const WALK_CAP: usize = 1_000_000;

impl MergeIndex {
    /// 单源增量合流 (live-tail 腿 F 引擎半): 新行 (ts, 文件行号) 按**源行序**给,
    /// 逐行找位插入。排序键 = (ts, src, line) 字典序 —— 与归并 tie-break 同规则
    /// (等 ts: 源序号小者先, 同源行号小者先)。尾追加快路: 新行 ≥ 当前尾行 →
    /// 回找零步直接 push (live-tail 常态)。
    ///
    /// 注意: 索引在乱序下不保证全局 ts 有序 (D1 钉住), 故不能用二分 ——
    /// 从尾部线性回找是唯一诚实形态 (新行近尾, 代价常数级)。
    pub fn insert_rows(&mut self, src: u32, new_rows: &[(i64, u32)]) {
        for &(ts, line) in new_rows {
            let pos = self.find_slot(src, ts, line);
            self.rows.insert(pos, MergeRow { ts, src, line });
        }
    }

    /// 插入位: 末行起回找, 首个排序键 ≤ 新行的位置之后。
    fn find_slot(&self, src: u32, ts: i64, line: u32) -> usize {
        let mut i = self.rows.len();
        let mut walked = 0usize;
        while i > 0 && walked < WALK_CAP {
            let r = self.rows[i - 1];
            let after =
                r.ts > ts || (r.ts == ts && (r.src > src || (r.src == src && r.line > line)));
            if !after {
                break;
            }
            i -= 1;
            walked += 1;
        }
        i
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
    let mut rows: Vec<MergeRow> = Vec::with_capacity(total);
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
}
