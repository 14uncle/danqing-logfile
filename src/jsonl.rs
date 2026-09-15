//! @author 十四叔
//! @date 2026/09/05
//!
//! JSONL 列化引擎: 检测 / 列发现 / 字段提取 / 字段过滤。
//!
//! 开枪前提②的主炮: 列化视图 + `level=ERROR status=50*` 字段过滤,
//! 对标 VS Code 扩展 daucloud.json-viewer (独立窗口、秒开、不占编辑器)。
//!
//! 显示路径 (T1): 逐可见行 serde_json parse (真 parser, 恒定成本), 嵌套值紧凑显示;
//! 过滤路径: 扁平等值/前缀走 memmem 粗筛零 parse (性能), 点路径/比较算子才
//! parse 验证 (T2 两段架构)。memmem 提取 (`extract_field`) 仅供过滤粗筛, 不再进显示。
//! 匹配一律 **ASCII 大小写不敏感** (2026-09-15): 裸词走 [`contains_ascii_ci`],
//! 值比较走 `eq_ignore_ascii_case` (等值) / [`starts_with_ascii_ci`] (前缀);
//! 键的 needle 保持精确, 由产品侧按列名规范化。

use crate::logfile::LogFile;

/// 并行过滤阈值: 剩余行数 ≥此值时启用多线程分段过滤 (经验值: 小文件单线程更简洁)。
const PARALLEL_FILTER_THRESHOLD: u64 = 100_000;
/// 并行过滤最大线程数 (避免线程过多导致调度开销大于收益)。
const MAX_FILTER_THREADS: usize = 8;

/// 列描述: 字段名 + 展示宽度 (字符数, 采样最大值, [4, 32] 截断)。
#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub width_chars: usize,
}

/// 列化模式: 按首见顺序排列的列集合。
#[derive(Debug, Clone)]
pub struct Schema {
    pub columns: Vec<Column>,
}

/// 检测行数采样上限。
const DETECT_SAMPLE: u64 = 64;
/// 列发现采样上限。
const SCHEMA_SAMPLE: u64 = 512;
/// 列数上限。
const MAX_COLUMNS: usize = 16;
/// 采样的**字节**预算 (2026-09-12 加)。
///
/// 只按行数采样时, 行一宽成本就无界: 实测 200 MiB / 563 KiB 行 / 每行含上万
/// 小对象 的文件, 列发现要 **3.2 s** (serde_json 解析这种形状只有 ~60 MB/s),
/// 按 512 行采样等于要解析几百 MiB —— 用户看到的就是「索引 17ms 却等了十几秒」。
/// 加字节预算后同一文件降到几十毫秒。
///
/// 行宽 ≤ 8 KiB 时预算不生效 (512 行 × 8 KiB = 4 MiB), 故对普通日志**零影响**。
const SCHEMA_SAMPLE_BYTES: usize = 4 << 20;
/// 检测采样的字节预算 (同上, 64 行 × 32 KiB = 2 MiB 才可能触顶)。
const DETECT_SAMPLE_BYTES: usize = 2 << 20;
/// 预算之下的**最少**采样行数 —— 证据不足不判 (detect 另有 nonempty ≥ 3 的判据)。
const MIN_SAMPLE_LINES: u64 = 6;
/// 列宽 (字符数) 的钳制上下界 —— **列发现只需量到这个上界**。
///
/// 这个常量是 `discover_schema` 里宽度探测的**唯一依据**: 既然结果钳到
/// [`WIDTH_CLAMP`], 量值宽度就只需要前 [`WIDTH_CLAMP`] 个字符, 多的部分
/// 算了也会被丢掉 (2026-09-12 修: 之前对每个字符串值 `chars().count()`
/// 走完全文、对每个对象/数组先 `to_string()` 整棵序列化再逐字符数 ——
/// 行内值一大, 列发现就成了整个打开路径里最慢的一步)。
const WIDTH_CLAMP: usize = 32;
/// 非字符串值宽度探测的字节上界 (有界序列化)。
///
/// 超界即按「≥ [`WIDTH_CLAMP`]」处理 —— 256 字节的 UTF-8 至少 85 个字符,
/// 远大于 32, **钳制后与「整棵序列化再逐字符数」结果相同**, 但不再为一个大
/// 对象分配一整棵序列化字符串。
const WIDTH_PROBE_BYTES: usize = 256;
/// 判定为 JSONL 的 object 行占比下限。
const DETECT_THRESHOLD: f64 = 0.9;

/// JSONL 检测: 采样前 DETECT_SAMPLE 行, 非空行中 ≥90% 能 parse 成 JSON object。
/// 采样不足 3 行不判 (证据不足), 空文件/全坏行 → false。
pub fn detect(file: &LogFile) -> bool {
    let n = file.line_count().min(DETECT_SAMPLE);
    let mut nonempty = 0u64;
    let mut objects = 0u64;
    let mut sampled_bytes = 0usize;
    for i in 0..n {
        if i >= MIN_SAMPLE_LINES && sampled_bytes >= DETECT_SAMPLE_BYTES {
            break; // 字节预算到顶: 大行文件不能让检测去解析几百 MiB
        }
        let line = file.line(i);
        sampled_bytes += line.len();
        if line.is_empty() {
            continue;
        }
        nonempty += 1;
        if serde_json::from_slice::<serde_json::Value>(line).is_ok_and(|v| v.is_object()) {
            objects += 1;
        }
    }
    nonempty >= 3 && objects as f64 >= nonempty as f64 * DETECT_THRESHOLD
}

/// 列发现: 采样前 SCHEMA_SAMPLE 行, 按首见顺序收顶层 key (≤MAX_COLUMNS 列)。
/// 宽度 = max(字段名长度, 采样值展示长度), 截到 [4, 32]。
/// 非 JSONL / 采样零列 → None。
/// 单元格值宽度 (字符数), **有界**到 [`WIDTH_CLAMP`] 以上即可。
///
/// 字符串取前 `WIDTH_CLAMP + 1` 个字符; 其余类型用有界序列化 ([`compact_prefix`]),
/// 超界直接返回 `WIDTH_CLAMP + 1`。三种情形经 `clamp(4, WIDTH_CLAMP)` 之后,
/// 与「完整序列化再逐字符数」**完全等价** —— 这是可以这样省的前提。
fn value_width(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::String(s) => s.chars().take(WIDTH_CLAMP + 1).count(),
        other => match compact_prefix(other, WIDTH_PROBE_BYTES) {
            Some(bytes) => String::from_utf8_lossy(&bytes).chars().count(),
            None => WIDTH_CLAMP + 1,
        },
    }
}

/// 有界紧凑序列化: 收集至多 `cap` 字节; 超出返回 `None` (调用方按「很宽」处理)。
///
/// 为什么不用 `to_string()`: 对象/数组的紧凑形式可能比整个文件还大, 而我们只
/// 需要前几十个字符。写进一个到顶即报错的 `Write` 就既拿到了前缀、又不会把
/// 整棵序列化结果留在内存里。
fn compact_prefix(value: &serde_json::Value, cap: usize) -> Option<Vec<u8>> {
    struct CapWriter {
        buf: Vec<u8>,
        cap: usize,
    }
    impl std::io::Write for CapWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.buf.len() + data.len() > self.cap {
                return Err(std::io::Error::other("宽度探测超界"));
            }
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = CapWriter {
        buf: Vec::new(),
        cap,
    };
    serde_json::to_writer(&mut w, value).ok()?;
    Some(w.buf)
}

pub fn discover_schema(file: &LogFile) -> Option<Schema> {
    let n = file.line_count().min(SCHEMA_SAMPLE);
    let mut columns: Vec<Column> = Vec::new();
    let mut sampled_bytes = 0usize;
    for i in 0..n {
        if i >= MIN_SAMPLE_LINES && sampled_bytes >= SCHEMA_SAMPLE_BYTES {
            break; // 字节预算到顶 (见 SCHEMA_SAMPLE_BYTES)
        }
        let raw = file.line(i);
        sampled_bytes += raw.len();
        let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(raw)
        else {
            continue;
        };
        for (key, value) in &map {
            let shown_len = value_width(value);
            match columns.iter_mut().find(|c| c.name == *key) {
                Some(col) => col.width_chars = col.width_chars.max(shown_len),
                None => {
                    if columns.len() < MAX_COLUMNS {
                        columns.push(Column {
                            name: key.clone(),
                            width_chars: key.chars().take(WIDTH_CLAMP + 1).count().max(shown_len),
                        });
                    }
                }
            }
        }
    }
    if columns.is_empty() {
        return None;
    }
    for c in &mut columns {
        c.width_chars = c.width_chars.clamp(4, WIDTH_CLAMP);
    }
    Some(Schema { columns })
}

/// 构造字段定位针: `"key":`。
fn field_needle(key: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(key.len() + 3);
    v.push(b'"');
    v.extend_from_slice(key.as_bytes());
    v.extend_from_slice(b"\":");
    v
}

/// 扁平字段提取: 返回值 token 切片 (字符串去引号, 数字/bool/null 原样)。
/// 前缀校验: key 之前 (跳过空白) 必须是 `{` 或 `,`, 挡住行内裸文本误配的一半。
/// 仅供**过滤粗筛** (T2 两段架构); 显示路径已换真 parser (见 [`parse_line`])。
/// 预构造的字段提取器: needle 与 memmem 的 prefilter **都只建一次**。
///
/// **为什么必须有它** (2026-09-13): [`extract_field`] 每次调用都重建 needle
/// (分配一个 `Vec`, 见 [`field_needle`]) **并且**重建 `memchr::memmem::Finder`
/// (对 needle 做一次 prefilter 分析)。逐行调用时这两笔固定开销会成为整个扫描的
/// 成本主体 —— 用户实机实测 (debug 构建, 20 线程可用, 同一台机器):
///
/// | 口径 | 文件 | 行数 | 耗时 |
/// |---|---|---|---|
/// | 字段口径 (逐行 `extract_field`) | 1 GB JSONL | 483 万 | **9312 ms** |
/// | 行口径 (`memchr3` 直扫) | 1 GB 明文 | 635 万 | **417 ms** |
///
/// **22 倍** —— 而字段口径扫的字节数其实**更少** (找到 `"level":` 即返回)。
/// 故慢的从来不是扫描, 是每行的两次构造。
pub struct FieldExtractor {
    needle: Vec<u8>,
    finder: memchr::memmem::Finder<'static>,
}

impl FieldExtractor {
    /// 为字段名构造 (needle 与 prefilter 各建一次, 之后逐行复用)。
    pub fn new(key: &str) -> Self {
        let needle = field_needle(key);
        let finder = memchr::memmem::Finder::new(&needle).into_owned();
        Self { needle, finder }
    }

    /// 提取该字段的值 token —— 语义与 [`extract_field`] **完全一致**
    /// (由 `field_extractor_matches_extract_field` 差分钉着)。
    pub fn extract<'a>(&self, line: &'a [u8]) -> Option<&'a [u8]> {
        next_field_value_with(line, &self.needle, &self.finder, 0).map(|(v, _)| v)
    }
}

pub fn extract_field<'a>(line: &'a [u8], key: &str) -> Option<&'a [u8]> {
    extract_with_needle(line, &field_needle(key))
}

/// 解析一行 JSON (显示路径, 只 parse 可见行, 恒定成本)。
/// 淘汰 memmem 提取出显示路径 —— 消除 POC「`,"key":"` 内嵌误判」已知边界。
pub fn parse_line(raw: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(raw).ok()
}

/// 单元格紧凑显示: 字符串裸值, 其余 (对象/数组/数字/bool/null) `to_string` 紧凑。
pub fn cell_display(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// 展开子行: 嵌套结构的一条 (深度, 路径段, 紧凑值)。
#[derive(Debug, Clone, PartialEq)]
pub struct SubRow {
    /// 缩进深度 (1 = 顶层字段, 递增)。
    pub depth: usize,
    /// 路径段: 对象 key 或数组索引 `[i]`。
    pub label: String,
    /// 值紧凑显示 (容器 = `{...}`/`[...]`, 叶子 = [`cell_display`])。
    pub value: String,
}

/// 展开一行 JSON: 顶层对象/数组字段 → 递归子行序列 (顶层叶子 = 列, 不进子行)。
/// 数组段显示为 `[i]` (spec Open Question 已答)。根为数组非 JSONL (spec Out)。
pub fn flatten(value: &serde_json::Value) -> Vec<SubRow> {
    let mut out = Vec::new();
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            if v.is_object() || v.is_array() {
                flatten_into(k, v, 1, &mut out);
            }
            // 顶层叶子 = 列, 不重复为子行
        }
    }
    out
}

/// 该 JSON 值是否可展开 (顶层有对象/数组字段)。等价 `!flatten(v).is_empty()`, 但更省。
pub fn is_expandable(value: &serde_json::Value) -> bool {
    matches!(value, serde_json::Value::Object(map) if map.values().any(|v| v.is_object() || v.is_array()))
}

/// 递归拍平一个 (路径段, 值) 对: 先推容器/叶子子行, 容器再递归子节点。
fn flatten_into(label: &str, val: &serde_json::Value, depth: usize, out: &mut Vec<SubRow>) {
    out.push(SubRow {
        depth,
        label: label.to_string(),
        value: cell_display(val),
    });
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                flatten_into(k, v, depth + 1, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                flatten_into(&format!("[{i}]"), v, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// 找下一个带合法前缀的字段值 token: 返回 (值 token, 下一搜索起点)。
/// 前缀校验: key 之前 (跳过空白) 必须是 `{` 或 `,`。字符串去引号, 数字/bool/null 原样。
fn next_field_value<'a>(line: &'a [u8], needle: &[u8], from: usize) -> Option<(&'a [u8], usize)> {
    // 一次性入口: 每次调用都重建 Finder。**逐行调用请走 [`FieldExtractor`]** ——
    // 那笔固定开销在循环里会成为成本主体 (见该类型的文档)。
    next_field_value_with(line, needle, &memchr::memmem::Finder::new(needle), from)
}

/// [`next_field_value`] 的核心: 搜索器由调用方预构造。
fn next_field_value_with<'a>(
    line: &'a [u8],
    needle: &[u8],
    finder: &memchr::memmem::Finder<'_>,
    mut from: usize,
) -> Option<(&'a [u8], usize)> {
    loop {
        let pos = finder.find(&line[from..])? + from;
        let mut i = pos;
        let prefix_ok = loop {
            if i == 0 {
                break false;
            }
            i -= 1;
            match line[i] {
                b' ' | b'\t' => continue,
                b'{' | b',' => break true,
                _ => break false,
            }
        };
        let next = pos + needle.len();
        if !prefix_ok {
            from = next;
            continue;
        }
        let mut s = next;
        while s < line.len() && matches!(line[s], b' ' | b'\t') {
            s += 1;
        }
        if s >= line.len() {
            return None;
        }
        let token = if line[s] == b'"' {
            // 字符串: 到未转义的收尾引号
            let mut e = s + 1;
            let mut closed = false;
            while e < line.len() {
                match line[e] {
                    b'\\' => e += 1,
                    b'"' => {
                        closed = true;
                        break;
                    }
                    _ => {}
                }
                e += 1;
            }
            if !closed {
                return None;
            }
            &line[s + 1..e]
        } else {
            let mut e = s;
            while e < line.len() && !matches!(line[e], b',' | b'}' | b' ' | b'\t') {
                e += 1;
            }
            &line[s..e]
        };
        return Some((token, next));
    }
}

/// 值 token 切取 (needle 预编译版, 供扁平过滤直通): 返回首个带合法前缀的字段值。
fn extract_with_needle<'a>(line: &'a [u8], needle: &[u8]) -> Option<&'a [u8]> {
    next_field_value(line, needle, 0).map(|(v, _)| v)
}

/// 行内是否存在某字段值命中 (点路径粗筛): 遍历所有 `"leaf":` 出现, 任一值匹配即 true。
/// 无假阴性 (值命中行必过), 把候选压到「值命中量级」再 parse 验证 —— 避免全量 parse。
fn field_value_matches(line: &[u8], needle: &[u8], op: Op, value: &str) -> bool {
    let mut from = 0usize;
    while let Some((token, next)) = next_field_value(line, needle, from) {
        if token_matches(token, op, value) {
            return true;
        }
        from = next;
    }
    false
}

/// 比较算子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `=` 等值 (**ASCII 大小写不敏感**, 非字节全等 —— 见 `token_matches`)。
    Eq,
    /// `=...*` 前缀通配 (**同样不敏感**)。
    Prefix,
    /// `>` 数值大于。
    Gt,
    /// `>=` 数值大于等于。
    GtEq,
    /// `<` 数值小于。
    Lt,
    /// `<=` 数值小于等于。
    LtEq,
}

/// 过滤子句。
#[derive(Debug, Clone, PartialEq)]
pub enum Clause {
    /// 字段匹配: `key=value` / `a.b.c=value` / `status>=500` / `level=ERR*`。
    Field {
        /// 字段路径 (点分; 单段 = 顶层)。
        path: Vec<String>,
        op: Op,
        value: String,
    },
    /// 裸词: 整行子串, ASCII 大小写不敏感。
    Bare(String),
}

/// 解析查询: 空白分词, 含算子 (`= >= <= > <`) 为字段子句, 否则裸词。AND 语义。
pub fn parse_query(q: &str) -> Vec<Clause> {
    q.split_whitespace().map(parse_clause).collect()
}

/// 按 schema 的真实列名规范化子句键名 (仅**单段** path), 使 `LEVEL=ERROR` 也能命中
/// `"level"` 列。
///
/// **为什么要改写而不是让键也走不敏感匹配**: 键的 needle 是精确的 memmem 前缀
/// (`,"level":"`), 粗筛必须保持精确才能零 parse 直通。让键走不敏感正则实测
/// 1GB 1822ms (**22x 退化** —— prefilter 被每个键名开头的 `"`+字母打爆, spec D5 禁路);
/// 而拿用户键名到列发现结果里查一次表是零成本。
///
/// 查无此列 → **保持原样** (自然 0 命中, 语义正确 —— 不猜、不报错, 与列发现
/// 「找不到级别列就降级只读」同一条保守原则)。
///
/// **多段 path (点路径/嵌套键) 不动**: 嵌套键不在列发现表层, 逐层扫 IndexMap
/// 做不敏感查表不值当 (spec D6 边界, 写明为敏感)。
pub fn normalize_clause_keys(clauses: &mut [Clause], schema: &Schema) {
    for c in clauses.iter_mut() {
        let Clause::Field { path, .. } = c else {
            continue;
        };
        let [name] = path.as_mut_slice() else {
            continue; // 空路径或多段: 均不在本函数的职责内
        };
        if let Some(col) = schema
            .columns
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
        {
            // 大小写本就一致时不做无谓重分配 (且让「已是正确写法 = 无操作」显式)
            if col.name != *name {
                *name = col.name.clone();
            }
        }
    }
}

/// 单 token → 子句。
fn parse_clause(tok: &str) -> Clause {
    let Some((path_str, op, value)) = split_operator(tok) else {
        return Clause::Bare(tok.to_string());
    };
    let path: Vec<String> = path_str
        .split('.')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if path.is_empty() {
        return Clause::Bare(tok.to_string());
    }
    // `=` + 值尾缀 `*` → 前缀通配 (比较算子不识别 `*`)
    let (op, value) = if op == Op::Eq {
        match value.strip_suffix('*') {
            Some(prefix) => (Op::Prefix, prefix.to_string()),
            None => (Op::Eq, value.to_string()),
        }
    } else {
        (op, value.to_string())
    };
    Clause::Field { path, op, value }
}

/// 找算子: 返回 (路径串, 算子, 值串)。长算子 (`>=`/`<=`) 先于短算子匹配。
fn split_operator(tok: &str) -> Option<(&str, Op, &str)> {
    for (pat, op) in [
        (">=", Op::GtEq),
        ("<=", Op::LtEq),
        (">", Op::Gt),
        ("<", Op::Lt),
        ("=", Op::Eq),
    ] {
        if let Some(pos) = tok.find(pat) {
            return Some((&tok[..pos], op, &tok[pos + pat.len()..]));
        }
    }
    None
}

/// 预编译子句 (needle 只造一次, 过滤循环零分配)。
enum Compiled {
    /// 裸词: 整行子串, **ASCII 大小写不敏感** (2026-09-15; 见 [`contains_ascii_ci`])。
    Bare(Vec<u8>),
    /// 扁平等值/前缀: memmem 提取值 token 直通, 零 parse (POC 性能路径)。
    ///
    /// `finder` 与 `needle` 同源、构造期一次建好 —— **不要**在逐行路径里用
    /// [`extract_field`] 那种每次重建搜索器的写法 (实测差 20 倍以上, 见
    /// [`FieldExtractor`] 的文档)。
    Flat {
        needle: Vec<u8>,
        op: Op,
        value: String,
        /// `Box` 化了: `Finder` 内含 prefilter 表, 直接内联会把本枚举撑到
        /// clippy 的 `large_enum_variant` 阈值; 每条子句只解一次引用, 代价可忽略。
        finder: Box<memchr::memmem::Finder<'static>>,
    },
    /// 需 parse 验证 (点路径或比较算子): 粗筛最内层 key + serde_json 导航比较。
    Verify {
        needle: Vec<u8>,
        path: Vec<String>,
        op: Op,
        value: String,
    },
}

/// ASCII 大小写不敏感前缀 (按**字节**比对, 不要求 UTF-8 字符边界)。
///
/// `pub` 是因为**产品侧的级别分类器 (字段口径) 必须与过滤子句同口径** ——
/// 桶可点, 点下去走 `col=WARN*` 的 Flat 前缀; 两边共用这一个原语, 「桶计数 ==
/// 筛选结果」才是构造保证而不是碰巧 (spec D7 / SPEC-level-histogram D2 红线)。
pub fn starts_with_ascii_ci(hay: &[u8], prefix: &[u8]) -> bool {
    hay.len() >= prefix.len() && hay[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// 值 token 匹配: Eq 全等, Prefix 前缀 (**两者均 ASCII 大小写不敏感**, 2026-09-15),
/// 比较算子按数值 (token 解析, 非数值不匹配) —— 数值算子**不受大小写逻辑影响**。
/// 扁平直通与点路径粗筛共用。比较按 token 解析成 f64 —— 字符串 "500" 也会当数值 500,
/// 与 parse 路径 (`compare_val`) 的严格字符串/数值区分有差异 (有意边界: 扁平比较是性能直通)。
fn token_matches(token: &[u8], op: Op, target: &str) -> bool {
    match op {
        Op::Eq => token.eq_ignore_ascii_case(target.as_bytes()),
        Op::Prefix => starts_with_ascii_ci(token, target.as_bytes()),
        Op::Gt | Op::GtEq | Op::Lt | Op::LtEq => {
            let Some(n) = std::str::from_utf8(token)
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
            else {
                return false;
            };
            let Ok(t) = target.parse::<f64>() else {
                return false;
            };
            match op {
                Op::Gt => n > t,
                Op::GtEq => n >= t,
                Op::Lt => n < t,
                Op::LtEq => n <= t,
                _ => unreachable!(),
            }
        }
    }
}

/// 验证路径比较: 等值/前缀按显示串 ([`cell_display`], **ASCII 大小写不敏感**),
/// 比较按数值 (非数值不匹配)。**嵌套键 (路径段名) 保持精确** —— 见 [`normalize_clause_keys`]。
fn compare_val(val: &serde_json::Value, op: Op, target: &str) -> bool {
    match op {
        Op::Eq => cell_display(val).eq_ignore_ascii_case(target),
        Op::Prefix => starts_with_ascii_ci(cell_display(val).as_bytes(), target.as_bytes()),
        Op::Gt | Op::GtEq | Op::Lt | Op::LtEq => {
            let Some(n) = val.as_f64() else {
                return false;
            };
            let Ok(t) = target.parse::<f64>() else {
                return false;
            };
            match op {
                Op::Gt => n > t,
                Op::GtEq => n >= t,
                Op::Lt => n < t,
                Op::LtEq => n <= t,
                _ => unreachable!(),
            }
        }
    }
}

/// 沿路径导航: 对象取 key, 数组取索引。中途非对象/数组 = 无。
fn navigate<'a>(mut val: &'a serde_json::Value, path: &[String]) -> Option<&'a serde_json::Value> {
    for seg in path {
        val = match val {
            serde_json::Value::Object(map) => map.get(seg)?,
            serde_json::Value::Array(arr) => {
                let i: usize = seg.parse().ok()?;
                arr.get(i)?
            }
            _ => return None,
        };
    }
    Some(val)
}

/// ASCII 大小写不敏感子串查找 —— 裸词过滤专用 (`memmem` 没有不敏感模式)。
///
/// 结构照搬 memmem 的两段式: **SIMD 定位候选 + 常数验窗**。首字节取大小写双变体
/// 交给 `memchr2` (首字节非字母时两变体同值, 退化为 `memchr`, 无额外代价),
/// 命中位置再用 `eq_ignore_ascii_case` 验整个窗口。
///
/// **为什么手写不选 `(?i-u)` 正则**: 每行一次 regex VM 进入/退出在同一量级的
/// 循环里是实打实的常数差; 本仓过滤路径通篇是 memchr 系惯用法, 不引第二种匹配机制。
/// 代价是要自己保证正确性 —— 故单测用**正则 oracle 穷举对拍**钉死语义。
///
/// **非 ASCII 字节按字面比较, 不折叠** —— 与 `(?i-u)` 在字节面上的行为一致。
/// 这是有意的: 非 UTF-8 文件 (GBK) 的过滤不过转码, 折叠只能在字节面做 (spec D4)。
///
/// **已知并接受的最坏情况**: 候选定位是 SIMD 的, 但验窗是线性的, 故单行内大量
/// 重复字节 + 长裸词 (如 1 MiB 的 `a` 里找 `a…ab`) 在该行退化为 O(n·m)。
/// 正常日志行长几百字节、且裸词也就几个字符, 到不了这个形状;
/// 真撞上再按词长分流回 `memmem` (只对全小写词——那时无需折叠)。
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return true; // 空 needle 处处命中 —— 与 memmem::find 同语义
    };
    if needle.len() > haystack.len() {
        return false;
    }
    // 候选窗口只到「再往后就放不下整个 needle」为止 —— 先切掉尾巴, 于是下面
    // 每个候选位置都天然合法, 不必在循环里再判一次越界。
    let windows = &haystack[..=haystack.len() - needle.len()];
    // 两变体必须是 **lower 与 upper 一对**: 拿 `first` 配 `to_ascii_uppercase()`
    // 在首字节本就是大写时两值相同, memchr2 退化成单字节搜索、漏掉小写候选
    // (穷举 oracle 当场抓到 —— 非字母时两变体同值无害)。
    memchr::memchr2_iter(
        first.to_ascii_lowercase(),
        first.to_ascii_uppercase(),
        windows,
    )
    .any(|at| haystack[at + 1..at + needle.len()].eq_ignore_ascii_case(rest))
}

/// 单行判定: 全部子句命中 (AND)。
fn line_matches(line: &[u8], clauses: &[Compiled]) -> bool {
    clauses.iter().all(|c| match c {
        Compiled::Bare(w) => contains_ascii_ci(line, w),
        Compiled::Flat {
            needle,
            op,
            value,
            finder,
        } => next_field_value_with(line, needle, finder, 0)
            .is_some_and(|(v, _)| token_matches(v, *op, value)),
        Compiled::Verify {
            needle,
            path,
            op,
            value,
        } => {
            // 粗筛: 任一 leaf 字段值命中才 parse 验证 (把候选压到值命中量级, 免全量 parse)
            if !field_value_matches(line, needle, *op, value) {
                return false;
            }
            let Some(parsed) = parse_line(line) else {
                return false;
            };
            let Some(val) = navigate(&parsed, path) else {
                return false;
            };
            compare_val(val, *op, value)
        }
    })
}

/// 全文字段过滤: 顺序走一遍 (lines() 迭代器, 每行 O(1)), 返回命中行号 (升序)。
/// 大文件 (≥64MB) 走分段并行, 小文件单线程 (简洁优先)。
/// 禁用 line(i) 逐行随机访问 —— 步进索引下每次定位带段内前扫, 全量遍历会
/// 把成本乘进行数 (T1 实测回归 235ms → 1072ms 的教训, 见 logfile.rs::lines 注释)。
pub fn run_filter(file: &LogFile, clauses: &[Clause]) -> Vec<u64> {
    run_filter_from(file, clauses, 0)
}

/// 增量过滤: 只对 >= start_line 的行跑谓词 (live-tail 追加), 返回命中行号 (升序)。
/// 走 `lines_from` 顺序扫描, 不重扫前文 —— 与全量路径命中集一致 (单测对拍)。
pub fn run_filter_from(file: &LogFile, clauses: &[Clause], start_line: u64) -> Vec<u64> {
    let compiled: Vec<Compiled> = clauses.iter().map(compile).collect();
    if compiled.is_empty() {
        return (start_line..file.line_count()).collect();
    }
    let total = file.line_count();
    if start_line >= total {
        return Vec::new();
    }
    let remaining = total - start_line;
    if remaining < PARALLEL_FILTER_THRESHOLD {
        // 小文件单线程 (阈值以下并行开销大于收益)
        let mut hits = Vec::new();
        for (i, line) in file.lines_from(start_line) {
            if line_matches(line, &compiled) {
                hits.push(i);
            }
        }
        return hits;
    }
    // 大文件并行: 按行等分, 每线程过滤一段, 合并结果
    // 分段策略: 按行等分保证每线程工作量相近, 合并时按序拼接保行号升序
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX_FILTER_THREADS);
    if threads <= 1 {
        let mut hits = Vec::new();
        for (i, line) in file.lines_from(start_line) {
            if line_matches(line, &compiled) {
                hits.push(i);
            }
        }
        return hits;
    }
    let chunk = remaining.div_ceil(threads as u64);
    let compiled = &compiled;
    let mut all_hits: Vec<Vec<u64>> = Vec::with_capacity(threads);
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..threads {
            let begin = start_line + t as u64 * chunk;
            let end = (begin + chunk).min(total);
            if begin >= total {
                break;
            }
            handles.push(s.spawn(move || {
                let mut hits = Vec::new();
                for (i, line) in file.lines_from(begin) {
                    if i >= end {
                        break;
                    }
                    if line_matches(line, compiled) {
                        hits.push(i);
                    }
                }
                hits
            }));
        }
        for h in handles {
            all_hits.push(h.join().expect("过滤线程 panic"));
        }
    });
    // 合并: 已按顺序, 直接拼接
    let mut hits = Vec::new();
    for h in all_hits {
        hits.extend(h);
    }
    hits
}

/// 子句 → 预编译 (needle = 最内层 key 的 `"key":` 针)。
fn compile(c: &Clause) -> Compiled {
    match c {
        Clause::Bare(w) => Compiled::Bare(w.as_bytes().to_vec()),
        Clause::Field { path, op, value } => {
            let leaf = path.last().map(String::as_str).unwrap_or("");
            let needle = field_needle(leaf);
            // 扁平字段 (任意算子) → token 直通零 parse; 点路径 → 粗筛 + parse 验证
            if path.len() == 1 {
                Compiled::Flat {
                    finder: Box::new(memchr::memmem::Finder::new(&needle).into_owned()),
                    needle,
                    op: *op,
                    value: value.clone(),
                }
            } else {
                Compiled::Verify {
                    needle,
                    path: path.clone(),
                    op: *op,
                    value: value.clone(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 落一个临时 JSONL 文件并打开 (文件名全局唯一: Windows 拒绝截断仍被映射的文件)。
    fn open_with(content: &[u8]) -> LogFile {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "danqing-log-jsonl-test-{}-{}-{}.log",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            content.len()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content).unwrap();
        }
        let lf = LogFile::open(&path).unwrap();
        std::fs::remove_file(&path).ok();
        lf
    }

    #[test]
    fn detect_jsonl_true() {
        let lf = open_with(b"{\"a\":1}\n{\"a\":2,\"b\":\"x\"}\n{\"a\":3}\n{\"a\":4}\n");
        assert!(detect(&lf));
    }

    #[test]
    fn detect_plain_log_false() {
        let lf = open_with(
            b"2026-09-05 INFO hello\n2026-09-05 INFO world\n2026-09-05 WARN x\n2026-09-05 INFO y\n",
        );
        assert!(!detect(&lf));
    }

    #[test]
    fn detect_tolerates_some_bad_lines() {
        // 10 行里 1 行坏 = 90% 及格线
        let mut content = String::new();
        for i in 0..9 {
            content.push_str(&format!("{{\"a\":{i}}}\n"));
        }
        content.push_str("not json\n");
        let lf = open_with(content.as_bytes());
        assert!(detect(&lf), "90% object 占比应判 JSONL");
    }

    #[test]
    fn schema_first_seen_order_and_widths() {
        let lf = open_with(
            b"{\"level\":\"INFO\",\"msg\":\"hi\",\"duration_ms\":12}\n{\"level\":\"ERROR\",\"msg\":\"a much longer message here\",\"status\":500}\n",
        );
        let s = discover_schema(&lf).expect("应有列");
        let names: Vec<&str> = s.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["level", "msg", "duration_ms", "status"],
            "首见顺序"
        );
        let msg = &s.columns[1];
        assert_eq!(msg.width_chars, 26, "宽度取采样最大值: {msg:?}");
        let status = &s.columns[3];
        assert_eq!(status.width_chars, 6, "短值按字段名长度: {status:?}");
    }

    #[test]
    fn extract_string_number_bool() {
        let line = br#"{"level":"ERROR","duration_ms":123,"ok":true,"ref":null}"#;
        assert_eq!(extract_field(line, "level"), Some(&b"ERROR"[..]));
        assert_eq!(extract_field(line, "duration_ms"), Some(&b"123"[..]));
        assert_eq!(extract_field(line, "ok"), Some(&b"true"[..]));
        assert_eq!(extract_field(line, "ref"), Some(&b"null"[..]));
        assert_eq!(extract_field(line, "missing"), None);
    }

    #[test]
    fn extract_skips_escaped_quote_in_string() {
        let line = br#"{"msg":"say \"hi\" now","x":1}"#;
        assert_eq!(extract_field(line, "msg"), Some(&br#"say \"hi\" now"#[..]));
        assert_eq!(extract_field(line, "x"), Some(&b"1"[..]));
    }

    #[test]
    fn extract_rejects_key_without_json_prefix() {
        // 裸文本里的 "level":"X" (前面不是 { 或 ,) 不算字段
        let line = br#"log prefix "level":"ERROR" tail"#;
        assert_eq!(extract_field(line, "level"), None);
    }

    #[test]
    fn parse_line_resolves_adversarial_embedded_key() {
        // 对抗样本: msg 值内含 `,"key":"` 形态 —— memmem 提取会误判成 WRONG,
        // 真 parser 不会 (T1 显示路径换 parser 的核心回归)。
        let line = br#"{"msg":"see ,\"key\":\"WRONG\" here","key":"RIGHT"}"#;
        let v = parse_line(line).expect("应可解析");
        assert_eq!(cell_display(v.get("key").unwrap()), "RIGHT");
        assert_eq!(
            cell_display(v.get("msg").unwrap()),
            "see ,\"key\":\"WRONG\" here"
        );
    }

    #[test]
    fn cell_display_compacts_nested_values() {
        let v = parse_line(br#"{"user":{"id":42},"tags":[1,2],"ok":true,"ref":null}"#).unwrap();
        assert_eq!(cell_display(v.get("user").unwrap()), "{\"id\":42}");
        assert_eq!(cell_display(v.get("tags").unwrap()), "[1,2]");
        assert_eq!(cell_display(v.get("ok").unwrap()), "true");
        assert_eq!(cell_display(v.get("ref").unwrap()), "null");
    }

    #[test]
    fn flatten_nested_object_and_array() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"level":"INFO","user":{"id":42,"name":"bob"},"tags":[7,8]}"#)
                .unwrap();
        let rows = flatten(&v);
        // level 是顶层叶子 = 列, 不进子行; user/tags 是容器 → 展开
        assert_eq!(
            rows,
            vec![
                SubRow {
                    depth: 1,
                    label: "user".into(),
                    value: "{\"id\":42,\"name\":\"bob\"}".into()
                },
                SubRow {
                    depth: 2,
                    label: "id".into(),
                    value: "42".into()
                },
                SubRow {
                    depth: 2,
                    label: "name".into(),
                    value: "bob".into()
                },
                SubRow {
                    depth: 1,
                    label: "tags".into(),
                    value: "[7,8]".into()
                },
                SubRow {
                    depth: 2,
                    label: "[0]".into(),
                    value: "7".into()
                },
                SubRow {
                    depth: 2,
                    label: "[1]".into(),
                    value: "8".into()
                },
            ]
        );
    }

    #[test]
    fn flatten_top_level_scalars_are_columns_not_rows() {
        let v = parse_line(br#"{"level":"ERROR","msg":"x"}"#).unwrap();
        assert!(flatten(&v).is_empty(), "全顶层叶子 → 无子行");
    }

    #[test]
    fn is_expandable_detects_nested_fields() {
        let v = parse_line(br#"{"user":{"id":1},"tags":[1,2]}"#).unwrap();
        assert!(is_expandable(&v), "有嵌套对象/数组");
        let flat = parse_line(br#"{"level":"ERROR","msg":"x"}"#).unwrap();
        assert!(!is_expandable(&flat), "全顶层叶子不可展开");
    }

    #[test]
    fn parse_query_splits_clauses() {
        let clauses = parse_query("level=ERROR status=50* slow");
        assert_eq!(
            clauses,
            vec![
                Clause::Field {
                    path: vec!["level".into()],
                    op: Op::Eq,
                    value: "ERROR".into()
                },
                Clause::Field {
                    path: vec!["status".into()],
                    op: Op::Prefix,
                    value: "50".into()
                },
                Clause::Bare("slow".into()),
            ]
        );
        // 点路径 + 比较算子 (长算子 >= 先于 >)
        let clauses = parse_query("user.id=42 status>=500 duration_ms>1000");
        assert_eq!(
            clauses,
            vec![
                Clause::Field {
                    path: vec!["user".into(), "id".into()],
                    op: Op::Eq,
                    value: "42".into()
                },
                Clause::Field {
                    path: vec!["status".into()],
                    op: Op::GtEq,
                    value: "500".into()
                },
                Clause::Field {
                    path: vec!["duration_ms".into()],
                    op: Op::Gt,
                    value: "1000".into()
                },
            ]
        );
    }

    #[test]
    fn field_value_match_is_case_insensitive() {
        let lf = open_with(
            br#"{"level":"INFO","msg":"ok"}
{"level":"ERROR","msg":"boom"}
{"level":"WARNING","msg":"slow"}
"#,
        );
        assert_eq!(run_filter(&lf, &parse_query("level=error")), vec![1]);
        assert_eq!(run_filter(&lf, &parse_query("level=Error")), vec![1]);
        assert_eq!(
            run_filter(&lf, &parse_query("level=warn*")),
            vec![2],
            "前缀通配同样不敏感 (WARNING 命中 warn*)"
        );
        assert_eq!(run_filter(&lf, &parse_query("level=WARN*")), vec![2]);
        // 数值算子不参与大小写逻辑, 行为不变
        let num = open_with(b"{\"status\":500}\n{\"status\":\"error\"}\n");
        assert_eq!(run_filter(&num, &parse_query("status>=500")), vec![0]);
    }

    #[test]
    fn normalize_clause_keys_maps_to_real_column_name() {
        let schema = Schema {
            columns: vec![Column {
                name: "level".into(),
                width_chars: 5,
            }],
        };
        let field = |p: &str, v: &str| Clause::Field {
            path: vec![p.to_string()],
            op: Op::Eq,
            value: v.to_string(),
        };

        // 键名大小写不同 → 改写为列里的真实写法 (否则 memmem needle 精确匹配不上)
        let mut c = parse_query("LEVEL=ERROR");
        normalize_clause_keys(&mut c, &schema);
        assert_eq!(c, vec![field("level", "ERROR")]);

        // 查无此列 → 保持原样 (自然 0 命中, 不猜)
        let mut c = parse_query("nosuch=1");
        normalize_clause_keys(&mut c, &schema);
        assert_eq!(c, vec![field("nosuch", "1")]);

        // 多段 path (嵌套键) 不动 —— spec D6 边界
        let mut c = parse_query("a.b=1");
        normalize_clause_keys(&mut c, &schema);
        assert_eq!(
            c,
            vec![Clause::Field {
                path: vec!["a".into(), "b".into()],
                op: Op::Eq,
                value: "1".into(),
            }]
        );

        // 裸词不带键, 不受影响
        let mut c = parse_query("ERROR");
        normalize_clause_keys(&mut c, &schema);
        assert_eq!(c, vec![Clause::Bare("ERROR".into())]);

        // 端到端: 规范化后大写键名真的能筛出小写列名文件
        let lf = open_with(b"{\"level\":\"ERROR\"}\n{\"level\":\"INFO\"}\n");
        let mut c = parse_query("LEVEL=ERROR");
        normalize_clause_keys(&mut c, &schema);
        assert_eq!(run_filter(&lf, &c), vec![0]);
    }

    #[test]
    fn nested_key_stays_case_sensitive_but_value_does_not() {
        let lf = open_with(b"{\"user\":{\"Level\":\"ERROR\"}}\n");
        // 值不敏感
        assert_eq!(run_filter(&lf, &parse_query("user.Level=error")), vec![0]);
        // 嵌套键保持精确 (spec D6 边界): 键写错大小写 → 不命中
        assert_eq!(
            run_filter(&lf, &parse_query("user.level=error")),
            Vec::<u64>::new(),
            "嵌套键不敏感化 (边界, 写明为敏感)"
        );
    }

    #[test]
    fn token_matches_eq_and_prefix() {
        assert!(token_matches(b"500", Op::Eq, "500"));
        assert!(!token_matches(b"500", Op::Eq, "50"));
        assert!(token_matches(b"500", Op::Prefix, "50"));
        assert!(token_matches(b"502", Op::Prefix, "50"));
        assert!(!token_matches(b"200", Op::Prefix, "50"));
        assert!(token_matches(b"ERROR", Op::Eq, "ERROR"));
        assert!(!token_matches(b"ERRORS", Op::Eq, "ERROR"));
    }

    #[test]
    fn navigate_dot_path_and_array() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"user":{"id":42,"tags":[7,8]}}"#).unwrap();
        let p = |s: &str| s.split('.').map(String::from).collect::<Vec<_>>();
        assert_eq!(navigate(&v, &p("user")).unwrap()["id"].as_i64(), Some(42));
        assert_eq!(navigate(&v, &p("user.id")).unwrap().as_i64(), Some(42));
        assert_eq!(navigate(&v, &p("user.tags.1")).unwrap().as_i64(), Some(8));
        assert!(navigate(&v, &p("user.nope")).is_none());
        assert!(navigate(&v, &p("nope.id")).is_none());
    }

    #[test]
    fn compare_val_operators_and_boundaries() {
        let num = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        assert!(compare_val(&num("500"), Op::GtEq, "500"), ">= 含等");
        assert!(compare_val(&num("501"), Op::Gt, "500"));
        assert!(!compare_val(&num("500"), Op::Gt, "500"), "> 不含等");
        assert!(compare_val(&num("-5"), Op::Lt, "0"), "负数");
        assert!(compare_val(&num("1.5"), Op::Lt, "2"), "浮点");
        assert!(compare_val(&num("42"), Op::Eq, "42"), "Eq 数值按显示串");
        assert!(
            !compare_val(&serde_json::Value::String("500".into()), Op::Gt, "0"),
            "字符串不参与数值比较"
        );
    }

    #[test]
    fn filter_dot_path_and_comparison() {
        let lf = open_with(
            br#"{"user":{"id":42},"status":500}
{"user":{"id":7},"status":200}
{"user":{"id":99},"status":503}
{"user":{"id":42},"status":501}
"#,
        );
        assert_eq!(run_filter(&lf, &parse_query("user.id=42")), vec![0, 3]);
        assert_eq!(run_filter(&lf, &parse_query("status>=500")), vec![0, 2, 3]);
        assert_eq!(
            run_filter(&lf, &parse_query("user.id=42 status>=500")),
            vec![0, 3]
        );
        assert_eq!(run_filter(&lf, &parse_query("user.id=4*")), vec![0, 3]);
    }

    #[test]
    fn field_value_matches_scans_all_occurrences() {
        // order.id 在前 (值 7), user.id 在后 (值 42): 粗筛必须扫到后者, 无假阴性
        let line = br#"{"order":{"id":7},"user":{"id":42}}"#;
        let needle = field_needle("id");
        assert!(
            field_value_matches(line, &needle, Op::Eq, "42"),
            "第二处 id 命中"
        );
        assert!(!field_value_matches(line, &needle, Op::Eq, "99"), "无 99");
        // 精确验证仍走 navigate: 第一处 id=7 不代表 user.id=7
        let v = parse_line(line).unwrap();
        assert_eq!(
            navigate(&v, &["user".into(), "id".into()])
                .unwrap()
                .as_i64(),
            Some(42)
        );
    }

    #[test]
    fn run_filter_from_matches_full() {
        let lf = open_with(
            br#"{"level":"INFO","msg":"a"}
{"level":"ERROR","msg":"b"}
{"level":"INFO","msg":"c"}
{"level":"ERROR","msg":"d"}
{"level":"ERROR","msg":"e"}
"#,
        );
        let clauses = parse_query("level=ERROR");
        let full = run_filter(&lf, &clauses);
        assert_eq!(full, vec![1, 3, 4]);
        assert_eq!(run_filter_from(&lf, &clauses, 0), full, "从 0 起跑 == 全量");
        assert_eq!(run_filter_from(&lf, &clauses, 3), vec![3, 4], "中间起跑");
        assert_eq!(
            run_filter_from(&lf, &clauses, 99),
            Vec::<u64>::new(),
            "越界空"
        );
    }

    /// **FieldExtractor 与 extract_field 必须逐行一致** —— 前者只是把 needle 与
    /// memmem 搜索器提到循环外, 语义一个字都不许变 (这是它可以替换后者的前提)。
    #[test]
    fn field_extractor_matches_extract_field() {
        let fx = FieldExtractor::new("level");
        let corpora: Vec<&[u8]> = vec![
            br#"{"level":"ERROR","msg":"a"}"#,
            br#"{"msg":"a","level":"INFO"}"#,
            br#"{"nested":{"level":"WARN"},"level":"DEBUG"}"#,
            br#"{"msg":"x ,"level":"ERROR" y","level":"INFO"}"#,
            br#"{"level":"error"}"#,
            br#"{"levelx":"INFO"}"#,
            br#"{"a":1}"#,
            b"",
            b"plain text",
            br#"{"level":"ERROR"}"#,
            br#"{"level":"ERROR1","level":"WARN"}"#,
            br#"{"level":123}"#,
            br#"{"level":null}"#,
            br#"  {"level" : "TRACE"}  "#,
        ];
        for &c in &corpora {
            assert_eq!(
                fx.extract(c),
                extract_field(c, "level"),
                "语料 {:?}",
                String::from_utf8_lossy(c)
            );
        }
        // 别的 key 也要一致
        let fs = FieldExtractor::new("severity");
        for &c in &corpora {
            assert_eq!(fs.extract(c), extract_field(c, "severity"));
        }
    }

    /// 采样**按字节**收手, 不按 512 行一路解析下去。
    ///
    /// 这条钉的是「列发现成本有界」这个不变量: 去掉字节预算它就会红 —— 那时
    /// 一个大行文件会解析整窗几百 MiB, 正是 2026-09-12「索引 17ms 却等了十几秒」
    /// 的成因 (实测 200 MiB / 563 KiB 行: 3.17s → 71ms)。
    ///
    /// 代价是**有意的**: 预算窗口之外的列不会被发现, 故断言写成「窗外的列不出现」。
    /// 行宽 ≤ 8 KiB 时预算不生效, 普通日志不受影响 (见 `SCHEMA_SAMPLE_BYTES`)。
    #[test]
    fn schema_sampling_stops_at_byte_budget() {
        let big = "x".repeat(1024 * 1024); // 每行 ~1 MiB
        let mut content = Vec::new();
        for i in 0..40 {
            // 第 30 行才出现的列: 落在预算窗口 (\(4 MiB / 1 MiB =) 4~6 行) 之外
            let extra = if i == 30 { r#","late":"y""# } else { "" };
            content.extend_from_slice(
                format!(r#"{{"ts":"T","level":"INFO"{extra},"blob":"{big}"}}"#).as_bytes(),
            );
            content.push(b'\n');
        }
        let f = open_with(&content);
        let s = discover_schema(&f).expect("检出 schema");
        for want in ["ts", "level", "blob"] {
            assert!(
                s.columns.iter().any(|c| c.name == want),
                "窗内列 {want} 要认"
            );
        }
        assert!(
            !s.columns.iter().any(|c| c.name == "late"),
            "预算之外的列不得发现 —— 有界成本的代价, 有意为之"
        );
    }

    /// 值宽度探测: 有界版必须与「完整序列化再逐字符数」在**钳制后**逐值相等 ——
    /// 这是「只量前 32 个字符 / 有界序列化」可以成立的前提。
    #[test]
    fn bounded_value_width_equals_unbounded_after_clamp() {
        fn unbounded(v: &serde_json::Value) -> usize {
            match v {
                serde_json::Value::String(s) => s.chars().count(),
                other => other.to_string().chars().count(),
            }
        }
        let cases = vec![
            serde_json::json!(""),
            serde_json::json!("a"),
            serde_json::json!("exactly-thirty-two-chars-long!"),
            serde_json::json!("x".repeat(50_000)),
            serde_json::json!("日本語のテキスト"),
            serde_json::json!(1),
            serde_json::json!(true),
            serde_json::json!(null),
            serde_json::json!(12345678901234567890u64),
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!({"a": 1}),
            serde_json::json!([1, 2, 3]),
            serde_json::json!({"k": "日本語"}),
            serde_json::json!({"nested": {"deep": "y".repeat(40_000)}}),
            serde_json::json!((0..500).collect::<Vec<i32>>()),
        ];
        for v in cases {
            let want = unbounded(&v).clamp(4, WIDTH_CLAMP);
            let got = value_width(&v).clamp(4, WIDTH_CLAMP);
            assert_eq!(got, want, "值 {v} 钳制后不等");
        }
    }

    /// 装得下时, 有界序列化必须给出**精确**前缀 (不能被上界粗暴吞成「很宽」)。
    #[test]
    fn compact_prefix_is_exact_when_it_fits() {
        let p = |v: &serde_json::Value, cap: usize| {
            compact_prefix(v, cap).map(|b| String::from_utf8_lossy(&b).into_owned())
        };
        assert_eq!(
            p(&serde_json::json!({"a": 1}), 256).as_deref(),
            Some(r#"{"a":1}"#)
        );
        assert_eq!(p(&serde_json::json!([1, 2]), 256).as_deref(), Some("[1,2]"));
        assert_eq!(p(&serde_json::json!("s"), 256).as_deref(), Some(r#""s""#));
        assert!(
            p(&serde_json::json!({"k": "y".repeat(1000)}), 16).is_none(),
            "超界须返回 None 而不是截断的前缀 (截断的 JSON 数出来的字符数没意义)"
        );
    }

    #[test]
    fn filter_field_and_bare() {
        let lf = open_with(
            br#"{"level":"INFO","msg":"fast"}
{"level":"ERROR","msg":"slow query"}
{"level":"ERROR","msg":"fast"}
{"level":"WARN","msg":"slow disk"}
"#,
        );
        let hits = run_filter(&lf, &parse_query("level=ERROR"));
        assert_eq!(hits, vec![1, 2]);
        let hits = run_filter(&lf, &parse_query("level=ERROR slow"));
        assert_eq!(hits, vec![1], "字段+裸词 AND");
        let hits = run_filter(&lf, &parse_query("level=ERR*"));
        assert_eq!(hits, vec![1, 2], "前缀通配");
        let hits = run_filter(&lf, &[]);
        assert_eq!(hits.len(), 4, "空查询 = 全量");
    }

    #[test]
    fn bare_word_is_case_insensitive() {
        let lf = open_with(
            b"2026-09-05 ERROR boom\n\
              2026-09-05 error soft\n\
              2026-09-05 Error Mixed\n\
              2026-09-05 WARN ok\n",
        );
        // 四种输入的**文件内容**大小写各异, 同一个词必须命中同样 3 行
        for q in ["error", "ERROR", "Error", "eRrOr"] {
            assert_eq!(
                run_filter(&lf, &parse_query(q)),
                vec![0, 1, 2],
                "裸词 {q} 应大小写不敏感"
            );
        }
        assert_eq!(
            run_filter(&lf, &parse_query("error boom")),
            vec![0],
            "多裸词 AND, 逐词都不敏感"
        );
    }

    #[test]
    fn bare_word_does_not_fold_across_multibyte_bytes() {
        // 非 UTF-8 文件不过转码, 匹配发生在字节面 —— 折叠只碰 ASCII, 不进多字节内部。
        // 0xE9 不是 'e' 的折叠伙伴 (那是 Latin-1 的 é, 与 ASCII 折叠无关)。
        let lf = open_with(&[
            0xE9, b'r', b'r', b'o', b'r', b'\n', b'E', b'R', b'R', b'O', b'R', b'\n',
        ]);
        assert_eq!(
            run_filter(&lf, &parse_query("error")),
            vec![1],
            "非 ASCII 首字节不得折叠成 ASCII 字母"
        );
        // 汉字查询词 (多字节) 照常按字节命中, 不受折叠影响
        // (第二行**不能**含「中文」子串 —— 否则测的是子串语义不是这里要验的折叠)
        let lf = open_with("中文error日志\n纯汉字一行\n".as_bytes());
        assert_eq!(run_filter(&lf, &parse_query("中文")), vec![0]);
        assert_eq!(run_filter(&lf, &parse_query("汉字")), vec![1]);
        assert_eq!(run_filter(&lf, &parse_query("ERROR")), vec![0]);
    }

    /// oracle: `(?i-u)` 对字面串的语义 —— ASCII 字母展开成双变体类, 其余字节按原值。
    /// 手写 [`contains_ascii_ci`] 的正确性全靠这条对拍。
    fn ci_oracle(needle: &[u8]) -> regex::bytes::Regex {
        let mut pat = String::from("(?-u)");
        for &b in needle {
            if b.is_ascii_alphabetic() {
                let lo = b.to_ascii_lowercase() as char;
                let up = b.to_ascii_uppercase() as char;
                pat.push_str(&format!("[{lo}{up}]"));
            } else {
                // `(?-u)` 下 \xNN 是原始字节; 缺了它 \xE9 会展开成 UTF-8 码点
                pat.push_str(&format!("\\x{b:02X}"));
            }
        }
        regex::bytes::Regex::new(&pat).unwrap()
    }

    /// 字母表所有定长串 (穷举用)。
    fn all_strings(alphabet: &[u8], len: usize) -> Vec<Vec<u8>> {
        let mut out = vec![Vec::new()];
        for _ in 0..len {
            let mut next = Vec::with_capacity(out.len() * alphabet.len());
            for s in &out {
                for &b in alphabet {
                    let mut t = s.clone();
                    t.push(b);
                    next.push(t);
                }
            }
            out = next;
        }
        out
    }

    #[test]
    fn contains_ascii_ci_matches_regex_oracle_exhaustively() {
        // 字母表含**非 ASCII 字节** —— 「非 ASCII 不折叠」是本函数的关键语义,
        // 只测 ASCII 的话漏掉它照样全绿。
        // 大小写**两组都放** (a/A 与 b/B): 只放 `a`/`A` 时 `b` 那一支的折叠
        // 全靠运气撞上, 对称覆盖才对得起「穷举」二字。
        const ALPHABET: [u8; 5] = [b'a', b'A', b'b', b'B', 0xE9];
        let mut haystacks = Vec::new();
        for n in 0..=4 {
            haystacks.extend(all_strings(&ALPHABET, n));
        }
        // needle 到 2 就够: 本函数的逻辑分支按「空 / 单字节 / 有 rest」三态分,
        // 更长的 needle 测的是同一段 `eq_ignore_ascii_case`, 不增覆盖。位置多变体
        // (贴边、重叠候选) 由 haystack 侧 0..=4 提供 —— 那才是微妙处。
        // 实测: 收到 ≤2 后对拍约 2.4 万组, 套件耗时回到秒内 (≤3 时是 12 万组 / 5 秒)。
        let mut needles = Vec::new();
        for n in 0..=2 {
            needles.extend(all_strings(&ALPHABET, n));
        }
        let mut checked = 0usize;
        for h in &haystacks {
            for nd in &needles {
                assert_eq!(
                    contains_ascii_ci(h, nd),
                    ci_oracle(nd).is_match(h),
                    "haystack={h:?} needle={nd:?}"
                );
                checked += 1;
            }
        }
        assert!(checked > 20_000, "对拍规模缩水: 只跑了 {checked} 组");
    }

    #[test]
    fn contains_ascii_ci_edge_cases() {
        assert!(contains_ascii_ci(b"anything", b""), "空 needle 处处命中");
        assert!(contains_ascii_ci(b"", b""), "空 vs 空");
        assert!(!contains_ascii_ci(b"", b"a"), "空 haystack");
        assert!(!contains_ascii_ci(b"ab", b"abc"), "needle 比 haystack 长");
        assert!(contains_ascii_ci(b"ERROR level", b"error"));
        assert!(contains_ascii_ci(b"error level", b"ERROR"));
        assert!(contains_ascii_ci(b"Error", b"eRRoR"));
        assert!(!contains_ascii_ci(b"ERRO level", b"ERROR"), "差一个字符");
        // 贴边: 窗口起点恰在上界 / needle 即整个 haystack
        assert!(contains_ascii_ci(b"xxERR", b"err"));
        assert!(contains_ascii_ci(b"ERR", b"err"));
        // 重叠候选: 首字节命中但验窗失败后必须继续找, 不能停在第一个候选上
        assert!(contains_ascii_ci(b"aab", b"ab"), "首个候选失败后须继续");
        assert!(contains_ascii_ci(b"aaaab", b"aaab"));
        // 非 ASCII 字节不折叠: 0xC9 不是 0xE9 的对应大小写
        assert!(!contains_ascii_ci(&[0xC9], &[0xE9]), "非 ASCII 不折叠");
        assert!(contains_ascii_ci(&[0xC3, 0x89], &[0xC3, 0x89]));
        // 汉字 (UTF-8 多字节) 不受影响
        assert!(contains_ascii_ci("中文error日志".as_bytes(), b"ERROR"));
        assert!(!contains_ascii_ci("中文日志".as_bytes(), b"error"));
    }
}
