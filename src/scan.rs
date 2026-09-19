//! @author 十四叔
//! @date 2026/09/19
//!
//! 顶层字段扫描器 —— danqing-log 字段分析模块的引擎前置
//! (SPEC-v1x-field-analytics D1)。
//!
//! 单遍状态机 (in-string / escape / 括号深度), 零 `Value` 树零分配: 只认
//! **顶层**(最外层对象内) 的键 —— 嵌套对象/数组里的同名键不算数。
//! 分析路径没有过滤那套「memmem 粗筛 + serde 验证」两段可省 (聚合对每行
//! 取值, 没有可跳过的行), 边界正确性必须自带 —— POC 已知的 `,"key":"`
//! 内嵌误判教训在档。
//!
//! 已知且接受的边界 (写明了才不算缺陷):
//! - 键名在文件里带 JSON 转义 (如 `"level"`) 时匹配不到纯文本键名 ——
//!   schema 列名来自 serde 解析 (已反转义), 这种畸形键名两边对不上, 不猜;
//! - 顶层重复键取**首个**, serde 的 Map 取末个 —— 差分测试语料不含重复键
//!   (真实日志几乎不产), 不一致性已声明。

/// 字段值类型 (聚合消费口径)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// 数字 (raw = 数字文本, 直接 `str::parse::<f64>`)。
    Num,
    /// 字符串 (raw = 引号内原文, **未反转义**; `has_escapes` 指示)。
    Str,
    Bool,
    Null,
    /// 嵌套对象/数组 (分析不可聚合, raw 为空)。
    Nested,
}

/// 一次顶层字段命中。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldValue<'a> {
    pub kind: FieldKind,
    /// Num = 数字文本; Str = 引号内原文; Bool/Null = 字面量; Nested = 空。
    pub raw: &'a [u8],
    /// Str 专用: 内容含 JSON 转义序列 —— 消费方要真值时, 把 raw 加引号丢给
    /// serde_json 兜底解析 (低频路径, 不值得自带一套含代理对的反转义)。
    pub has_escapes: bool,
}

/// 扫描一行 JSONL, 取顶层字段 `key` 的值。取不到 (无此键 / 行残件 /
/// 根非对象) 返回 `None`。
pub fn scan_field<'a>(line: &'a [u8], key: &str) -> Option<FieldValue<'a>> {
    let key = key.as_bytes();
    let n = line.len();
    let mut i = 0usize;
    let mut depth: i32 = 0; // { [ 加, } ] 减; 字符串内不计
    while i < n {
        match line[i] {
            b'"' => {
                let start = i + 1;
                let (end, _has_esc) = scan_string_end(line, start)?;
                // 该字符串是「顶层键」的充要条件: 括号深度 1 + 紧随其后是 ':'
                let mut k = end + 1;
                while k < n && matches!(line[k], b' ' | b'\t') {
                    k += 1;
                }
                if depth == 1 && k < n && line[k] == b':' && &line[start..end] == key {
                    return read_value(line, k + 1);
                }
                i = end + 1;
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// 从字符串内容起点找闭引号, 返回 (内容末偏移, 是否含转义)。
/// 行尾残件 (无闭引号, live-tail 半途行) → None。
fn scan_string_end(line: &[u8], mut i: usize) -> Option<(usize, bool)> {
    let mut has_esc = false;
    while i < line.len() {
        match line[i] {
            b'\\' => {
                has_esc = true;
                i += 1; // 跳过被转义的那个字节
            }
            b'"' => return Some((i, has_esc)),
            _ => {}
        }
        i += 1;
    }
    None
}

/// 跳过空白读值 token。行尾残件/非法起始 → None。
fn read_value(line: &[u8], mut i: usize) -> Option<FieldValue<'_>> {
    let n = line.len();
    while i < n && matches!(line[i], b' ' | b'\t') {
        i += 1;
    }
    if i >= n {
        return None;
    }
    let rest = &line[i..];
    match line[i] {
        b'"' => {
            let (end, has_esc) = scan_string_end(line, i + 1)?;
            Some(FieldValue {
                kind: FieldKind::Str,
                raw: &line[i + 1..end],
                has_escapes: has_esc,
            })
        }
        b'{' | b'[' => Some(FieldValue {
            kind: FieldKind::Nested,
            raw: &[],
            has_escapes: false,
        }),
        b't' if rest.starts_with(b"true") => Some(FieldValue {
            kind: FieldKind::Bool,
            raw: &rest[..4],
            has_escapes: false,
        }),
        b'f' if rest.starts_with(b"false") => Some(FieldValue {
            kind: FieldKind::Bool,
            raw: &rest[..5],
            has_escapes: false,
        }),
        b'n' if rest.starts_with(b"null") => Some(FieldValue {
            kind: FieldKind::Null,
            raw: &rest[..4],
            has_escapes: false,
        }),
        b'-' | b'0'..=b'9' => {
            let mut j = i;
            while j < n && matches!(line[j], b'-' | b'+' | b'0'..=b'9' | b'.' | b'e' | b'E') {
                j += 1;
            }
            Some(FieldValue {
                kind: FieldKind::Num,
                raw: &line[i..j],
                has_escapes: false,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── 对抗样本 (手写, 每条盯一个已知坑) ───

    #[test]
    fn finds_top_level_flat_field() {
        let v = scan_field(br#"{"level":"ERROR","duration_ms":42}"#, "level").unwrap();
        assert_eq!(v.kind, FieldKind::Str);
        assert_eq!(v.raw, b"ERROR");
        assert!(!v.has_escapes);
    }

    #[test]
    fn nested_same_name_key_is_not_matched() {
        // 嵌套对象的同名键不许顶包: 顶层无 "status", 内层有 —— 必须取不到。
        let line = br#"{"user":{"status":200},"ok":true}"#;
        assert_eq!(scan_field(line, "status"), None);
        // 顶层也有时取顶层那个 (内层 999 是干扰)。
        let line = br#"{"status":200,"user":{"status":999}}"#;
        let v = scan_field(line, "status").unwrap();
        assert_eq!(v.kind, FieldKind::Num);
        assert_eq!(v.raw, b"200");
    }

    #[test]
    fn fake_key_inside_string_value_is_not_matched() {
        // POC 已知边界的对抗形态: 值里内嵌 `,"level":"` —— memmem 会误中,
        // 状态机靠 in-string 跟踪免疫。
        let line = br#"{"msg":"boom ,\"level\":\"FATAL\" here","level":"INFO"}"#;
        let v = scan_field(line, "level").unwrap();
        assert_eq!(v.raw, b"INFO");
    }

    #[test]
    fn escaped_quotes_and_unicode_in_value() {
        // br#""# 必须 ASCII —— 含中文的用例走普通 raw string 再转字节。
        let line = r#"{"msg":"他说 \"你好\" A中","level":"WARN"}"#.as_bytes();
        let v = scan_field(line, "msg").unwrap();
        assert_eq!(v.kind, FieldKind::Str);
        assert!(v.has_escapes);
        // 消费方兜底路径: raw 加引号丢回 serde_json 必须解出真值。
        let mut token = Vec::new();
        token.push(b'"');
        token.extend_from_slice(v.raw);
        token.push(b'"');
        let s: String = serde_json::from_slice(&token).unwrap();
        assert_eq!(s, "他说 \"你好\" A中");
        let v = scan_field(line, "level").unwrap();
        assert_eq!(v.raw, b"WARN");
        assert!(!v.has_escapes);
    }

    #[test]
    fn numbers_negative_float_scientific() {
        let line = br#"{"a":-3.5,"b":1.2e4,"c":0}"#;
        assert_eq!(scan_field(line, "a").unwrap().raw, b"-3.5");
        assert_eq!(scan_field(line, "b").unwrap().raw, b"1.2e4");
        assert_eq!(scan_field(line, "c").unwrap().raw, b"0");
    }

    #[test]
    fn bool_null_nested_kinds() {
        let line = br#"{"ok":false,"err":null,"cfg":{"a":1},"tags":["x"]}"#;
        assert_eq!(scan_field(line, "ok").unwrap().kind, FieldKind::Bool);
        assert_eq!(scan_field(line, "err").unwrap().kind, FieldKind::Null);
        assert_eq!(scan_field(line, "cfg").unwrap().kind, FieldKind::Nested);
        assert_eq!(scan_field(line, "tags").unwrap().kind, FieldKind::Nested);
    }

    #[test]
    fn truncated_line_returns_none() {
        // live-tail 半途行 (无闭引号/无值)
        assert_eq!(scan_field(br#"{"level":"ERR"#, "level"), None);
        assert_eq!(scan_field(br#"{"level":"#, "level"), None);
        assert_eq!(scan_field(b"", "level"), None);
    }

    #[test]
    fn root_array_has_no_top_level_keys() {
        assert_eq!(scan_field(br#"[{"level":"ERROR"}]"#, "level"), None);
    }

    #[test]
    fn key_with_whitespace_around_colon() {
        let line = b"{ \"level\" : \"DEBUG\" }";
        let v = scan_field(line, "level").unwrap();
        assert_eq!(v.raw, b"DEBUG");
    }

    // ─── 差分对拍: 与 serde_json 全行 parse 逐值全等 (D1 的正确性判据) ───

    /// xorshift64 (与 logfile.rs 测试/genlog 同款确定性伪随机)。
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// 用 serde_json 序列化器造随机扁平对象行 (合法 JSON 由序列化器保证,
    /// 转义/unicode 都由它产出 —— 扫描器面对的就是这种真实字节)。
    fn random_line(rng: &mut Rng, fields: &[&str]) -> String {
        let mut map = serde_json::Map::new();
        for _ in 0..1 + rng.below(6) {
            let f = fields[rng.below(fields.len() as u64) as usize];
            if map.contains_key(f) {
                continue; // 重复键是已声明的不一致区, 语料不产 (见模块头)
            }
            let val = match rng.below(7) {
                0 => serde_json::json!(null),
                1 => serde_json::json!(rng.below(2) == 0),
                2 => serde_json::json!(rng.next() as f64 / 97.0 - 500.0),
                3 => serde_json::json!(rng.below(600) as i64 - 300),
                4 => serde_json::json!(format!("值{} with space", rng.below(50))),
                5 => serde_json::json!(format!("esc \"q\" \\ \n {}", rng.below(50))),
                _ => serde_json::json!({"nested": f}), // 嵌套对象 (同名键干扰)
            };
            map.insert(f.to_string(), val);
        }
        serde_json::Value::Object(map).to_string()
    }

    /// 对拍一单条: 扫描结果与 serde 全行 parse 逐值全等。
    fn assert_eq_serde(line: &str, key: &str) {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        let expect = parsed.as_object().and_then(|m| m.get(key));
        let got = scan_field(line.as_bytes(), key);
        match (expect, got) {
            (None, None) => {}
            (Some(v), Some(fv)) => {
                match v {
                    serde_json::Value::Number(n) => {
                        assert_eq!(fv.kind, FieldKind::Num, "{line} key={key}");
                        // 扫描器的合同是**字节保真** (raw = 原 token 文本)。
                        // 数值语义对拍时: serde_json 的浮点解析与 str::parse
                        // 可差 1 ulp (它有自己的浮点通路) —— 整数字面量两边都
                        // 精确, 必须全等; 含小数点/e 的浮点放宽到相对 1e-15。
                        let text = std::str::from_utf8(fv.raw).unwrap();
                        if n.is_i64() || n.is_u64() {
                            assert_eq!(text, n.to_string(), "{line} key={key}");
                        } else {
                            let a: f64 = text.parse().unwrap();
                            let b = n.as_f64().unwrap();
                            let tol = b.abs() * 1e-15 + f64::MIN_POSITIVE;
                            assert!((a - b).abs() <= tol, "{line} key={key}: {a} vs {b}");
                        }
                    }
                    serde_json::Value::String(s) => {
                        assert_eq!(fv.kind, FieldKind::Str, "{line} key={key}");
                        // raw 加引号丢回 serde 解出真值后与 parse 结果全等 ——
                        // 这条同时验证 token 边界与转义处理。
                        let mut token = Vec::new();
                        token.push(b'"');
                        token.extend_from_slice(fv.raw);
                        token.push(b'"');
                        let back: String = serde_json::from_slice(&token)
                            .unwrap_or_else(|e| panic!("token 回解失败 {e}: {line} key={key}"));
                        assert_eq!(&back, s, "{line} key={key}");
                    }
                    serde_json::Value::Bool(_) => assert_eq!(fv.kind, FieldKind::Bool),
                    serde_json::Value::Null => assert_eq!(fv.kind, FieldKind::Null),
                    serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                        assert_eq!(fv.kind, FieldKind::Nested, "{line} key={key}")
                    }
                }
            }
            (expect, got) => panic!("不一致: serde={expect:?} scan={got:?} 行={line} key={key}"),
        }
    }

    #[test]
    fn differential_against_serde_random_lines() {
        let fields = ["level", "status", "duration_ms", "msg", "user"];
        let mut rng = Rng(0x9e3779b97f4a7c15);
        for _ in 0..3000 {
            let line = random_line(&mut rng, &fields);
            for f in fields {
                assert_eq_serde(&line, f);
            }
        }
    }
}
