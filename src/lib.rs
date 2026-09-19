//! @author 十四叔
//! @date 2026/09/10
//!
//! 丹青日志文件引擎 —— mmap + 行步进索引 + 全文正则搜索 + JSONL 列化。
//!
//! 从 danqing-log 独立为兄弟 crate, 供 LogLens 及未来消费大数据文件的产品共用。
//! 零 UI 依赖 (danqing-encoding 是纯逻辑 crate)。

pub mod jsonl;
pub mod logfile;
pub mod scan;
