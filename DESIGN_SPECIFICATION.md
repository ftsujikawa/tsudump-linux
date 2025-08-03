# ELF/DWARF解析ツール 機能処理設計書

## 1. 概要

### 1.1 システム概要
本ツール（tsudump）は、ELFファイルの包括的解析を行うRust製コマンドラインツールです。ELFヘッダー、セクション情報、シンボルテーブル、DWARF1-5デバッグ情報、機械語逆アセンブルまで対応した高機能解析ツールです。

### 1.2 主要機能
- ELFファイル構造解析
- DWARF1-5デバッグ情報詳細解析
- シンボルテーブル解析
- .textセクション逆アセンブル
- 文字列参照解決（DW_FORM_strp, DW_FORM_string）
- 人間可読な技術情報表示

### 1.3 技術スタック
```toml
[dependencies]
elf = "0.7"          # ELF解析
gimli = "0.32"       # DWARF解析
iced-x86 = "1.21"    # x86-64逆アセンブル
```

## 2. システムアーキテクチャ

### 2.1 全体構成
```
┌─────────────────────────────────────────────────────────────┐
│                    tsudump メイン処理                       │
├─────────────────────────────────────────────────────────────┤
│  main()                                                     │
│  ├── コマンドライン引数処理                                   │
│  ├── ELFファイル読み込み                                     │
│  ├── ELFヘッダー解析・表示                                   │
│  ├── セクションヘッダー解析・表示                             │
│  ├── シンボルテーブル解析・表示                               │
│  ├── .textセクション逆アセンブル                              │
│  ├── デバッグセクション解析・表示                             │
│  └── DWARF詳細解析・表示                                    │
├─────────────────────────────────────────────────────────────┤
│  ELF解析層 (elf crate)                                      │
│  ├── ElfBytes::minimal_parse()                              │
│  ├── section_headers()                                      │
│  ├── section_data()                                         │
│  └── symbols()                                              │
├─────────────────────────────────────────────────────────────┤
│  DWARF解析層 (gimli crate)                                  │
│  ├── Dwarf::load()                                          │
│  ├── CompilationUnitHeadersIter                             │
│  ├── DebuggingInformationEntry                              │
│  └── AttributeValue解析                                     │
├─────────────────────────────────────────────────────────────┤
│  逆アセンブル層 (iced-x86 crate)                             │
│  ├── Decoder::with_ip()                                     │
│  ├── NasmFormatter::new()                                   │
│  └── Instruction解析                                        │
└─────────────────────────────────────────────────────────────┘
```

## 3. 機能詳細仕様

### 3.1 コマンドライン引数処理

**機能**: コマンドライン引数の処理とファイル指定

**処理フロー**:
1. `std::env::args()`で引数取得
2. 引数数チェック（2個必要）
3. ファイルパス抽出
4. エラー時Usage表示

**使用方法**:
```bash
./target/debug/tsudump <elf_file>
```

**エラーハンドリング**:
- 引数不足時: "Usage: ./target/debug/tsudump <elf_file>"
- 適切な終了コード設定

### 3.2 ELFヘッダー解析

**機能**: ELFファイルのヘッダー情報を解析・表示


### 3. シンボルテーブル解析

**機能**: シンボル情報の詳細表示（制限なし）

**処理フロー**:
1. .symtabセクションの検索
2. シンボルエントリの解析
3. シンボル名の文字列テーブルからの解決

**出力例**:
```
=== Symbol Table ===
Found 37 symbols:
Symbol   Value            Size Type    Bind    Vis     Ndx Name
--------------------------------------------------------------------------------
0        0000000000000000    0 NOTYPE  LOCAL   DEFAULT UND 
1        0000000000000000    0 FILE    LOCAL   DEFAULT ABS a.c
2        0000000000001080   47 FUNC    GLOBAL  DEFAULT  16 main
```

### 4. .textセクション逆アセンブル

**機能**: 実行可能コードの逆アセンブル表示

**処理フロー**:
1. `.text`セクションの検索・読み込み
2. `iced-x86`デコーダーの初期化（x86-64）
3. `NasmFormatter`でNASM構文フォーマット
4. 機械語命令の順次デコード・表示
5. 最大100命令表示で出力制御

**表示形式**:
```
=== .text Section Disassembly ===
Address          Bytes                    Assembly
----------------------------------------------------------------
0000000000001080  f3 0f 1e fa              endbr64
0000000000001084  31 ed                    xor ebp,ebp
0000000000001086  49 89 d1                 mov r9,rdx
```

**技術詳細**:
- `Decoder::with_ip()`でx86-64デコーダ作成
- `instruction.ip()`でアドレス取得
- `instruction.len()`で命令長取得
- バイト配列から機械語バイトを16進表示

### 3.6 デバッグセクション解析
**機能**: DWARF関連セクションの解析・表示

**処理フロー**:
1. デバッグセクション（.debug_*）の検索
2. セクションデータの16進ダンプ表示
3. 制限なし全バイト表示（以前の256バイト制限撤廃）

**対象セクション**:
- `.debug_info`: コンパイルユニット・DIE情報
- `.debug_line`: 行番号情報
- `.debug_str`: 文字列テーブル
- `.debug_abbrev`: 略語テーブル
- `.debug_ranges`: アドレス範囲情報
- その他デバッグセクション

**表示形式**:
```
=== .debug_info Section ===
Size: 171 bytes
00000000: 67 00 00 00 04 00 00 00 00 00 08 01 00 00 00 00
00000010: 02 08 07 00 00 00 00 03 08 05 00 00 00 00 04 04
```

### 3.7 .debug_str文字列抽出
**機能**: .debug_strセクションから文字列を抽出・一覧表示

**処理フロー**:
1. `.debug_str`セクションの検索・読み込み
2. null終端文字列の抽出
3. 統計情報の計算
4. カテゴリ別自動分類

**表示項目**:
- オフセット・長さ・内容の一覧
- 統計情報（総数・平均長・最長・最短）
- カテゴリ分類（コンパイラ情報・型名・ファイルパス・その他）

**実装関数**: `extract_debug_str_strings()`

### 3.8 DWARF詳細解析

**機能**: gimliクレートを使用したDWARF情報の詳細解析

**処理フロー**:
1. DWARF関連セクションの読み込み（.debug_info, .debug_abbrev, .debug_str等）
2. `Dwarf::load()`でDWARF構造体作成
3. コンパイルユニットの順次解析
4. DIE（Debug Information Entry）の階層解析
5. 属性値の詳細解決・表示

#### 3.8.1 DWARFバージョン対応

**対応バージョン**: DWARF1-5完全対応

**バージョン別特徴**:
- **DWARF1**: Basic debug info, limited type information
- **DWARF2**: Enhanced type system, line number info, macro support
- **DWARF3**: 64-bit support, improved location expressions, namespaces
- **DWARF4**: Call frame info, ranges, improved compression
- **DWARF5**: Split DWARF, type units, improved performance

#### 3.8.2 Abbreviation Table解析

**処理フロー**:
1. `.debug_abbrev`セクションの読み込み
2. ULEB128エンコーディングの解析
3. タグ・属性・フォームの人間可読変換
4. DW_FORM詳細情報の表示

**表示例**:
```
--- Abbreviation Table ---
Abbrev Code 1: DW_TAG_compile_unit (0x11) - Children: Yes
    DW_AT_producer (0x25) -> DW_FORM_strp (0x0e)
      Description: Offset into .debug_str section (string pointer)
      Size: 4 or 8 bytes (offset)
      Example strings from .debug_str:
        0x66: "GNU C17 11.4.0 -mtune=generic..."
```

#### 3.8.3 コンパイルユニット解析

**処理フロー**:
1. `.debug_info`セクションの読み込み
2. コンパイルユニットヘッダーの解析
3. DWARFバージョンの判定・表示
4. ルートDIEの詳細解析
5. 子DIEの階層構造表示

**表示例**:
```
=== DWARF Analysis with gimli crate ===
Compilation Unit 1:
  Version: 4 (DWARF4)
  Features: Call frame info, ranges, improved compression
  Address size: 8 bytes
  Root DIE tag: DW_TAG_compile_unit (DwTag(17))
```

#### 3.8.4 属性値詳細解析

**対応フォーム**:
- **DW_FORM_string**: インライン文字列の直接表示
- **DW_FORM_strp**: .debug_str参照解決
- **DW_FORM_addr**: アドレス値の表示
- **DW_FORM_data1/2/4/8**: データ値の表示
- **DW_FORM_exprloc**: location expression表示
- **DW_FORM_ref***: DIE参照の表示

**特別処理属性**:
- **DW_AT_language**: 言語コードの人間可読表示（"Rust (DwLang(28))"）
- **DW_AT_producer**: コンパイラ情報の完全表示
- **DW_AT_name**: 名前属性の特別表示

**実装関数**:
- `dwarf_tag_to_string()`: DWARFタグの人間可読変換
- `dwarf_at_to_string()`: DWARF属性の人間可読変換
- `dwarf_lang_to_string()`: 言語コードの変換
- `get_attribute_value_details()`: 属性値詳細取得

## 4. データ構造・実装詳細

### 4.1 主要関数

```rust
// DWARFタグ変換
fn dwarf_tag_to_string(tag: DwTag) -> &'static str

// DWARF属性変換
fn dwarf_at_to_string(attr: DwAt) -> &'static str

// DWARF言語コード変換
fn dwarf_lang_to_string(lang: DwLang) -> &'static str

// 属性値詳細取得
fn get_attribute_value_details(
    attr: &gimli::Attribute<gimli::EndianSlice<gimli::LittleEndian>>,
    dwarf: &gimli::Dwarf<gimli::EndianSlice<gimli::LittleEndian>>
) -> String

// .debug_str文字列抽出
fn extract_debug_str_strings(data: &[u8]) -> Vec<(usize, String)>

// .textセクション逆アセンブル
fn disassemble_text_section(data: &[u8], base_address: u64)
```

### 4.2 DWARFセクション管理

```rust
// DWARF構造体の初期化
let dwarf = Dwarf {
    debug_abbrev: debug_abbrev_slice.into(),
    debug_addr: EndianSlice::new(&[], endian).into(),
    debug_aranges: EndianSlice::new(&[], endian).into(),
    debug_info: debug_info_slice.into(),
    debug_line: debug_line_slice.into(),
    debug_line_str: debug_line_str_slice.into(),  // DWARF5対応
    debug_str: debug_str_slice.into(),
    debug_ranges: debug_ranges_slice.into(),
    // その他のセクション
};
```

## 5. 対応仕様・制約

### 5.1 対応アーキテクチャ

- **x86-64**: 完全対応（ELF解析・DWARF解析・逆アセンブル）
- **その他**: ELF解析・DWARF解析のみ対応

### 5.2 対応エンディアン

- **Little Endian**: 完全対応・テスト済み
- **Big Endian**: 基本対応（テスト不十分）

### 5.3 表示制限

- **逆アセンブル**: 最大100命令表示
- **その他**: 制限撤廃（全情報表示）

## 6. エラーハンドリング

### 6.1 文字列参照エラー

```rust
// 無効な文字列参照の処理
match dwarf.debug_str.get_str(offset) {
    Ok(s) => format!("String reference: \"{}\" (DW_FORM_strp)", s.to_string_lossy()),
    Err(_) => format!("String reference: <invalid@{:?}> (DW_FORM_strp)", offset),
}
```

### 6.2 セクション不存在エラー

```rust
// セクションが存在しない場合の処理
let debug_line_str = debug_sections.get(".debug_line_str").copied().unwrap_or(&[]);
```

### 6.3 コマンドライン引数エラー

```rust
// 引数不足時の処理
if args.len() != 2 {
    eprintln!("Usage: {} <elf_file>", args[0]);
    std::process::exit(1);
}
```

## 7. パフォーマンス・メモリ効率

### 7.1 メモリ効率化

- **EndianSlice**: ゼロコピー文字列処理
- **参照渡し**: 大きなデータのコピー回避
- **遅延読み込み**: セクションデータの必要時読み込み

### 7.2 出力制御

- **適切な省略**: 長い文字列の省略表示
- **制限設定**: 大量データの適切な制限

## 8. 今後の拡張予定

### 8.1 機能拡張

- [ ] コマンドライン引数の拡張（フィルタリング・出力制御）
- [ ] JSON/XML出力対応
- [ ] インタラクティブモード
- [ ] より多くのアーキテクチャ対応（ARM64等）

### 8.2 パフォーマンス改善

- [ ] 並列処理の導入
- [ ] キャッシュ機能の実装
- [ ] メモリ使用量の最適化

### 8.3 ユーザビリティ向上

- [ ] 詳細度レベル設定
- [ ] 出力フォーマット選択
- [ ] エラーメッセージの改善

## 9. テスト戦略

### 9.1 テストファイル

- **DWARF4ファイル**: 基本機能テスト
- **DWARF5ファイル**: 最新仕様テスト
- **各種言語**: C/C++/Rust等のテスト

### 9.2 テストケース

1. **基本機能テスト**: 各セクションの正常表示
2. **エラーハンドリングテスト**: 不正ファイル・破損データ
3. **パフォーマンステスト**: 大きなファイルでの動作確認
4. **互換性テスト**: 各DWARFバージョンでの動作確認

---

---

**文書バージョン**: 1.0  
**最終更新日**: 2025-08-03  
**作成者**: ELF/DWARF解析ツール開発チーム

### ユーザビリティ改善

- [ ] カラー出力対応
- [ ] 進捗表示機能
- [ ] 詳細度レベルの選択機能

---

**作成日**: 2025-08-03  
**バージョン**: 1.0  
**作成者**: ELF/DWARF解析ツール開発チーム
