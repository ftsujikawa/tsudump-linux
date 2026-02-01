use elf::{ElfBytes, endian::AnyEndian};
use gimli::{EndianSlice, LittleEndian, Reader, Dwarf, DwLang, DwTag, DwAt};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter};
use clap::{Parser, Subcommand};

// Helper function to get virtual base address from ELF file
fn get_virtual_base_address(file: &ElfBytes<AnyEndian>) -> u64 {
    // Try to get program headers
    if let Some(program_headers) = file.segments() {
        for phdr in program_headers.iter() {
            // Look for the first LOAD segment with executable permission
            if phdr.p_type == 1 && (phdr.p_flags & 1) != 0 { // PT_LOAD and PF_X
                return phdr.p_vaddr;
            }
        }
    }
    // Fallback: try to get entry point from ELF header
    file.ehdr.e_entry
}

// Provide concise details of a DWARF attribute for diagnostics
fn get_attribute_value_details(
    attr: &gimli::Attribute<EndianSlice<LittleEndian>>,
    _dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
    _base_address: u64,
) -> String {
    // Keep it simple yet informative; avoid heavy dereferencing
    format!(
        "name={:?}, raw={:?}",
        attr.name(),
        attr.value()
    )
}

fn dwarf_version_to_string(version: u16) -> &'static str {
    match version {
        1 => "DWARF1",
        2 => "DWARF2",
        3 => "DWARF3",
        4 => "DWARF4",
        5 => "DWARF5",
        _ => "Unknown DWARF Version",
    }
}

fn dwarf_version_features(version: u16) -> &'static str {
    match version {
        1 => "Basic debug info, limited type information",
        2 => "Enhanced type system, line number info, macro support",
        3 => "64-bit support, improved location expressions, namespaces",
        4 => "Call frame info, ranges, improved compression",
        5 => "Split DWARF, type units, improved performance",
        _ => "Unknown version features",
    }
}

fn dwarf_lang_to_string(lang: DwLang) -> &'static str {
    match lang {
        DwLang(0x0001) => "C89",
        DwLang(0x0002) => "C",
        DwLang(0x0003) => "Ada83",
        DwLang(0x0004) => "C++",
        DwLang(0x0005) => "Cobol74",
        DwLang(0x0006) => "Cobol85",
        DwLang(0x0007) => "Fortran77",
        DwLang(0x0008) => "Fortran90",
        DwLang(0x0009) => "Pascal83",
        DwLang(0x000a) => "Modula2",
        DwLang(0x000b) => "Java",
        DwLang(0x000c) => "C99",
        DwLang(0x000d) => "Ada95",
        DwLang(0x000e) => "Fortran95",
        DwLang(0x000f) => "PLI",
        DwLang(0x0010) => "ObjC",
        DwLang(0x0011) => "ObjC++",
        DwLang(0x0012) => "UPC",
        DwLang(0x0013) => "D",
        DwLang(0x0014) => "Python",
        DwLang(0x0015) => "OpenCL",
        DwLang(0x0016) => "Go",
        DwLang(0x0017) => "Modula3",
        DwLang(0x0018) => "Haskell",
        DwLang(0x0019) => "C++03",
        DwLang(0x001a) => "C++11",
        DwLang(0x001b) => "OCaml",
        DwLang(0x001c) => "Rust",
        DwLang(0x001d) => "C11",
        DwLang(0x001e) => "Swift",
        DwLang(0x001f) => "Julia",
        DwLang(0x0020) => "Dylan",
        DwLang(0x0021) => "C++14",
        DwLang(0x0022) => "Fortran03",
        DwLang(0x0023) => "Fortran08",
        DwLang(0x0024) => "RenderScript",
        DwLang(0x0025) => "BLISS",
        _ => "Unknown",
    }
}

fn dwarf_tag_to_string(tag: DwTag) -> &'static str {
    match tag {
        DwTag(0x01) => "DW_TAG_array_type",
        DwTag(0x02) => "DW_TAG_class_type",
        DwTag(0x03) => "DW_TAG_entry_point",
        DwTag(0x04) => "DW_TAG_enumeration_type",
        DwTag(0x05) => "DW_TAG_formal_parameter",
        DwTag(0x06) => "DW_TAG_imported_declaration",
        DwTag(0x07) => "DW_TAG_imported_declaration",
        DwTag(0x08) => "DW_TAG_imported_declaration",
        DwTag(0x09) => "DW_TAG_imported_declaration",
        DwTag(0x0a) => "DW_TAG_label",
        DwTag(0x0b) => "DW_TAG_lexical_block",
        DwTag(0x0c) => "DW_TAG_lexical_block",
        DwTag(0x0d) => "DW_TAG_member",
        DwTag(0x0e) => "DW_TAG_member",
        DwTag(0x0f) => "DW_TAG_pointer_type",
        DwTag(0x10) => "DW_TAG_reference_type",
        DwTag(0x11) => "DW_TAG_compile_unit",
        DwTag(0x12) => "DW_TAG_string_type",
        DwTag(0x13) => "DW_TAG_structure_type",
        DwTag(0x15) => "DW_TAG_subroutine_type",
        DwTag(0x16) => "DW_TAG_typedef",
        DwTag(0x17) => "DW_TAG_union_type",
        DwTag(0x18) => "DW_TAG_unspecified_parameters",
        DwTag(0x19) => "DW_TAG_variant",
        DwTag(0x1a) => "DW_TAG_common_block",
        DwTag(0x1b) => "DW_TAG_common_inclusion",
        DwTag(0x1c) => "DW_TAG_inheritance",
        DwTag(0x1d) => "DW_TAG_inlined_subroutine",
        DwTag(0x1e) => "DW_TAG_module",
        DwTag(0x1f) => "DW_TAG_ptr_to_member_type",
        DwTag(0x20) => "DW_TAG_set_type",
        DwTag(0x21) => "DW_TAG_subrange_type",
        DwTag(0x22) => "DW_TAG_with_stmt",
        DwTag(0x23) => "DW_TAG_access_declaration",
        DwTag(0x24) => "DW_TAG_base_type",
        DwTag(0x25) => "DW_TAG_catch_block",
        DwTag(0x26) => "DW_TAG_const_type",
        DwTag(0x27) => "DW_TAG_constant",
        DwTag(0x28) => "DW_TAG_enumerator",
        DwTag(0x29) => "DW_TAG_file_type",
        DwTag(0x2a) => "DW_TAG_friend",
        DwTag(0x2b) => "DW_TAG_namelist",
        DwTag(0x2c) => "DW_TAG_namelist_item",
        DwTag(0x2d) => "DW_TAG_packed_type",
        DwTag(0x2e) => "DW_TAG_subprogram",
        DwTag(0x2f) => "DW_TAG_template_type_parameter",
        DwTag(0x30) => "DW_TAG_template_value_parameter",
        DwTag(0x31) => "DW_TAG_thrown_type",
        DwTag(0x32) => "DW_TAG_try_block",
        DwTag(0x33) => "DW_TAG_variant_part",
        DwTag(0x34) => "DW_TAG_variable",
        DwTag(0x35) => "DW_TAG_volatile_type",
        DwTag(0x36) => "DW_TAG_dwarf_procedure",
        DwTag(0x37) => "DW_TAG_restrict_type",
        DwTag(0x38) => "DW_TAG_interface_type",
        DwTag(0x39) => "DW_TAG_namespace",
        DwTag(0x3a) => "DW_TAG_imported_module",
        DwTag(0x3b) => "DW_TAG_unspecified_type",
        DwTag(0x3c) => "DW_TAG_partial_unit",
        DwTag(0x3d) => "DW_TAG_imported_unit",
        DwTag(0x3f) => "DW_TAG_condition",
        DwTag(0x40) => "DW_TAG_shared_type",
        DwTag(0x41) => "DW_TAG_type_unit",
        DwTag(0x42) => "DW_TAG_rvalue_reference_type",
        DwTag(0x43) => "DW_TAG_template_alias",
        _ => "DW_TAG_unknown",
    }
}

fn dwarf_at_to_string(at: DwAt) -> &'static str {
    match at {
        DwAt(0x01) => "DW_AT_sibling",
        DwAt(0x02) => "DW_AT_location",
        DwAt(0x03) => "DW_AT_name",
        DwAt(0x09) => "DW_AT_ordering",
        DwAt(0x0b) => "DW_AT_byte_size",
        DwAt(0x0c) => "DW_AT_bit_offset",
        DwAt(0x0d) => "DW_AT_bit_size",
        DwAt(0x10) => "DW_AT_stmt_list",
        DwAt(0x11) => "DW_AT_low_pc",
        DwAt(0x12) => "DW_AT_high_pc",
        DwAt(0x13) => "DW_AT_language",
        DwAt(0x15) => "DW_AT_discr",
        DwAt(0x16) => "DW_AT_discr_value",
        DwAt(0x17) => "DW_AT_visibility",
        DwAt(0x18) => "DW_AT_import",
        DwAt(0x19) => "DW_AT_string_length",
        DwAt(0x1a) => "DW_AT_common_reference",
        DwAt(0x1b) => "DW_AT_comp_dir",
        DwAt(0x1c) => "DW_AT_const_value",
        DwAt(0x1d) => "DW_AT_containing_type",
        DwAt(0x1e) => "DW_AT_default_value",
        DwAt(0x20) => "DW_AT_inline",
        DwAt(0x21) => "DW_AT_is_optional",
        DwAt(0x22) => "DW_AT_lower_bound",
        DwAt(0x25) => "DW_AT_producer",
        DwAt(0x27) => "DW_AT_prototyped",
        DwAt(0x28) => "DW_AT_return_addr",
        DwAt(0x2a) => "DW_AT_start_scope",
        DwAt(0x2c) => "DW_AT_bit_stride",
        DwAt(0x2e) => "DW_AT_upper_bound",
        DwAt(0x2f) => "DW_AT_abstract_origin",
        DwAt(0x30) => "DW_AT_accessibility",
        DwAt(0x31) => "DW_AT_address_class",
        DwAt(0x32) => "DW_AT_artificial",
        DwAt(0x33) => "DW_TAG_base_types",
        DwAt(0x34) => "DW_AT_calling_convention",
        DwAt(0x35) => "DW_AT_count",
        DwAt(0x36) => "DW_AT_data_member_location",
        DwAt(0x37) => "DW_AT_decl_column",
        DwAt(0x38) => "DW_AT_decl_file",
        DwAt(0x39) => "DW_AT_decl_line",
        DwAt(0x3a) => "DW_AT_declaration",
        DwAt(0x3b) => "DW_AT_discr_list",
        DwAt(0x3c) => "DW_AT_encoding",
        DwAt(0x3d) => "DW_AT_external",
        DwAt(0x3e) => "DW_AT_frame_base",
        DwAt(0x3f) => "DW_AT_friend",
        DwAt(0x40) => "DW_AT_identifier_case",
        DwAt(0x41) => "DW_AT_macro_info",
        DwAt(0x42) => "DW_AT_namelist_item",
        DwAt(0x43) => "DW_AT_priority",
        DwAt(0x44) => "DW_AT_segment",
        DwAt(0x45) => "DW_AT_specification",
        DwAt(0x46) => "DW_AT_static_link",
        DwAt(0x47) => "DW_AT_type",
        DwAt(0x48) => "DW_AT_use_location",
        DwAt(0x49) => "DW_AT_variable_parameter",
        DwAt(0x4a) => "DW_AT_virtuality",
        DwAt(0x4b) => "DW_AT_vtable_elem_location",
        DwAt(0x4c) => "DW_AT_allocated",
        DwAt(0x4d) => "DW_AT_associated",
        DwAt(0x4e) => "DW_AT_data_location",
        DwAt(0x4f) => "DW_AT_byte_stride",
        DwAt(0x50) => "DW_AT_entry_pc",
        DwAt(0x51) => "DW_AT_use_UTF8",
        DwAt(0x52) => "DW_AT_extension",
        DwAt(0x53) => "DW_AT_ranges",
        DwAt(0x54) => "DW_AT_trampoline",
        DwAt(0x55) => "DW_AT_call_column",
        DwAt(0x56) => "DW_AT_call_file",
        DwAt(0x57) => "DW_AT_call_line",
        DwAt(0x58) => "DW_AT_description",
        DwAt(0x59) => "DW_AT_binary_scale",
        DwAt(0x5a) => "DW_AT_decimal_scale",
        DwAt(0x5b) => "DW_AT_small",
        DwAt(0x5c) => "DW_AT_decimal_sign",
        DwAt(0x5d) => "DW_AT_digit_count",
        DwAt(0x5e) => "DW_AT_picture_string",
        DwAt(0x5f) => "DW_AT_mutable",
        DwAt(0x60) => "DW_AT_threads_scaled",
        DwAt(0x61) => "DW_AT_explicit",
        DwAt(0x62) => "DW_AT_object_pointer",
        DwAt(0x63) => "DW_AT_endianity",
        DwAt(0x64) => "DW_AT_elemental",
        DwAt(0x65) => "DW_AT_pure",
        DwAt(0x66) => "DW_AT_recursive",
        DwAt(0x67) => "DW_AT_signature",
        DwAt(0x68) => "DW_AT_main_subprogram",
        DwAt(0x69) => "DW_AT_data_bit_offset",
        DwAt(0x6a) => "DW_AT_const_expr",
        DwAt(0x6b) => "DW_AT_enum_class",
        DwAt(0x6c) => "DW_AT_linkage_name",
        _ => "DW_AT_unknown",
    }
}

struct SymbolEntry {
    start: u64,
    size: u64,
    name: String,
}

type SymbolMap = Vec<SymbolEntry>;

fn build_symbol_map(file: &ElfBytes<AnyEndian>) -> SymbolMap {
    let mut symbols = Vec::new();

    // Collect from both regular and dynamic symbol tables if present
    for (sym_section, str_section) in [(".symtab", ".strtab"), (".dynsym", ".dynstr")] {
        let sym_shdr = match file.section_header_by_name(sym_section) {
            Ok(Some(shdr)) => shdr,
            _ => continue,
        };

        let str_shdr = match file.section_header_by_name(str_section) {
            Ok(Some(shdr)) => shdr,
            _ => continue,
        };

        let (sym_data, _) = match file.section_data(&sym_shdr) {
            Ok(data) => data,
            Err(_) => continue,
        };

        let (str_data, _) = match file.section_data(&str_shdr) {
            Ok(data) => data,
            Err(_) => continue,
        };

        let symbol_size = 24; // 64-bit ELF symbol size
        let num_symbols = if sym_shdr.sh_entsize > 0 {
            sym_shdr.sh_size / sym_shdr.sh_entsize
        } else {
            0
        };

        for i in 0..num_symbols {
            let offset = (i * symbol_size) as usize;
            if offset + symbol_size as usize > sym_data.len() {
                break;
            }

            let name_offset = u32::from_le_bytes([
                sym_data[offset],
                sym_data[offset + 1],
                sym_data[offset + 2],
                sym_data[offset + 3],
            ]);

            let info = sym_data[offset + 4];

            let value = u64::from_le_bytes([
                sym_data[offset + 8],
                sym_data[offset + 9],
                sym_data[offset + 10],
                sym_data[offset + 11],
                sym_data[offset + 12],
                sym_data[offset + 13],
                sym_data[offset + 14],
                sym_data[offset + 15],
            ]);

            let size = u64::from_le_bytes([
                sym_data[offset + 16],
                sym_data[offset + 17],
                sym_data[offset + 18],
                sym_data[offset + 19],
                sym_data[offset + 20],
                sym_data[offset + 21],
                sym_data[offset + 22],
                sym_data[offset + 23],
            ]);

            // Only keep function symbols
            let sym_type = info & 0xf;
            if sym_type != 2 {
                continue;
            }

            if (name_offset as usize) >= str_data.len() {
                continue;
            }

            let name_start = name_offset as usize;
            let name_end = str_data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|pos| name_start + pos)
                .unwrap_or(str_data.len());

            let name = match std::str::from_utf8(&str_data[name_start..name_end]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            // Store symbol value directly (ELF VMA), to match objdump -d
            symbols.push(SymbolEntry { start: value, size, name });
        }
    }

    symbols
}

fn find_symbol_name_and_offset<'a>(symbols: &'a SymbolMap, addr: u64) -> Option<(&'a str, u64)> {
    for sym in symbols {
        let end = if sym.size > 0 { sym.start.saturating_add(sym.size) } else { sym.start.saturating_add(1) };
        if addr >= sym.start && addr < end {
            let offset = addr.saturating_sub(sym.start);
            return Some((sym.name.as_str(), offset));
        }
    }
    None
}

fn dump_text_section(file: &ElfBytes<AnyEndian>, symbols: &SymbolMap) {
    // Find .text section
    let text_shdr = match file.section_header_by_name(".text") {
        Ok(Some(shdr)) => shdr,
        Ok(None) => {
            println!(".text section not found");
            return;
        }
        Err(e) => {
            println!("Error finding .text section: {}", e);
            return;
        }
    };

    // Get section data
    let text_data = match file.section_data(&text_shdr) {
        Ok((data, _)) => data,
        Err(e) => {
            println!("Error reading .text section data: {}", e);
            return;
        }
    };

    println!("Section: .text");
    println!("Address: 0x{:x}", text_shdr.sh_addr);
    println!("Offset: 0x{:x}", text_shdr.sh_offset);
    println!("Size: {} bytes (0x{:x})", text_shdr.sh_size, text_shdr.sh_size);
    println!();

    // Display all bytes
    let dump_size = text_data.len();
    println!("Dumping first {} bytes:", dump_size);
    
    for (i, chunk) in text_data[..dump_size].chunks(16).enumerate() {
        // Print offset (ELF virtual address from section header)
        print!("{:08x}: ", text_shdr.sh_addr + (i * 16) as u64);
        
        // Print hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" "); // Extra space after 8 bytes
            }
        }
        
        // Pad if less than 16 bytes
        for _ in chunk.len()..16 {
            print!("   ");
            if chunk.len() <= 8 {
                print!(" ");
            }
        }
        
        // Print ASCII representation
        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    
    // Add disassembly section, using section VMA as base IP (matches objdump -d)
    disassemble_text_section(&text_data, text_shdr.sh_addr, symbols);
}

fn dump_other_executable_sections(file: &ElfBytes<AnyEndian>, symbols: &SymbolMap) {
    let section_headers = match file.section_headers() {
        Some(h) => h,
        None => return,
    };

    let string_table = match file.section_headers_with_strtab() {
        Ok((_, strtab)) => strtab,
        Err(_) => return,
    };

    for sh in section_headers.iter() {
        // Skip non-executable sections
        if sh.sh_flags & 0x4 == 0 { // SHF_EXECINSTR
            continue;
        }

        let name = match string_table {
            Some(ref strtab) => strtab.get(sh.sh_name as usize).unwrap_or("<invalid>"),
            None => "<no-strtab>",
        };

        // .text は既に別途処理しているのでスキップ
        if name == ".text" {
            continue;
        }

        let (data, _) = match file.section_data(&sh) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if data.is_empty() {
            continue;
        }

        println!();
        println!("=== {} Section Disassembly ===", name);

        disassemble_text_section(data, sh.sh_addr, symbols);
    }
}

fn disassemble_text_section(code: &[u8], base_address: u64, symbols: &SymbolMap) {
    println!();
    println!("=== Section Disassembly (base 0x{:x}) ===", base_address);
    
    // Create decoder for x86-64
    let mut decoder = Decoder::with_ip(64, code, base_address, DecoderOptions::NONE);
    
    // Create formatter for NASM syntax
    let mut formatter = NasmFormatter::new();
    
    // Output buffer for formatted instruction
    let mut output = String::new();
    
    // Instruction object
    let mut instruction = Instruction::default();
    
    let mut instruction_count = 0;
    const MAX_INSTRUCTIONS: usize = 100; // Limit to avoid overwhelming output
    
    println!("Address          Bytes                    Assembly");
    println!("----------------------------------------------------------------");
    
    while decoder.can_decode() && instruction_count < MAX_INSTRUCTIONS {
        decoder.decode_out(&mut instruction);
        
        // Clear output buffer
        output.clear();
        
        // Format the instruction
        formatter.format(&instruction, &mut output);
        
        // Get instruction bytes
        let start_index = (instruction.ip() - base_address) as usize;
        let end_index = start_index + instruction.len();
        
        // Print address
        print!("{:016x}  ", instruction.ip());
        
        // Print instruction bytes (up to 8 bytes, padded)
        let mut bytes_str = String::new();
        if end_index <= code.len() {
            for i in start_index..end_index {
                bytes_str.push_str(&format!("{:02x} ", code[i]));
            }
        }
        print!("{:<24} ", bytes_str);

        // Try to resolve target symbol for near call/jmp/je/jne instructions
        let mut symbol_suffix = String::new();
        let mut branch_target: Option<u64> = None;
        match instruction.mnemonic() {
            Mnemonic::Call | Mnemonic::Jmp => {
                if instruction.is_call_near() || instruction.is_jmp_near() {
                    let target = instruction.near_branch_target();
                    branch_target = Some(target);
                    if let Some((name, offset)) = find_symbol_name_and_offset(symbols, target) {
                        symbol_suffix = if offset == 0 {
                            format!(" ; {}", name)
                        } else {
                            format!(" ; {}+0x{:x}", name, offset)
                        };
                    }
                }
            }
            Mnemonic::Je | Mnemonic::Jne => {
                // Conditional near branches (JE/JNE)
                if instruction.is_jcc_short_or_near() {
                    let target = instruction.near_branch_target();
                    branch_target = Some(target);
                    if let Some((name, offset)) = find_symbol_name_and_offset(symbols, target) {
                        symbol_suffix = if offset == 0 {
                            format!(" ; {}", name)
                        } else {
                            format!(" ; {}+0x{:x}", name, offset)
                        };
                    }
                }
            }
            _ => {}
        }

        // Fallback: if no function symbol, still show label-like name within .text
        if symbol_suffix.is_empty() {
            if let Some(target) = branch_target {
                let text_start = base_address;
                let text_end = base_address.saturating_add(code.len() as u64);
                if target >= text_start && target < text_end {
                    let off = target.saturating_sub(text_start);
                    symbol_suffix = format!(" ; .text+0x{:x}", off);
                }
            }
        }

        // Print disassembled instruction with optional symbol name
        println!("{}{}", output, symbol_suffix);
        
        instruction_count += 1;
    }
    
    if decoder.can_decode() {
        println!("... ({} more instructions not shown)", 
                 code.len() / 2); // Rough estimate
    }
    
    println!("Total instructions shown: {}", instruction_count);
}

fn dump_data_section(file: &ElfBytes<AnyEndian>) {
    // Find .data section
    let data_shdr = match file.section_header_by_name(".data") {
        Ok(Some(shdr)) => shdr,
        Ok(None) => {
            println!(".data section not found");
            return;
        }
        Err(e) => {
            println!("Error finding .data section: {}", e);
            return;
        }
    };

    // Get section data
    let data_data = match file.section_data(&data_shdr) {
        Ok((data, _)) => data,
        Err(e) => {
            println!("Error reading .data section data: {}", e);
            return;
        }
    };

    println!("Section: .data");
    println!("Address: 0x{:x}", data_shdr.sh_addr);
    println!("Offset: 0x{:x}", data_shdr.sh_offset);
    println!("Size: {} bytes (0x{:x})", data_shdr.sh_size, data_shdr.sh_size);
    println!("Type: {}", match data_shdr.sh_type {
        1 => "SHT_PROGBITS",
        2 => "SHT_SYMTAB",
        3 => "SHT_STRTAB",
        4 => "SHT_RELA",
        5 => "SHT_HASH",
        6 => "SHT_DYNAMIC",
        7 => "SHT_NOTE",
        8 => "SHT_NOBITS",
        9 => "SHT_REL",
        _ => "Other"
    });
    println!();

    // Display all bytes
    let dump_size = data_data.len();
    println!("Dumping first {} bytes:", dump_size);
    
    for (i, chunk) in data_data[..dump_size].chunks(16).enumerate() {
        print!("{:08x}: ", data_shdr.sh_addr + (i * 16) as u64);
        
        // Print hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{:02x} ", byte);
        }
        
        // Pad if chunk is less than 16 bytes
        for j in chunk.len()..16 {
            if j == 8 {
                print!(" ");
            }
            print!("   ");
        }
        
        // Print ASCII representation
        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

fn dump_symbol_section(file: &ElfBytes<AnyEndian>) {
    // Try to dump .symtab first
    println!("=== .symtab Section Dump ===");
    dump_symbol_table(file, ".symtab", ".strtab");
    
    println!();
    
    // Then try to dump .dynsym
    println!("=== .dynsym Section Dump ===");
    dump_symbol_table(file, ".dynsym", ".dynstr");
}

fn dump_symbol_table(file: &ElfBytes<AnyEndian>, sym_section: &str, str_section: &str) {
    // Find symbol table section
    let sym_shdr = match file.section_header_by_name(sym_section) {
        Ok(Some(shdr)) => shdr,
        Ok(None) => {
            println!("{} section not found", sym_section);
            return;
        }
        Err(e) => {
            println!("Error finding {} section: {}", sym_section, e);
            return;
        }
    };

    // Find string table section
    let str_shdr = match file.section_header_by_name(str_section) {
        Ok(Some(shdr)) => shdr,
        Ok(None) => {
            println!("{} section not found", str_section);
            return;
        }
        Err(e) => {
            println!("Error finding {} section: {}", str_section, e);
            return;
        }
    };

    // Get symbol table data
    let (sym_data, _) = match file.section_data(&sym_shdr) {
        Ok(data) => data,
        Err(e) => {
            println!("Error reading {} section data: {}", sym_section, e);
            return;
        }
    };

    // Get string table data
    let (str_data, _) = match file.section_data(&str_shdr) {
        Ok(data) => data,
        Err(e) => {
            println!("Error reading {} section data: {}", str_section, e);
            return;
        }
    };

    println!("Section: {}", sym_section);
    println!("Address: 0x{:x}", sym_shdr.sh_addr);
    println!("Offset: 0x{:x}", sym_shdr.sh_offset);
    println!("Size: {} bytes (0x{:x})", sym_shdr.sh_size, sym_shdr.sh_size);
    println!("Entry size: {} bytes", sym_shdr.sh_entsize);
    
    let num_symbols = if sym_shdr.sh_entsize > 0 {
        sym_shdr.sh_size / sym_shdr.sh_entsize
    } else {
        0
    };
    println!("Number of symbols: {}", num_symbols);
    println!();

    // Parse symbols (assuming 64-bit ELF)
    let symbol_size = 24; // 64-bit ELF symbol size
    println!("#    Value            Size     Type     Bind     Vis      Name");
    println!("--------------------------------------------------------------------------------");
    
    for i in 0..num_symbols {
        let offset = (i * symbol_size) as usize;
        if offset + symbol_size as usize > sym_data.len() {
            break;
        }
        
        // Parse symbol entry (64-bit ELF format)
        let name_offset = u32::from_le_bytes([
            sym_data[offset], sym_data[offset + 1], 
            sym_data[offset + 2], sym_data[offset + 3]
        ]);
        
        let info = sym_data[offset + 4];
        let other = sym_data[offset + 5];
        
        let value = u64::from_le_bytes([
            sym_data[offset + 8], sym_data[offset + 9],
            sym_data[offset + 10], sym_data[offset + 11],
            sym_data[offset + 12], sym_data[offset + 13],
            sym_data[offset + 14], sym_data[offset + 15]
        ]);
        
        let size = u64::from_le_bytes([
            sym_data[offset + 16], sym_data[offset + 17],
            sym_data[offset + 18], sym_data[offset + 19],
            sym_data[offset + 20], sym_data[offset + 21],
            sym_data[offset + 22], sym_data[offset + 23]
        ]);
        
        // Extract symbol name from string table
        let name = if (name_offset as usize) < str_data.len() {
            let name_start = name_offset as usize;
            let name_end = str_data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|pos| name_start + pos)
                .unwrap_or(str_data.len());
            
            std::str::from_utf8(&str_data[name_start..name_end])
                .unwrap_or("<invalid>")
        } else {
            "<invalid>"
        };
        
        let sym_type = match info & 0xf {
            0 => "NOTYPE",
            1 => "OBJECT",
            2 => "FUNC",
            3 => "SECTION",
            4 => "FILE",
            _ => "OTHER"
        };
        
        let bind = match info >> 4 {
            0 => "LOCAL",
            1 => "GLOBAL",
            2 => "WEAK",
            _ => "OTHER"
        };
        
        let visibility = match other & 0x3 {
            0 => "DEFAULT",
            1 => "INTERNAL",
            2 => "HIDDEN",
            3 => "PROTECTED",
            _ => "OTHER"
        };
        
        println!("{:<4} {:<16x} {:<8} {:<8} {:<8} {:<8} {}", 
                 i, value, size, sym_type, bind, visibility, name);
    }
    

}

fn dump_line_section(file: &ElfBytes<AnyEndian>) {
    // Find .line section (DWARF line number information)
    let line_shdr = match file.section_header_by_name(".line") {
        Ok(Some(shdr)) => shdr,
        Ok(None) => {
            println!(".line section not found");
            return;
        }
        Err(e) => {
            println!("Error finding .line section: {}", e);
            return;
        }
    };

    // Get section data
    let line_data = match file.section_data(&line_shdr) {
        Ok((data, _)) => data,
        Err(e) => {
            println!("Error reading .line section data: {}", e);
            return;
        }
    };

    println!("Section: .line");
    println!("Address: 0x{:x}", line_shdr.sh_addr);
    println!("Offset: 0x{:x}", line_shdr.sh_offset);
    println!("Size: {} bytes (0x{:x})", line_shdr.sh_size, line_shdr.sh_size);
    println!("Type: {}", match line_shdr.sh_type {
        1 => "SHT_PROGBITS",
        2 => "SHT_SYMTAB",
        3 => "SHT_STRTAB",
        4 => "SHT_RELA",
        5 => "SHT_HASH",
        6 => "SHT_DYNAMIC",
        7 => "SHT_NOTE",
        8 => "SHT_NOBITS",
        9 => "SHT_REL",
        _ => "Other"
    });
    println!();

    // Display all bytes
    let dump_size = line_data.len();
    println!("Dumping first {} bytes:", dump_size);
    
    for (i, chunk) in line_data[..dump_size].chunks(16).enumerate() {
        // Print offset
        print!("{:08x}: ", line_shdr.sh_offset + (i * 16) as u64);
        
        // Print hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" "); // Extra space after 8 bytes
            }
        }
        
        // Pad if less than 16 bytes
        for _ in chunk.len()..16 {
            print!("   ");
            if chunk.len() <= 8 {
                print!(" ");
            }
        }
        
        // Print ASCII representation
        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    
    // Try to parse DWARF line number information if present
    if line_data.len() >= 4 {
        println!();
        println!("DWARF Line Number Information (first few bytes):");
        
        // Read the unit length (first 4 bytes)
        let unit_length = u32::from_le_bytes([
            line_data[0], line_data[1], line_data[2], line_data[3]
        ]);
        println!("Unit Length: {} (0x{:x})", unit_length, unit_length);
        
        if line_data.len() >= 6 {
            // Read the version (next 2 bytes)
            let version = u16::from_le_bytes([line_data[4], line_data[5]]);
            println!("DWARF Version: {}", version);
        }
        
        if line_data.len() >= 10 {
            // Read the header length (next 4 bytes)
            let header_length = u32::from_le_bytes([
                line_data[6], line_data[7], line_data[8], line_data[9]
            ]);
            println!("Header Length: {} (0x{:x})", header_length, header_length);
        }
    }
}

fn dump_section_headers(file: &ElfBytes<AnyEndian>) {
    println!("\n=== Section Headers ===");
    println!("{:>3} {:>16} {:>10} {:>16} {:>16} {:>8} {:>8} {:>8} {:>8} {:>8} {}",
             "#", "Name", "Type", "Address", "Offset", "Size", "EntSize", "Flags", "Link", "Info", "Align");
    println!("{}", "-".repeat(120));
    
    let _section_headers = match file.section_headers() {
        Some(headers) => headers,
        None => {
            println!("No section headers found");
            return;
        }
    };
    
    let string_table = match file.section_headers_with_strtab() {
        Ok((_, strtab)) => strtab,
        Err(_) => {
            println!("Could not read string table");
            return;
        }
    };
    
    for (i, section_header) in _section_headers.iter().enumerate() {
        let section_name = match string_table {
            Some(ref strtab) => {
                strtab.get(section_header.sh_name as usize)
                    .unwrap_or("<invalid>")
            },
            None => "<no-strtab>"
        };
        
        let section_type = match section_header.sh_type {
            0 => "NULL",
            1 => "PROGBITS",
            2 => "SYMTAB",
            3 => "STRTAB",
            4 => "RELA",
            5 => "HASH",
            6 => "DYNAMIC",
            7 => "NOTE",
            8 => "NOBITS",
            9 => "REL",
            10 => "SHLIB",
            11 => "DYNSYM",
            14 => "INIT_ARRAY",
            15 => "FINI_ARRAY",
            16 => "PREINIT_ARRAY",
            17 => "GROUP",
            18 => "SYMTAB_SHNDX",
            0x6ffffff6 => "GNU_HASH",
            0x6ffffffe => "VERNEED",
            0x6fffffff => "VERSYM",
            _ => "UNKNOWN"
        };
        
        let flags_str = {
            let mut flags = Vec::new();
            if section_header.sh_flags & 0x1 != 0 { flags.push("W"); }  // SHF_WRITE
            if section_header.sh_flags & 0x2 != 0 { flags.push("A"); }  // SHF_ALLOC
            if section_header.sh_flags & 0x4 != 0 { flags.push("X"); }  // SHF_EXECINSTR
            if section_header.sh_flags & 0x10 != 0 { flags.push("M"); } // SHF_MERGE
            if section_header.sh_flags & 0x20 != 0 { flags.push("S"); } // SHF_STRINGS
            if flags.is_empty() { "-".to_string() } else { flags.join("") }
        };
        
        println!("{:>3} {:>16} {:>10} {:>16x} {:>16x} {:>8x} {:>8x} {:>8} {:>8} {:>8} {:>8x}",
                 i,
                 section_name,
                 section_type,
                 section_header.sh_addr,
                 section_header.sh_offset,
                 section_header.sh_size,
                 section_header.sh_entsize,
                 flags_str,
                 section_header.sh_link,
                 section_header.sh_info,
                 section_header.sh_addralign);
    }
}

fn dump_debug_sections(file: &ElfBytes<AnyEndian>) {
    println!("\n=== Debug Sections ===");
    
    let _section_headers = match file.section_headers() {
        Some(headers) => headers,
        None => {
            println!("No section headers found");
            return;
        }
    };
    
    let string_table = match file.section_headers_with_strtab() {
        Ok((_, strtab)) => strtab,
        Err(_) => {
            println!("Could not read string table");
            return;
        }
    };
    
    let mut debug_sections = Vec::new();
    
    // Find all debug sections
    for (i, section_header) in _section_headers.iter().enumerate() {
        let section_name = match string_table {
            Some(ref strtab) => {
                strtab.get(section_header.sh_name as usize)
                    .unwrap_or("<invalid>")
            },
            None => "<no-strtab>"
        };
        
        if section_name.starts_with(".debug") {
            debug_sections.push((i, section_name, section_header));
        }
    }
    
    if debug_sections.is_empty() {
        println!("No debug sections found");
        return;
    }
    
    println!("Found {} debug sections:", debug_sections.len());
    println!("{:>3} {:>20} {:>16} {:>16} {:>10} {}",
             "#", "Name", "Address", "Offset", "Size", "Description");
    println!("{}", "-".repeat(80));
    
    for (i, section_name, section_header) in &debug_sections {
        let description = match *section_name {
            ".debug_info" => "Debug information entries",
            ".debug_abbrev" => "Abbreviations used by debug info",
            ".debug_line" => "Line number information",
            ".debug_str" => "String table for debug info",
            ".debug_loc" => "Location lists",
            ".debug_ranges" => "Address ranges",
            ".debug_frame" => "Call frame information",
            ".debug_aranges" => "Address range table",
            ".debug_pubnames" => "Public names",
            ".debug_pubtypes" => "Public types",
            ".debug_macinfo" => "Macro information",
            ".debug_macro" => "Macro information (DWARF 5)",
            _ => "Unknown debug section"
        };
        
        println!("{:>3} {:>20} {:>16x} {:>16x} {:>10x} {}", 
                 i, section_name, section_header.sh_addr, section_header.sh_offset, section_header.sh_size, description);
    }
    
    // Show detailed content for some debug sections
    for (_i, section_name, section_header) in &debug_sections {
        if *section_name == ".debug_str" {
            extract_debug_str_strings(file, section_header);
        } else if *section_name == ".debug_info" || *section_name == ".debug_line" {
            println!("\n--- {} Content (all bytes) ---", section_name);
            
            let section_data = match file.section_data(section_header) {
                Ok((data, _)) => data,
                Err(e) => {
                    println!("Error reading section {}: {}", section_name, e);
                    continue;
                }
            };
            
            let bytes_to_show = section_data.len();
            let offset = section_header.sh_offset;
            
            for (i, chunk) in section_data[..bytes_to_show].chunks(16).enumerate() {
                print!("{:08x}: ", offset + (i * 16) as u64);
                
                // Print hex bytes
                for (j, byte) in chunk.iter().enumerate() {
                    if j == 8 {
                        print!(" ");
                    }
                    print!("{:02x} ", byte);
                }
                
                // Pad if chunk is less than 16 bytes
                for j in chunk.len()..16 {
                    if j == 8 {
                        print!(" ");
                    }
                    print!("   ");
                }
                
                // Print ASCII representation
                print!(" |");
                for byte in chunk {
                    if *byte >= 32 && *byte <= 126 {
                        print!("{}", *byte as char);
                    } else {
                        print!(".");
                    }
                }
                println!("|")
            }
            

        }
    }
}

fn extract_debug_str_strings(file: &ElfBytes<AnyEndian>, section_header: &elf::section::SectionHeader) {
    println!("\n--- .debug_str String Extraction ---");
    
    let section_data = match file.section_data(section_header) {
        Ok((data, _)) => data,
        Err(e) => {
            println!("Error reading .debug_str section: {}", e);
            return;
        }
    };
    
    println!("Section size: {} bytes (0x{:x})", section_data.len(), section_data.len());
    println!("Section offset: 0x{:x}", section_header.sh_offset);
    println!();
    
    // Hexadecimal dump
    println!("--- Hex Dump ---");
    for (i, byte) in section_data.iter().enumerate() {
        if i % 16 == 0 {
            if i != 0 {
                print!(" | ");
                for j in i-16..i {
                    let b = section_data[j];
                    if b.is_ascii_graphic() || b == b' ' {
                        print!("{}", b as char);
                    } else {
                        print!(".");
                    }
                }
                println!("|");
            }
            print!("0x{:08x}: ", i);
        }
        print!("{:02x} ", byte);
    }
    let remainder = section_data.len() % 16;
    if remainder != 0 {
        for _ in remainder..16 {
            print!("   ");
        }
        print!(" | ");
        for j in section_data.len()-remainder..section_data.len() {
            let b = section_data[j];
            if b.is_ascii_graphic() || b == b' ' {
                print!("{}", b as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    println!();

    // Extract null-terminated strings
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut offset = 0;
    
    for (i, &byte) in section_data.iter().enumerate() {
        if byte == 0 {
            // End of string found
            if !current_string.is_empty() {
                let string = String::from_utf8_lossy(&current_string).to_string();
                strings.push((offset, string));
                current_string.clear();
            }
            offset = i + 1;
        } else {
            if current_string.is_empty() {
                offset = i;
            }
            current_string.push(byte);
        }
    }
    
    // Handle case where last string doesn't end with null
    if !current_string.is_empty() {
        let string = String::from_utf8_lossy(&current_string).to_string();
        strings.push((offset, string));
    }
    
    println!("Found {} strings:", strings.len());
    println!("{:<8} {:<8} {}", "Offset", "Length", "String Content");
    println!("{}", "-".repeat(80));
    
    for (offset, string) in &strings {
        // Limit string display length for readability
        let display_string = if string.len() > 60 {
            format!("{}...", &string[..57])
        } else {
            string.clone()
        };
        
        println!("{:<8x} {:<8} \"{}\"", offset, string.len(), display_string);
    }
    
    println!();
    println!("String statistics:");
    println!("  Total strings: {}", strings.len());
    println!("  Average length: {:.1} characters", 
             strings.iter().map(|(_, s)| s.len()).sum::<usize>() as f64 / strings.len() as f64);
    println!("  Longest string: {} characters", 
             strings.iter().map(|(_, s)| s.len()).max().unwrap_or(0));
    println!("  Shortest string: {} characters", 
             strings.iter().map(|(_, s)| s.len()).min().unwrap_or(0));
    
    // Show some example strings by category
    println!();
    println!("String categories:");
    
    let mut compiler_strings = Vec::new();
    let mut file_path_strings = Vec::new();
    let mut type_strings = Vec::new();
    let mut other_strings = Vec::new();
    
    for (offset, string) in &strings {
        if string.contains("gcc") || string.contains("clang") || string.contains("GNU") || string.contains("LLVM") {
            compiler_strings.push((offset, string));
        } else if string.contains("/") && (string.ends_with(".c") || string.ends_with(".h") || string.ends_with(".cpp")) {
            file_path_strings.push((offset, string));
        } else if string == "int" || string == "char" || string == "void" || string == "long" || string.contains("unsigned") {
            type_strings.push((offset, string));
        } else {
            other_strings.push((offset, string));
        }
    }
    
    if !compiler_strings.is_empty() {
        println!("  Compiler info ({} strings):", compiler_strings.len());
        for (offset, string) in compiler_strings.iter().take(3) {
            let display = if string.len() > 50 { format!("{}...", &string[..47]) } else { string.to_string() };
            println!("    0x{:x}: \"{}\"", offset, display);
        }
    }
    
    if !file_path_strings.is_empty() {
        println!("  File paths ({} strings):", file_path_strings.len());
        for (offset, string) in file_path_strings.iter().take(3) {
            println!("    0x{:x}: \"{}\"", offset, string);
        }
    }
    
    if !type_strings.is_empty() {
        println!("  Type names ({} strings):", type_strings.len());
        for (offset, string) in type_strings.iter().take(5) {
            println!("    0x{:x}: \"{}\"", offset, string);
        }
    }
    
    if !other_strings.is_empty() {
        println!("  Other strings ({} strings):", other_strings.len());
        for (offset, string) in other_strings.iter().take(3) {
            let display = if string.len() > 30 { format!("{}...", &string[..27]) } else { string.to_string() };
            println!("    0x{:x}: \"{}\"", offset, display);
        }
    }
}

fn dump_debug_info_section(file: &ElfBytes<AnyEndian>) {
    println!("\n=== .debug_info Section Analysis ===");
    
    let _section_headers = match file.section_headers() {
        Some(headers) => headers,
        None => {
            println!("No section headers found");
            return;
        }
    };
    
    let string_table = match file.section_headers_with_strtab() {
        Ok((_, strtab)) => strtab,
        Err(_) => {
            println!("Could not read string table");
            return;
        }
    };
    
    // Find .debug_info section
    let mut debug_info_section = None;
    for section_header in _section_headers.iter() {
        let section_name = match string_table {
            Some(ref strtab) => {
                strtab.get(section_header.sh_name as usize)
                    .unwrap_or("<invalid>")
            },
            None => "<no-strtab>"
        };
        
        if section_name == ".debug_info" {
            debug_info_section = Some(section_header);
            break;
        }
    }
    
    let debug_info_header = match debug_info_section {
        Some(header) => header,
        None => {
            println!(".debug_info section not found");
            return;
        }
    };
    
    let section_data = match file.section_data(&debug_info_header) {
        Ok((data, _)) => data,
        Err(e) => {
            println!("Error reading .debug_info section: {}", e);
            return;
        }
    };
    
    println!("Section size: {} bytes (0x{:x})", section_data.len(), section_data.len());
    println!("Section offset: 0x{:x}", debug_info_header.sh_offset);
    
    // Parse DWARF compilation units
    let mut offset = 0;
    let mut cu_count = 0;
    
    while offset + 11 < section_data.len() {
        cu_count += 1;
        
        // Read compilation unit header
        let unit_length = u32::from_le_bytes([
            section_data[offset],
            section_data[offset + 1],
            section_data[offset + 2],
            section_data[offset + 3]
        ]);
        
        let version = u16::from_le_bytes([
            section_data[offset + 4],
            section_data[offset + 5]
        ]);
        
        let debug_abbrev_offset = u32::from_le_bytes([
            section_data[offset + 6],
            section_data[offset + 7],
            section_data[offset + 8],
            section_data[offset + 9]
        ]);
        
        let address_size = section_data[offset + 10];
        
        println!("\n--- Compilation Unit {} ---", cu_count);
        println!("Offset: 0x{:x}", debug_info_header.sh_offset + offset as u64);
        println!("Unit Length: {} bytes (0x{:x})", unit_length, unit_length);
        println!("DWARF Version: {} ({})", version, dwarf_version_to_string(version));
        println!("Debug Abbrev Offset: 0x{:x}", debug_abbrev_offset);
        println!("Address Size: {} bytes", address_size);
        
        // Show first few DIE entries
        let die_start = offset + 11;
        let die_end = offset + unit_length as usize + 4;
        
        if die_start < section_data.len() && die_end <= section_data.len() {
            println!("\nAll DIE entries ({} bytes):", die_end - die_start);
            let die_offset = debug_info_header.sh_offset + die_start as u64;
            
            for (i, chunk) in section_data[die_start..die_end].chunks(16).enumerate() {
                print!("{:08x}: ", die_offset + (i * 16) as u64);
                
                // Print hex bytes
                for (j, byte) in chunk.iter().enumerate() {
                    if j == 8 {
                        print!(" ");
                    }
                    print!("{:02x} ", byte);
                }
                
                // Pad if chunk is less than 16 bytes
                for j in chunk.len()..16 {
                    if j == 8 {
                        print!(" ");
                    }
                    print!("   ");
                }
                
                // Print ASCII representation
                print!(" |");
                for byte in chunk {
                    if *byte >= 32 && *byte <= 126 {
                        print!("{}", *byte as char);
                    } else {
                        print!(".");
                    }
                }
                println!("|")
            }
        }
        
        // Move to next compilation unit
        offset += unit_length as usize + 4;
        
        // Limit to first 5 compilation units to avoid too much output
        if cu_count >= 5 {
            let remaining_units = {
                let mut remaining = 0;
                let mut temp_offset = offset;
                while temp_offset + 11 < section_data.len() {
                    let temp_length = u32::from_le_bytes([
                        section_data[temp_offset],
                        section_data[temp_offset + 1],
                        section_data[temp_offset + 2],
                        section_data[temp_offset + 3]
                    ]);
                    temp_offset += temp_length as usize + 4;
                    remaining += 1;
                    if temp_offset >= section_data.len() { break; }
                }
                remaining
            };
            
            if remaining_units > 0 {

            }
            break;
        }
    }
    
    println!("\nTotal compilation units analyzed: {}", cu_count);
}

fn dump_dwarf_detailed(file: &ElfBytes<AnyEndian>) {
    println!("\n=== DWARF Debug Information (Detailed) ===");
    
    let _section_headers = match file.section_headers() {
        Some(headers) => headers,
        None => {
            println!("No section headers found");
            return;
        }
    };
    
    let string_table = match file.section_headers_with_strtab() {
        Ok((_, strtab)) => strtab,
        Err(_) => {
            println!("Could not read string table");
            return;
        }
    };
    
    // Find and load all DWARF sections
    let mut debug_sections = std::collections::HashMap::new();
    
    for section_header in _section_headers.iter() {
        let section_name = match string_table {
            Some(ref strtab) => {
                strtab.get(section_header.sh_name as usize)
                    .unwrap_or("<invalid>")
            },
            None => "<no-strtab>"
        };
        
        if section_name.starts_with(".debug_") {
            if let Ok((data, _)) = file.section_data(&section_header) {
                debug_sections.insert(section_name.to_string(), data);
            }
        }
    }
    
    println!("Found {} debug sections", debug_sections.len());
    
    // Create DWARF object using the dwarf crate
    let debug_info = debug_sections.get(".debug_info").copied().unwrap_or(&[]);
    let debug_abbrev = debug_sections.get(".debug_abbrev").copied().unwrap_or(&[]);
    let debug_str = debug_sections.get(".debug_str").copied().unwrap_or(&[]);
    let debug_line = debug_sections.get(".debug_line").copied().unwrap_or(&[]);
    let debug_line_str = debug_sections.get(".debug_line_str").copied().unwrap_or(&[]);
    let debug_ranges = debug_sections.get(".debug_ranges").copied().unwrap_or(&[]);
    let debug_rnglists = debug_sections.get(".debug_rnglists").copied().unwrap_or(&[]);
    let debug_loc = debug_sections.get(".debug_loc").copied().unwrap_or(&[]);
    let debug_loclists = debug_sections.get(".debug_loclists").copied().unwrap_or(&[]);
    
    println!("Section sizes:");
    println!("  .debug_info: {} bytes", debug_info.len());
    println!("  .debug_abbrev: {} bytes", debug_abbrev.len());
    println!("  .debug_str: {} bytes", debug_str.len());
    println!("  .debug_line: {} bytes", debug_line.len());
    println!("  .debug_line_str: {} bytes", debug_line_str.len());
    println!("  .debug_ranges: {} bytes", debug_ranges.len());
    println!("  .debug_rnglists: {} bytes", debug_rnglists.len());
    println!("  .debug_loc: {} bytes", debug_loc.len());
    println!("  .debug_loclists: {} bytes", debug_loclists.len());
    
    // Create EndianSlice wrappers
    let endian = LittleEndian;
    let debug_info_slice = EndianSlice::new(debug_info, endian);
    let debug_abbrev_slice = EndianSlice::new(debug_abbrev, endian);
    let debug_str_slice = EndianSlice::new(debug_str, endian);
    let debug_line_slice = EndianSlice::new(debug_line, endian);
    let debug_line_str_slice = EndianSlice::new(debug_line_str, endian);
    let debug_ranges_slice = EndianSlice::new(debug_ranges, endian);
    let debug_rnglists_slice = EndianSlice::new(debug_rnglists, endian);
    let debug_loc_slice = EndianSlice::new(debug_loc, endian);
    let debug_loclists_slice = EndianSlice::new(debug_loclists, endian);
    
    // Create DWARF object
    let dwarf = Dwarf {
        debug_abbrev: debug_abbrev_slice.into(),
        debug_addr: EndianSlice::new(&[], endian).into(),
        debug_aranges: EndianSlice::new(&[], endian).into(),
        debug_info: debug_info_slice.into(),
        debug_line: debug_line_slice.into(),
        debug_line_str: debug_line_str_slice.into(),
        debug_str: debug_str_slice.into(),
        debug_str_offsets: EndianSlice::new(&[], endian).into(),
        debug_types: EndianSlice::new(&[], endian).into(),
        locations: gimli::LocationLists::new(
            debug_loc_slice.into(),
            debug_loclists_slice.into(),
        ),
        ranges: gimli::RangeLists::new(
            debug_ranges_slice.into(),
            debug_rnglists_slice.into(),
        ),
        file_type: gimli::DwarfFileType::Main,
        sup: None,
        abbreviations_cache: gimli::AbbreviationsCache::new(),
        debug_macinfo: EndianSlice::new(&[], endian).into(),
        debug_macro: EndianSlice::new(&[], endian).into(),
    };
    
    println!("\n--- Compilation Units ---");
    
    // Iterate through compilation units
    let mut units = dwarf.units();
    let mut unit_count = 0;
    
    while let Ok(Some(header)) = units.next() {
        unit_count += 1;
        println!("\nCompilation Unit {}:", unit_count);
        println!("  Offset: {:?}", header.offset());
        println!("  Length: {} bytes", header.length_including_self());
        println!("  Version: {} ({})", header.version(), dwarf_version_to_string(header.version()));
        println!("  Features: {}", dwarf_version_features(header.version()));
        println!("  Address size: {} bytes", header.address_size());

        let base_address = get_virtual_base_address(file);
        if let Ok(unit) = dwarf.unit(header) {
            let mut entries = unit.entries();
            if let Ok(Some((_, entry))) = entries.next_dfs() {
                println!("  Root DIE tag: {} ({:?})", dwarf_tag_to_string(entry.tag()), entry.tag());
                // Root DIE attributes
                let low_pc_abs: Option<u64> = match entry.attr_value(gimli::DW_AT_low_pc) {
                    Ok(Some(gimli::AttributeValue::Addr(a))) => Some(base_address + a),
                    _ => None,
                };
                let mut attrs = entry.attrs();
                while let Ok(Some(attr)) = attrs.next() {
                    if attr.name() == gimli::DW_AT_ranges && header.version() != 5 { continue; }
                    let attr_name = dwarf_at_to_string(attr.name());
                    let attr_value = if attr.name() == gimli::DW_AT_ranges {
                        format!("ranges: {:?}", attr.value())
                    } else if attr.name() == gimli::DW_AT_name {
                        match attr.value() {
                            gimli::AttributeValue::String(s) => format!("\"{}\" (inline)", s.to_string_lossy()),
                            gimli::AttributeValue::DebugStrRef(offset) => match dwarf.debug_str.get_str(offset) {
                                Ok(s) => format!("\"{}\" (strp)", s.to_string_lossy()),
                                Err(_) => format!("<string@{:?}> (strp)", offset),
                            },
                            gimli::AttributeValue::DebugLineStrRef(offset) => match dwarf.debug_line_str.get_str(offset) {
                                Ok(s) => format!("\"{}\" (line_strp)", s.to_string_lossy()),
                                Err(_) => format!("<line_string@0x{:x}> (line_strp)", offset.0),
                            },
                            _ => format!("{:?}", attr.value()),
                        }
                    } else { match attr.value() {
                        gimli::AttributeValue::Language(lang) => format!("{} ({:?})", dwarf_lang_to_string(lang), lang),
                        gimli::AttributeValue::DebugStrRef(offset) => match dwarf.debug_str.get_str(offset) {
                            Ok(s) => format!("\"{}\"", s.to_string_lossy()),
                            Err(_) => format!("<string@{:?}>", offset),
                        },
                        gimli::AttributeValue::DebugLineRef(offset) => format!("line_program@0x{:x}", offset.0),
                        gimli::AttributeValue::UnitRef(offset) => format!("unit_ref@0x{:x}", offset.0),
                        gimli::AttributeValue::Exprloc(expr) => match expr.0.to_slice() {
                            Ok(cow_bytes) => { let bytes = cow_bytes.as_ref(); if bytes.len() <= 8 { format!("location[{}]: {:02x?}", bytes.len(), bytes) } else { format!("location[{}]: {:02x?}...", bytes.len(), &bytes[..8]) } },
                            Err(_) => "location[invalid]".to_string(),
                        },
                        gimli::AttributeValue::Addr(addr) => {
                            if attr.name() == gimli::DW_AT_low_pc || attr.name() == gimli::DW_AT_high_pc { format!("Addr(0x{:x})", base_address + addr) } else { format!("{:?}", attr.value()) }
                        }
                        gimli::AttributeValue::Udata(off) if attr.name() == gimli::DW_AT_high_pc => {
                            if let Some(low) = low_pc_abs { format!("Addr(0x{:x})", low.saturating_add(off as u64)) } else { format!("Udata({})", off) }
                        }
                        _ => format!("{:?}", attr.value()),
                    }};
                    println!("    {}: {}", attr_name, attr_value);
                    println!("      Form details: {}", get_attribute_value_details(&attr, &dwarf, base_address));
                }

                // Ranges for root DIE (DWARF5)
                if header.version() == 5 {
                    let mut decoded = Vec::new();
                    if let Ok(mut ranges) = dwarf.die_ranges(&unit, &entry) {
                        while let Ok(Some(range)) = ranges.next() { decoded.push((range.begin, range.end)); }
                    }
                    if !decoded.is_empty() {
                        println!("    DW_AT_ranges (decoded):");
                        for (b, e) in decoded { println!("      [0x{:x}..0x{:x}] (virt: 0x{:x}..0x{:x})", b, e, base_address + b, base_address + e); }
                    }
                }

                // Direct children only
                println!("  Child DIEs (direct children):");
                let mut die_count = 0;
                while let Ok(Some((depth, entry))) = entries.next_dfs() {
                    if depth == 0 { break; }
                    if depth != 1 { continue; }
                    println!("    DIE {}: {} ({:?}) (depth: {})", die_count + 1, dwarf_tag_to_string(entry.tag()), entry.tag(), depth);
                    let low_pc_abs: Option<u64> = match entry.attr_value(gimli::DW_AT_low_pc) {
                        Ok(Some(gimli::AttributeValue::Addr(a))) => Some(base_address + a),
                        _ => None,
                    };
                    let mut attrs = entry.attrs();
                    while let Ok(Some(attr)) = attrs.next() {
                        if attr.name() == gimli::DW_AT_ranges && header.version() != 5 { continue; }
                        let attr_name = dwarf_at_to_string(attr.name());
                        let attr_value = if attr.name() == gimli::DW_AT_ranges {
                            format!("ranges: {:?}", attr.value())
                        } else if attr.name() == gimli::DW_AT_name {
                            match attr.value() {
                                gimli::AttributeValue::String(s) => format!("\"{}\" (inline)", s.to_string_lossy()),
                                gimli::AttributeValue::DebugStrRef(offset) => match dwarf.debug_str.get_str(offset) {
                                    Ok(s) => format!("\"{}\" (strp)", s.to_string_lossy()),
                                    Err(_) => format!("<string@{:?}> (strp)", offset),
                                },
                                gimli::AttributeValue::DebugLineStrRef(offset) => match dwarf.debug_line_str.get_str(offset) {
                                    Ok(s) => format!("\"{}\" (line_strp)", s.to_string_lossy()),
                                    Err(_) => format!("<line_string@0x{:x}> (line_strp)", offset.0),
                                },
                                _ => format!("{:?}", attr.value()),
                            }
                        } else { match attr.value() {
                            gimli::AttributeValue::Language(lang) => format!("{} ({:?})", dwarf_lang_to_string(lang), lang),
                            gimli::AttributeValue::DebugStrRef(offset) => match dwarf.debug_str.get_str(offset) {
                                Ok(s) => format!("\"{}\"", s.to_string_lossy()),
                                Err(_) => format!("<string@{:?}>", offset),
                            },
                            gimli::AttributeValue::DebugLineRef(offset) => format!("line_program@0x{:x}", offset.0),
                            gimli::AttributeValue::UnitRef(offset) => format!("unit_ref@0x{:x}", offset.0),
                            gimli::AttributeValue::Exprloc(expr) => match expr.0.to_slice() {
                                Ok(cow_bytes) => { let bytes = cow_bytes.as_ref(); if bytes.len() <= 8 { format!("location[{}]: {:02x?}", bytes.len(), bytes) } else { format!("location[{}]: {:02x?}...", bytes.len(), &bytes[..8]) } },
                                Err(_) => "location[invalid]".to_string(),
                            },
                            gimli::AttributeValue::Addr(addr) => {
                                if attr.name() == gimli::DW_AT_low_pc || attr.name() == gimli::DW_AT_high_pc { format!("Addr(0x{:x})", base_address + addr) } else { format!("{:?}", attr.value()) }
                            }
                            gimli::AttributeValue::Udata(off) if attr.name() == gimli::DW_AT_high_pc => {
                                if let Some(low) = low_pc_abs { format!("Addr(0x{:x})", low.saturating_add(off as u64)) } else { format!("Udata({})", off) }
                            }
                            _ => format!("{:?}", attr.value()),
                        }};
                        println!("      {}: {}", attr_name, attr_value);
                        println!("        Form details: {}", get_attribute_value_details(&attr, &dwarf, base_address));
                    }
                    // Ranges for child (DWARF5)
                    if header.version() == 5 {
                        let mut decoded = Vec::new();
                        if let Ok(mut ranges) = dwarf.die_ranges(&unit, &entry) {
                            while let Ok(Some(range)) = ranges.next() { decoded.push((range.begin, range.end)); }
                        }
                        if !decoded.is_empty() {
                            println!("      DW_AT_ranges (decoded):");
                            for (b, e) in decoded { println!("        [0x{:x}..0x{:x}] (virt: 0x{:x}..0x{:x})", b, e, base_address + b, base_address + e); }
                        }
                    }
                    die_count += 1;
                }

                // Line number info for this unit
                if let Some(line_program) = unit.line_program.clone() {
                    println!("\n--- Line Number Information (this unit) ---");
                    let mut rows = line_program.rows();
                    let mut row_count: u64 = 0;
                    while let Ok(Some((header, row))) = rows.next_row() {
                        if let Some(file) = row.file(header) {
                            let file_name = match dwarf.attr_string(&unit, file.path_name()) {
                                Ok(name) => name.to_string_lossy().into_owned(),
                                Err(_) => "<unknown>".to_string(),
                            };
                            println!("  Row {}: {}:{} -> 0x{:x}", row_count + 1, file_name, row.line().map(|n| n.get()).unwrap_or(0), row.address());
                        }
                        row_count += 1;
                    }
                    println!("  Total line number entries in this unit: {}", row_count);
                } else {
                    println!("\n--- Line Number Information (this unit) ---\n  No line program");
                }
            }
        }
    }
}

fn dump_dwarf_with_crate(file: &ElfBytes<AnyEndian>) {
    println!("\n=== DWARF Debug Information (Using gimli crate) ===");
    dump_dwarf_detailed(file);
}

#[derive(Parser)]
#[command(name = "tsudump-linux")]
#[command(about = "ELF file analysis and DWARF debugging information dumper")]
struct Cli {
    /// ELF file to analyze
    file: String,
    
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Dump ELF header information
    Header,
    /// Dump section headers
    Sections,
    /// Dump .text section with disassembly
    Text,
    /// Dump .data section
    Data,
    /// Dump symbol tables
    Symbols,
    /// Dump line number information
    Line,
    /// Dump debug sections overview
    Debug,
    /// Dump detailed .debug_info section
    DebugInfo,
    /// Dump detailed DWARF information
    DwarfDetailed,
    /// Dump DWARF information using gimli crate
    DwarfGimli,
    /// Dump all information (default behavior)
    All,
}

fn main() {
    let cli = Cli::parse();
    let file_path = std::path::PathBuf::from(&cli.file);
    let file_data = std::fs::read(&file_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Failed to parse ELF file");

    match cli.command {
        Some(Commands::Header) => {
            // Removed unused function `dump_elf_header`
        },
        Some(Commands::Sections) => {
            dump_section_headers(&file);
        },
        Some(Commands::Text) => {
            println!("=== .text Section Dump ===");
            let symbols = build_symbol_map(&file);
            dump_text_section(&file, &symbols);
            dump_other_executable_sections(&file, &symbols);
        },
        Some(Commands::Data) => {
            println!("=== .data Section Dump ===");
            dump_data_section(&file);
        },
        Some(Commands::Symbols) => {
            dump_symbol_section(&file);
        },
        Some(Commands::Line) => {
            println!("=== .line Section Dump ===");
            dump_line_section(&file);
        },
        Some(Commands::Debug) => {
            dump_debug_sections(&file);
        },
        Some(Commands::DebugInfo) => {
            dump_debug_info_section(&file);
        },
        Some(Commands::DwarfDetailed) => {
            dump_dwarf_detailed(&file);
        },
        Some(Commands::DwarfGimli) => {
            dump_dwarf_with_crate(&file);
        },
        Some(Commands::All) | None => {
            // Default behavior: dump all information
            dump_section_headers(&file);
            
            println!();
            println!("=== .text Section Dump ===");
            let symbols = build_symbol_map(&file);
            dump_text_section(&file, &symbols);
            dump_other_executable_sections(&file, &symbols);
            
            println!();
            println!("=== .data Section Dump ===");
            dump_data_section(&file);
            
            println!();
            dump_symbol_section(&file);
            
            println!();
            println!("=== .line Section Dump ===");
            dump_line_section(&file);
            
            dump_debug_sections(&file);
            dump_debug_info_section(&file);
            dump_dwarf_with_crate(&file);
        }
    }
}