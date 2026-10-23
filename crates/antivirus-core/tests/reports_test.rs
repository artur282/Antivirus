mod common;

use std::fs;
use std::sync::atomic::AtomicBool;

use antivirus_core::{ScanKind, ScanRequest};

fn scanned_core() -> (tempfile::TempDir, antivirus_core::Core) {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));

    let infected = common::write_file(&dir.path().join("a_infected.bin"), b"hello");
    let safe = common::write_file(&dir.path().join("b_safe.txt"), b"world");
    let weird = common::write_file(&dir.path().join("c_con,ñ.txt"), b"otro");

    let request = ScanRequest {
        kind: ScanKind::File,
        paths: vec![
            common::path_string(&infected),
            common::path_string(&safe),
            common::path_string(&weird),
        ],
    };
    let cancel = AtomicBool::new(false);
    core.scan(request, &cancel, &|_| {}).expect("scan");
    (dir, core)
}

#[test]
fn csv_export_has_exact_header_states_and_all_rows() {
    let (dir, core) = scanned_core();
    let output = dir.path().join("report.csv");

    core.export_csv(&output).expect("export csv");
    let content = fs::read_to_string(&output).expect("read csv");

    let mut lines = content.lines();
    assert_eq!(lines.next(), Some("Archivo,Estado,Fecha"));
    let rows: Vec<&str> = lines.collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows.iter()
            .filter(|row| row.contains(",Infectado,"))
            .count(),
        1
    );
    assert_eq!(
        rows.iter().filter(|row| row.contains(",Seguro,")).count(),
        2
    );
    assert!(content.contains("a_infected.bin"));
    assert!(content.contains("c_con,ñ.txt"), "UTF-8 paths are kept");
    assert!(
        content.contains("c_con,ñ.txt\","),
        "fields containing commas are quoted"
    );
}

#[test]
fn csv_export_of_empty_history_contains_only_the_header() {
    let dir = common::temp_dir();
    let core = common::make_core(&dir.path().join("app-data"), None);
    let output = dir.path().join("empty.csv");

    core.export_csv(&output).expect("export csv");
    assert_eq!(
        fs::read_to_string(&output).expect("read csv"),
        "Archivo,Estado,Fecha\n"
    );
}

#[test]
fn pdf_export_is_a_valid_1_4_document_with_summary_values() {
    let (dir, core) = scanned_core();
    let output = dir.path().join("report.pdf");

    core.export_pdf(&output).expect("export pdf");
    let bytes = fs::read(&output).expect("read pdf");

    assert!(bytes.starts_with(b"%PDF-1.4"));
    assert!(bytes.ends_with(b"%%EOF\n"));
    assert!(bytes.windows(b"xref".len()).any(|window| window == b"xref"));
    assert!(contains(
        &bytes,
        b"Reporte Estad\xEDstico de Escaneos - Antivirus Rust"
    ));
    assert!(contains(&bytes, b"Fecha de generaci\xF3n: "));
    assert!(contains(&bytes, b"Total de Archivos Escaneados: 3"));
    assert!(contains(&bytes, b"Archivos Seguros: 2"));
    assert!(contains(&bytes, b"Archivos Infectados: 1"));
    assert!(contains(&bytes, b"Tasa de Infecci\xF3n: 33.33%"));
}

#[test]
fn pdf_export_of_empty_history_reports_zero_values() {
    let dir = common::temp_dir();
    let core = common::make_core(&dir.path().join("app-data"), None);
    let output = dir.path().join("empty.pdf");

    core.export_pdf(&output).expect("export pdf");
    let bytes = fs::read(&output).expect("read pdf");

    assert!(bytes.starts_with(b"%PDF-1.4"));
    assert!(contains(&bytes, b"Total de Archivos Escaneados: 0"));
    assert!(contains(&bytes, b"Archivos Seguros: 0"));
    assert!(contains(&bytes, b"Archivos Infectados: 0"));
    assert!(contains(&bytes, b"Tasa de Infecci\xF3n: 0.00%"));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
