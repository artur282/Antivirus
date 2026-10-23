use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use chrono::Utc;

use crate::db;
use crate::stats;
use crate::Result;

pub(crate) fn export_csv(history_db: &Path, path: &Path) -> Result<()> {
    let connection = db::open(history_db)?;
    let mut statement = connection.prepare(
        "SELECT file_path, is_infected, scan_date
         FROM scan_history
         ORDER BY scan_date DESC, id DESC",
    )?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "Archivo,Estado,Fecha")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let file_path: String = row.get(0)?;
        let is_infected: i64 = row.get(1)?;
        let scan_date: String = row.get(2)?;
        let status = if is_infected != 0 {
            "Infectado"
        } else {
            "Seguro"
        };
        writeln!(
            writer,
            "{},{},{}",
            csv_field(&file_path),
            status,
            csv_field(&scan_date)
        )?;
    }
    writer.flush()?;
    Ok(())
}

pub(crate) fn export_pdf(history_db: &Path, path: &Path) -> Result<()> {
    let stats = stats::compute(history_db)?;
    let generated_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let lines = [
        format!("Fecha de generación: {generated_at}"),
        format!("Total de Archivos Escaneados: {}", stats.total_scanned),
        format!("Archivos Seguros: {}", stats.total_safe),
        format!("Archivos Infectados: {}", stats.total_infected),
        format!("Tasa de Infección: {:.2}%", stats.infection_rate),
    ];

    let mut content = Vec::new();
    content.extend_from_slice(b"BT\n/F1 16 Tf\n72 750 Td\n");
    push_pdf_string(
        &mut content,
        "Reporte Estadístico de Escaneos - Antivirus Rust",
    );
    content.extend_from_slice(b" Tj\nET\nBT\n/F2 12 Tf\n72 710 Td\n");
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            content.extend_from_slice(b"0 -24 Td\n");
        }
        push_pdf_string(&mut content, line);
        content.extend_from_slice(b" Tj\n");
    }
    content.extend_from_slice(b"ET\n");

    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = Vec::with_capacity(6);
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj\n",
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold \
         /Encoding /WinAnsiEncoding >>\nendobj\n",
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
         /Encoding /WinAnsiEncoding >>\nendobj\n",
    ];
    for object in objects {
        offsets.push(pdf.len());
        pdf.extend_from_slice(object.as_bytes());
    }

    offsets.push(pdf.len());
    pdf.extend_from_slice(format!("6 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    pdf.extend_from_slice(&content);
    pdf.extend_from_slice(b"endstream\nendobj\n");

    let xref_offset = pdf.len();
    pdf.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );

    fs::write(path, pdf)?;
    Ok(())
}

fn csv_field(value: &str) -> String {
    if value
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn push_pdf_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'(');
    for character in text.chars() {
        let code = if (character as u32) < 0x100 {
            character as u8
        } else {
            b'?'
        };
        match code {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(code);
            }
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            _ => out.push(code),
        }
    }
    out.push(b')');
}
