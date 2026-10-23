use std::collections::HashMap;
use std::path::Path;

use chrono::{Duration, Utc};

use crate::db;
use crate::types::{DailyStat, Stats};
use crate::Result;

const DAILY_WINDOW_DAYS: usize = 14;

pub(crate) fn compute(history_db: &Path) -> Result<Stats> {
    let connection = db::open(history_db)?;

    let (total_scanned, total_infected, last_scan_at): (i64, i64, Option<String>) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(is_infected), 0), MAX(scan_date) FROM scan_history",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

    let today = Utc::now().date_naive();
    let first_day = today - Duration::days((DAILY_WINDOW_DAYS - 1) as i64);
    let window_start = format!("{} 00:00:00", first_day.format("%Y-%m-%d"));

    let mut per_day: HashMap<String, (u64, u64)> = HashMap::new();
    let mut statement = connection.prepare(
        "SELECT substr(scan_date, 1, 10) AS day,
                COUNT(*),
                COALESCE(SUM(is_infected), 0)
         FROM scan_history
         WHERE scan_date >= ?1
         GROUP BY day",
    )?;
    let rows = statement.query_map([window_start], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (date, total, infected) = row?;
        per_day.insert(date, (total.max(0) as u64, infected.max(0) as u64));
    }

    let mut daily = Vec::with_capacity(DAILY_WINDOW_DAYS);
    for offset in 0..DAILY_WINDOW_DAYS {
        let date = (first_day + Duration::days(offset as i64))
            .format("%Y-%m-%d")
            .to_string();
        let (total, infected) = per_day.get(&date).copied().unwrap_or((0, 0));
        daily.push(DailyStat {
            date,
            total,
            infected,
        });
    }

    let total_scanned = total_scanned.max(0) as u64;
    let total_infected = total_infected.max(0) as u64;
    let total_safe = total_scanned.saturating_sub(total_infected);
    let infection_rate = if total_scanned == 0 {
        0.0
    } else {
        total_infected as f64 / total_scanned as f64 * 100.0
    };

    Ok(Stats {
        total_scanned,
        total_infected,
        total_safe,
        infection_rate,
        last_scan_at,
        daily,
    })
}
