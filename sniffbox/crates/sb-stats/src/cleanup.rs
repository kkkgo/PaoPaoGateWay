// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use time::{OffsetDateTime, UtcOffset};

#[derive(Debug, Default, Clone, Copy)]
pub struct CleanState {

    pub last_fired_ym: Option<(i32, u8)>,
}

pub fn should_clean(now: OffsetDateTime, cfg_day: u8, state: &CleanState) -> bool {
    if cfg_day == 0 || cfg_day > 31 {
        return false;
    }
    if now.day() != cfg_day {
        return false;
    }
    !matches!(state.last_fired_ym, Some((y, m)) if y == now.year() && m == now.month() as u8)
}

pub fn maybe_clean(cfg_day: u8, state: &mut CleanState, clear: impl FnOnce()) -> bool {
    let now = OffsetDateTime::now_utc().to_offset(UtcOffset::from_hms(8, 0, 0).unwrap());
    maybe_clean_at(cfg_day, state, now, clear)
}

pub fn maybe_clean_at(
    cfg_day: u8,
    state: &mut CleanState,
    now: OffsetDateTime,
    clear: impl FnOnce(),
) -> bool {
    if should_clean(now, cfg_day, state) {
        clear();
        state.last_fired_ym = Some((now.year(), now.month() as u8));
        tracing::info!(
            year = now.year(),
            month = now.month() as u8,
            day = now.day(),
            "net_cleanday fired"
        );
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use time::{Date, Month, UtcOffset};

    fn odt(y: i32, m: Month, d: u8) -> OffsetDateTime {
        let date = Date::from_calendar_date(y, m, d).unwrap();
        date.with_hms(0, 0, 0)
            .unwrap()
            .assume_offset(UtcOffset::UTC)
    }

    #[test]
    fn cfg_zero_never_cleans() {
        let mut s = CleanState::default();
        let cleared = Cell::new(false);
        assert!(!maybe_clean_at(
            0,
            &mut s,
            odt(2026, Month::April, 24),
            || cleared.set(true)
        ));
        assert!(!cleared.get());
    }

    #[test]
    fn cleans_on_target_day_once_per_month() {
        let count = Cell::new(0u32);
        let mut s = CleanState::default();

        assert!(maybe_clean_at(
            15,
            &mut s,
            odt(2026, Month::April, 15),
            || count.set(count.get() + 1)
        ));

        assert!(!maybe_clean_at(
            15,
            &mut s,
            odt(2026, Month::April, 15),
            || count.set(count.get() + 1)
        ));

        assert!(maybe_clean_at(
            15,
            &mut s,
            odt(2026, Month::May, 15),
            || count.set(count.get() + 1)
        ));
        assert_eq!(count.get(), 2);
    }

    #[test]
    fn does_not_clean_on_other_day() {
        let mut s = CleanState::default();
        let cleared = Cell::new(false);
        assert!(!maybe_clean_at(
            15,
            &mut s,
            odt(2026, Month::April, 16),
            || cleared.set(true)
        ));
        assert!(!cleared.get());
    }

    #[test]
    fn invalid_cfg_day_ignored() {
        let mut s = CleanState::default();
        assert!(!maybe_clean_at(
            32,
            &mut s,
            odt(2026, Month::April, 30),
            || {}
        ));
    }
}
