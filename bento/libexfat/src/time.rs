const SEC_IN_MIN: i64 = 60;
const SEC_IN_HOUR: i64 = 60 * SEC_IN_MIN;
const SEC_IN_DAY: i64 = 24 * SEC_IN_HOUR;
const SEC_IN_YEAR: i64 = 365 * SEC_IN_DAY; // not leap year

// Unix epoch started at 0:00:00 UTC 1 January 1970
const UNIX_EPOCH_YEAR: i64 = 1970;

// exFAT epoch started at 0:00:00 UTC 1 January 1980
const EXFAT_EPOCH_YEAR: i64 = 1980;

// number of years from Unix epoch to exFAT epoch
const EPOCH_DIFF_YEAR: i64 = EXFAT_EPOCH_YEAR - UNIX_EPOCH_YEAR;

// number of days from Unix epoch to exFAT epoch (considering leap days)
const EPOCH_DIFF_DAYS: i64 = EPOCH_DIFF_YEAR * 365 + EPOCH_DIFF_YEAR / 4;

// number of seconds from Unix epoch to exFAT epoch (considering leap days)
const EPOCH_DIFF_SEC: i64 = EPOCH_DIFF_DAYS * SEC_IN_DAY;

const DAYS_IN_YEAR: [i64; 13] = [
    0,   // N/A
    0,   // Jan
    31,  // Feb
    59,  // Mar
    90,  // Apr
    120, // May
    151, // Jun
    181, // Jul
    212, // Aug
    243, // Sep
    273, // Oct
    304, // Nov
    334, // Dec
];

// timezone offset from UTC in seconds; positive for western timezones,
// negative for eastern ones
static mut EXFAT_TIMEZONE: i64 = 0;

// number of leap years passed from exFAT epoch to the specified year
// (excluding the specified year itself)
fn leap_years(year: i64) -> i64 {
    (EXFAT_EPOCH_YEAR + year - 1) / 4 - (EXFAT_EPOCH_YEAR - 1) / 4
}

// checks whether the specified year is leap
fn is_leap_year(year: i64) -> bool {
    (EXFAT_EPOCH_YEAR + year) % 4 == 0
}

pub(crate) fn exfat2unix(date: u16, time: u16, centisec: u8, tzoffset: u8) -> u64 {
    let mut unix_time = EPOCH_DIFF_SEC;
    let ndate = i64::from(u16::from_le(date));
    let ntime = i64::from(u16::from_le(time));

    let day = ndate & 0x1f; // 5 bits, 1-31
    let month = (ndate >> 5) & 0xf; // 4 bits, 1-12
    let year = ndate >> 9; // 7 bits, 1-127 (+1980)

    let twosec = ntime & 0x1f; // 5 bits, 0-29 (2 sec granularity)
    let min = (ntime >> 5) & 0x3f; // 6 bits, 0-59
    let hour = ntime >> 11; // 5 bits, 0-23

    if day == 0 || month == 0 || month > 12 {
        log::error!(
            "bad date {}-{:02}-{:02}",
            year + EXFAT_EPOCH_YEAR,
            month,
            day
        );
        return 0;
    }
    if hour > 23 || min > 59 || twosec > 29 {
        log::error!("bad time {}:{:02}:{:02}", hour, min, twosec * 2);
        return 0;
    }
    if centisec > 199 {
        log::error!("bad centiseconds count {centisec}");
        return 0;
    }

    // every 4th year between 1904 and 2096 is leap
    unix_time += year * SEC_IN_YEAR + leap_years(year) * SEC_IN_DAY;
    unix_time += DAYS_IN_YEAR[usize::try_from(month).unwrap()] * SEC_IN_DAY;
    // if it's leap year and February has passed we should add 1 day
    if ((EXFAT_EPOCH_YEAR + year) % 4 == 0) && month > 2 {
        unix_time += SEC_IN_DAY;
    }
    unix_time += (day - 1) * SEC_IN_DAY;

    unix_time += hour * SEC_IN_HOUR;
    unix_time += min * SEC_IN_MIN;
    // exFAT represents time with 2 sec granularity
    unix_time += twosec * 2;
    unix_time += i64::from(centisec) / 100;

    // exFAT stores timestamps in local time, so we correct it to UTC
    if (tzoffset & 0x80) != 0 {
        // lower 7 bits are signed timezone offset in 15 minute increments
        unix_time -= i64::from((tzoffset << 1) as i8) * 15 * 60 / 2;
    } else {
        // timezone offset not present, assume our local timezone
        unix_time += tzget();
    }
    assert!(unix_time > 0); // 1980 or after
    unix_time.try_into().unwrap()
}

pub(crate) fn unix2exfat(unix_time: u64) -> (u16, u16, u8, u8) {
    // time before exFAT epoch cannot be represented
    let shift = EPOCH_DIFF_SEC + tzget();
    let mut unix_time = unix_time.try_into().unwrap();
    if unix_time < shift {
        unix_time = shift;
    }
    unix_time -= shift;

    let mut days = unix_time / SEC_IN_DAY;
    let year = (4 * days) / (4 * 365 + 1);
    days -= year * 365 + leap_years(year);
    let mut month = 0i64;
    for i in 1..=12 {
        let leap_day = i64::from(is_leap_year(year) && i == 2);
        let leap_sub = i64::from(is_leap_year(year) && i >= 3);
        if i == 12 || days - leap_sub < DAYS_IN_YEAR[i + 1] + leap_day {
            month = i.try_into().unwrap();
            days -= DAYS_IN_YEAR[i] + leap_sub;
            break;
        }
    }
    let day = days + 1;

    let hour = (unix_time % SEC_IN_DAY) / SEC_IN_HOUR;
    let min = (unix_time % SEC_IN_HOUR) / SEC_IN_MIN;
    let twosec = (unix_time % SEC_IN_MIN) / 2;

    let date = (day | (month << 5) | (year << 9))
        .to_le()
        .try_into()
        .unwrap();
    let time = (twosec | (min << 5) | (hour << 11))
        .to_le()
        .try_into()
        .unwrap();
    let centisec = ((unix_time % 2) * 100).try_into().unwrap();
    // record our local timezone offset in exFAT (15 minute increment) format
    let tzoffset = ((-tzget() / 60 / 15) | 0x80) as u8;
    (date, time, centisec, tzoffset)
}

fn tzclear() {
    unsafe {
        EXFAT_TIMEZONE = 0;
    }
}

pub(crate) fn tzget() -> i64 {
    unsafe { EXFAT_TIMEZONE }
}

pub(crate) fn tzset() -> Result<(), crate::Error> {
    tzclear();
    Ok(())
}

pub(crate) fn tzassert() {
    let diff_utc_plus = 14 * 60 * 60;
    let diff_utc_minus = -12 * 60 * 60;
    let tz = -tzget();
    assert!(tz <= diff_utc_plus);
    assert!(tz >= diff_utc_minus);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_tzget() {
        super::tzclear();
        assert_eq!(super::tzget(), 0);
    }

    #[test]
    fn test_tzset() {
        if let Err(e) = super::tzset() {
            eprintln!("{e}"); // XXX ["local-offset"] feature not usable in tests
        }
        super::tzassert();
        super::tzclear();
    }
}
