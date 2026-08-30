// The `Date` response header (RFC 7231 §7.1.1.1). uvicorn stamps one on every response and
// refreshes it once a second rather than per request, because formatting a date is dearer than
// comparing two integers and a response is only ever dated to the second anyway.

///|
/// The three-letter day names of the IMF-fixdate format, indexed from Sunday.
let day_names : Array[String] = [
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
]

///|
/// The three-letter month names of the IMF-fixdate format, indexed from January.
let month_names : Array[String] = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]

///|
/// Two decimal digits, zero-padded — the width IMF-fixdate gives the day and each clock field.
fn two_digits(n : Int) -> String {
  if n < 10 {
    "0\{n}"
  } else {
    "\{n}"
  }
}

///|
/// Floor division, so a pre-epoch instant lands on the day that contains it rather than the one
/// after. Truncating division would round negatives towards zero.
fn floor_div(a : Int64, b : Int64) -> Int64 {
  if a >= 0L {
    a / b
  } else {
    (a - b + 1L) / b
  }
}

///|
/// Format a Unix-epoch millisecond count as an HTTP-date in the IMF-fixdate form RFC 7231 §7.1.1.1
/// makes mandatory for a `Date` header: `Sun, 06 Nov 1994 08:49:37 GMT`, always GMT, always
/// fixed-width.
///
/// The calendar conversion is the standard civil-from-days one: shift the epoch to a March-based
/// year so the leap day falls at the end of the era, then divide out 400-year eras. It is exact for
/// any instant an `Int64` millisecond count can name, and needs no locale and no clock but the one
/// that produced `ms`.
pub fn http_date(ms : Int64) -> String {
  let days = floor_div(ms, 86400000L)
  let ms_of_day = ms - days * 86400000L
  let sec_of_day = (ms_of_day / 1000L).to_int()
  let hour = sec_of_day / 3600
  let minute = sec_of_day % 3600 / 60
  let second = sec_of_day % 60
  // 1970-01-01 was a Thursday, so shifting by 4 puts Sunday at 0.
  let weekday = ((days + 4L) % 7L + 7L) % 7L
  let z = days + 719468L
  let era = floor_div(z, 146097L)
  let doe = z - era * 146097L
  let yoe = (doe - doe / 1460L + doe / 36524L - doe / 146096L) / 365L
  let doy = doe - (365L * yoe + yoe / 4L - yoe / 100L)
  let mp = (5L * doy + 2L) / 153L
  let day = (doy - (153L * mp + 2L) / 5L + 1L).to_int()
  let month = (if mp < 10L { mp + 3L } else { mp - 9L }).to_int()
  let year = (yoe + era * 400L + (if month <= 2 { 1L } else { 0L })).to_int()
  let name = day_names[weekday.to_int()]
  let mon = month_names[month - 1]
  "\{name}, \{two_digits(day)} \{mon} \{year} \{two_digits(hour)}:\{two_digits(minute)}:\{two_digits(second)} GMT"
}

///|
/// The formatted date and the epoch second it was formatted for, so a second's worth of responses
/// share one formatting pass (← uvicorn, which refreshes its `Date` on a one-second tick).
let date_cache : Ref[(Int64, String)] = Ref((-1L, ""))

///|
/// The current instant as an HTTP-date, reformatted only when the epoch second has moved on.
pub fn http_date_now() -> String {
  let ms = @async.now()
  let sec = floor_div(ms, 1000L)
  let (at, text) = date_cache.val
  if at == sec {
    return text
  }
  let fresh = http_date(ms)
  date_cache.val = (sec, fresh)
  fresh
}

///|
/// The IMF-fixdate examples RFC 7231 §7.1.1.1 itself gives, plus the epoch, a leap day, and a
/// pre-epoch instant that only floor division dates correctly.
test "http_date renders the RFC 7231 §7.1.1.1 fixdate form" {
  // The spec's own example: Sun, 06 Nov 1994 08:49:37 GMT.
  assert_eq(http_date(784111777000L), "Sun, 06 Nov 1994 08:49:37 GMT")
  // The epoch itself was a Thursday.
  assert_eq(http_date(0L), "Thu, 01 Jan 1970 00:00:00 GMT")
  // A leap day, which the 400-year era arithmetic has to place.
  assert_eq(http_date(951782400000L), "Tue, 29 Feb 2000 00:00:00 GMT")
  // Sub-second remainders are dropped, not rounded.
  assert_eq(http_date(999L), "Thu, 01 Jan 1970 00:00:00 GMT")
  // One millisecond before the epoch belongs to the previous day, not the epoch day.
  assert_eq(http_date(-1L), "Wed, 31 Dec 1969 23:59:59 GMT")
}

///|
/// Every field is fixed-width, so a parser can index into the string: `Sun, 06 Nov 1994 08:49:37
/// GMT` is 29 characters and nothing shorter is legal.
test "http_date pads every field to the fixed width" {
  let d = http_date(1L)
  assert_eq(d.length(), 29)
  assert_eq(d, "Thu, 01 Jan 1970 00:00:00 GMT")
  // A single-digit hour, minute and second all keep their leading zero.
  assert_eq(http_date(3723000L), "Thu, 01 Jan 1970 01:02:03 GMT")
}

///|
/// The cache hands back the same second's rendering and it is a well-formed date, whatever the
/// clock happens to say when the suite runs.
test "http_date_now caches within the second and stays well-formed" {
  let a = http_date_now()
  let b = http_date_now()
  assert_eq(a, b)
  assert_eq(a.length(), 29)
  assert_eq(a[25:].to_owned(), " GMT")
}
