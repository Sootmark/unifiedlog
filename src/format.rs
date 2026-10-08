//! Formatting a message: the format string's conversions filled with the
//! entry's items, the way `printf` does, with Apple's additions.
//!
//! A conversion is `%`, an optional annotation in braces (`{public}`,
//! `{private}`, or a decoder such as `{bool}`, `{time_t}`,
//! `{network:in_addr}`), flags (`-+ #0'`), a width and a precision
//! (digits, or `*` to take them from an item), a length (`hh h l ll q j z
//! t L`), and a conversion character. Each conversion takes the next item;
//! a precision item before a value that does not ask for one is skipped.
//!
//! Values the system did not record show as `<private>`, conversions with
//! no item left as `<Missing message data>`, and NULL strings as `(null)`.

use crate::decoders;
use crate::items::{Item, Value};
use crate::text::base64;

/// What a conversion with no item left shows.
pub const MISSING: &str = "<Missing message data>";
/// What a value the system did not record shows.
pub const PRIVATE: &str = "<private>";

/// Fills a format string's conversions with items.
#[must_use]
pub fn format(format: &str, items: &[Item]) -> String {
    if format.is_empty() {
        return items.first().map(plain).unwrap_or_default();
    }
    let mut out = String::with_capacity(format.len());
    let mut items = items.iter().peekable();
    let mut rest = format;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if let Some((spec, used)) = Spec::parse(after) {
            out.push_str(&spec.render(&rest[at..=at + used], &mut items));
            rest = &after[used..];
        } else {
            out.push('%');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// An item shown with no conversion to guide it.
fn plain(item: &Item) -> String {
    let spec = Spec {
        conversion: 's',
        ..Spec::default()
    };
    spec.value(item)
}

/// A conversion, as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Spec<'a> {
    /// The annotation between the braces, when there is one.
    annotation: Option<&'a str>,
    /// `-`: padding goes on the right.
    left: bool,
    /// `+` or ` `: what a non-negative number starts with.
    sign: Sign,
    /// `#`: `0x` before hex digits, `0` before octal ones.
    alternate: bool,
    /// `0`: numbers padded with zeros rather than spaces.
    zero: bool,
    /// The least characters to write.
    width: Count,
    /// For numbers, the least digits; for floats, the digits after the
    /// point.
    precision: Option<Count>,
    /// The bytes an integer is cast to (`hh` 1, `h` 2), when narrower than
    /// the item.
    cast: Option<u8>,
    /// The conversion character (`%` for `%%`, `}` for an annotation alone).
    conversion: char,
}

/// What a non-negative number starts with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Sign {
    /// Nothing.
    #[default]
    None,
    /// `+`.
    Plus,
    /// A space.
    Space,
}

impl Sign {
    fn text(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Plus => "+",
            Self::Space => " ",
        }
    }
}

/// A width or precision: written, or taken from an item (`*`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Count {
    #[default]
    None,
    Fixed(usize),
    FromItem,
}

/// The largest width or precision applied.
const MAX_COUNT: usize = 4096;
/// The conversion characters.
const CONVERSIONS: &str = "cmCdiouxXeEfFgGaAnpsSZP@DOU";
/// The length modifiers' characters.
const LENGTHS: &str = "hlqjztLwI0123456";

impl<'a> Spec<'a> {
    /// A conversion from the text after its `%`, and how many bytes it
    /// takes; `None` when it is not one (the `%` is then text).
    fn parse(text: &'a str) -> Option<(Self, usize)> {
        let mut spec = Spec::default();
        let bytes = text.as_bytes();
        let mut at = 0;
        if bytes.first() == Some(&b'%') {
            spec.conversion = '%';
            return Some((spec, 1));
        }
        if bytes.first() == Some(&b' ') {
            return None;
        }
        if bytes.first() == Some(&b'{') {
            let close = text.find('}')?;
            spec.annotation = Some(&text[1..close]);
            at = close + 1;
        }
        at += spec.parse_flags(&bytes[at..]);
        let (width, used) = parse_count(&bytes[at..]);
        spec.width = width;
        at += used;
        if bytes.get(at) == Some(&b'.') {
            let (precision, used) = parse_count(&bytes[at + 1..]);
            spec.precision = Some(match precision {
                Count::None => Count::Fixed(0),
                other => other,
            });
            at += 1 + used;
        }
        let lengths = bytes[at..]
            .iter()
            .take_while(|b| LENGTHS.as_bytes().contains(b))
            .count();
        spec.cast = match &bytes[at..at + lengths] {
            b"hh" => Some(1),
            b"h" => Some(2),
            _ => None,
        };
        at += lengths;
        match bytes.get(at) {
            Some(&c) if CONVERSIONS.as_bytes().contains(&c) => {
                spec.conversion = char::from(c);
                Some((spec, at + 1))
            }
            // An annotation alone (`%{public}` before another `%`) is text.
            _ if spec.annotation.is_some() => {
                spec.conversion = '}';
                Some((spec, text.find('}')? + 1))
            }
            _ => None,
        }
    }

    fn parse_flags(&mut self, bytes: &[u8]) -> usize {
        let mut used = 0;
        for &b in bytes {
            match b {
                b'-' => self.left = true,
                b'+' => self.sign = Sign::Plus,
                b' ' if self.sign == Sign::None => self.sign = Sign::Space,
                b'#' => self.alternate = true,
                b'0' => self.zero = true,
                b'\'' => {}
                _ => break,
            }
            used += 1;
        }
        used
    }

    /// The conversion's text, taking the items it needs.
    fn render<'i>(
        mut self,
        written: &str,
        items: &mut std::iter::Peekable<impl Iterator<Item = &'i Item>>,
    ) -> String {
        match self.conversion {
            '%' => return "%".to_owned(),
            '}' => return written.to_owned(),
            _ => {}
        }
        if self.width == Count::FromItem {
            self.width = match items.next() {
                Some(item) => self.width_from(item),
                None => return MISSING.to_owned(),
            };
        }
        if self.precision == Some(Count::FromItem) {
            self.precision = match items.next() {
                Some(item) => precision_from(item),
                None => return MISSING.to_owned(),
            };
        } else if items
            .peek()
            .is_some_and(|i| matches!(i.value, Value::Count(_)))
        {
            items.next();
        }
        match items.next() {
            Some(item) => self.value(item),
            None => MISSING.to_owned(),
        }
    }

    /// A width from an item: a negative one left-justifies.
    fn width_from(&mut self, item: &Item) -> Count {
        let width = count_of(item).unwrap_or(0);
        if width < 0 {
            self.left = true;
        }
        Count::Fixed(capped(width.unsigned_abs()))
    }

    /// An item's text for this conversion.
    fn value(&self, item: &Item) -> String {
        if item.value == Value::Private {
            return PRIVATE.to_owned();
        }
        if let Some(decoded) = self
            .annotation
            .and_then(|annotation| decoders::decode(annotation, item))
        {
            return decoded;
        }
        let text = match &item.value {
            Value::Number { bits, size } => self.number(*bits, *size),
            Value::Count(n) => self.number(*n, 8),
            // A string's precision limited what the system copied, so it is
            // not applied again (Apple's tools show `%.s` whole).
            Value::Text(text) => text.clone(),
            Value::Bytes(bytes) if self.conversion == 'P' => hex_bytes(bytes),
            Value::Bytes(bytes) => base64(bytes),
            Value::Null => "(null)".to_owned(),
            Value::Private => PRIVATE.to_owned(),
        };
        self.pad(text)
    }

    fn number(&self, bits: u64, size: u8) -> String {
        let size = match self.cast {
            Some(cast) if !is_float(self.conversion) => cast.min(size),
            _ => size,
        };
        let unsigned = truncate(bits, size);
        match self.conversion {
            'd' | 'i' | 'D' => self.signed(sign_extend(unsigned, size)),
            'u' | 'U' => self.digits(unsigned.to_string(), ""),
            'x' => self.digits(format!("{unsigned:x}"), self.prefix(unsigned, "0x")),
            'X' => self.digits(format!("{unsigned:X}"), self.prefix(unsigned, "0X")),
            'o' | 'O' => self.digits(format!("{unsigned:o}"), self.prefix(unsigned, "0")),
            'p' => format!("0x{unsigned:x}"),
            'c' => char::from(unsigned as u8).to_string(),
            'C' => char::from_u32(unsigned as u32).map_or_else(String::new, String::from),
            c if is_float(c) => self.float(as_float(unsigned, size)),
            'm' => decoders::strerror(sign_extend(unsigned, size)),
            _ => sign_extend(unsigned, size).to_string(),
        }
    }

    fn prefix(&self, value: u64, prefix: &'static str) -> &'static str {
        if self.alternate && value != 0 {
            prefix
        } else {
            ""
        }
    }

    fn signed(&self, value: i64) -> String {
        let sign = if value < 0 { "-" } else { self.sign.text() };
        self.digits(value.unsigned_abs().to_string(), sign)
    }

    /// Digits with the precision's minimum count, a sign or prefix, and
    /// zero padding to the width when asked.
    fn digits(&self, digits: String, prefix: &str) -> String {
        let digits = match self.precision {
            // Zero with a precision of zero is no digits at all.
            Some(Count::Fixed(0)) if digits == "0" => String::new(),
            Some(Count::Fixed(min)) if digits.len() < min => {
                format!("{}{digits}", "0".repeat(min - digits.len()))
            }
            _ => digits,
        };
        let zero_pad = self.zero && !self.left && self.precision.is_none();
        match self.width {
            Count::Fixed(width) if zero_pad && prefix.len() + digits.len() < width => {
                let zeros = "0".repeat(width - prefix.len() - digits.len());
                format!("{prefix}{zeros}{digits}")
            }
            _ => format!("{prefix}{digits}"),
        }
    }

    fn float(&self, value: f64) -> String {
        let precision = match self.precision {
            Some(Count::Fixed(p)) => p,
            _ => 6,
        };
        let text = match self.conversion {
            'e' | 'E' => exponent(value, precision),
            'g' | 'G' => general(value, precision, self.alternate),
            'a' | 'A' => format!("{value:e}"),
            _ if !value.is_finite() => non_finite(value),
            _ => format!("{value:.precision$}"),
        };
        let text = if self.conversion.is_ascii_uppercase() {
            text.to_uppercase()
        } else {
            text
        };
        let (sign, digits) = match text.strip_prefix('-') {
            Some(digits) => ("-", digits.to_owned()),
            None => (self.sign.text(), text),
        };
        let zero_pad = self.zero && !self.left && value.is_finite();
        match self.width {
            Count::Fixed(width) if zero_pad && sign.len() + digits.len() < width => {
                format!(
                    "{sign}{}{digits}",
                    "0".repeat(width - sign.len() - digits.len())
                )
            }
            _ => format!("{sign}{digits}"),
        }
    }

    /// Spaces to the width.
    fn pad(&self, text: String) -> String {
        let Count::Fixed(width) = self.width else {
            return text;
        };
        let length = text.chars().count();
        if length >= width {
            return text;
        }
        let spaces = " ".repeat(width - length);
        if self.left {
            text + &spaces
        } else {
            spaces + &text
        }
    }
}

/// Raw data as `%P` shows it: hex bytes in quotes (`'03 80 22'`).
fn hex_bytes(bytes: &[u8]) -> String {
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!("'{}'", hex.join(" "))
}

/// Whether a conversion is a floating point one.
fn is_float(conversion: char) -> bool {
    matches!(conversion, 'e' | 'E' | 'f' | 'F' | 'g' | 'G' | 'a' | 'A')
}

/// A precision from an item; a negative one is as if there were none.
fn precision_from(item: &Item) -> Option<Count> {
    let precision = count_of(item).unwrap_or(0);
    (precision >= 0).then(|| Count::Fixed(capped(precision.unsigned_abs())))
}

/// A width or precision written after `%`, or `*`.
fn parse_count(bytes: &[u8]) -> (Count, usize) {
    if bytes.first() == Some(&b'*') {
        return (Count::FromItem, 1);
    }
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return (Count::None, 0);
    }
    let value = bytes[..digits].iter().fold(0u64, |n, &d| {
        n.saturating_mul(10).saturating_add(u64::from(d - b'0'))
    });
    (Count::Fixed(capped(value)), digits)
}

/// A width or precision, at most [`MAX_COUNT`]: a damaged one must not
/// ask for gigabytes of padding.
fn capped(count: u64) -> usize {
    count.min(MAX_COUNT as u64) as usize
}

/// An item's value as a width or precision.
fn count_of(item: &Item) -> Option<i64> {
    match item.value {
        Value::Count(n) => Some(n as i64),
        Value::Number { bits, size } => Some(sign_extend(truncate(bits, size), size)),
        _ => None,
    }
}

/// The low `size` bytes.
fn truncate(bits: u64, size: u8) -> u64 {
    match size {
        1..=7 => bits & ((1u64 << (u32::from(size) * 8)) - 1),
        _ => bits,
    }
}

/// A `size`-byte value as signed.
fn sign_extend(bits: u64, size: u8) -> i64 {
    match size {
        1..=7 => {
            let shift = 64 - u32::from(size) * 8;
            ((bits << shift) as i64) >> shift
        }
        _ => bits as i64,
    }
}

/// A float from its bits: 4 bytes are a `float`, others a `double`.
fn as_float(bits: u64, size: u8) -> f64 {
    if size == 4 {
        f64::from(f32::from_bits(bits as u32))
    } else {
        f64::from_bits(bits)
    }
}

/// `%e`: one digit, the fraction, and a signed exponent of two digits or
/// more.
fn exponent(value: f64, precision: usize) -> String {
    if !value.is_finite() {
        return non_finite(value);
    }
    let text = format!("{value:.precision$e}");
    let (mantissa, exp) = text.split_once('e').unwrap_or((&text, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exp.unsigned_abs())
}

/// `%g`: `%e` or `%f`, whichever suits the exponent, without trailing
/// zeros unless `#`.
fn general(value: f64, precision: usize, alternate: bool) -> String {
    if !value.is_finite() {
        return non_finite(value);
    }
    let precision = precision.max(1);
    let exp = if value == 0.0 {
        0
    } else {
        let text = format!("{value:.e$e}", e = precision - 1);
        text.split_once('e')
            .and_then(|(_, e)| e.parse::<i64>().ok())
            .unwrap_or(0)
    };
    let text = if exp < -4 || exp >= precision as i64 {
        exponent(value, precision - 1)
    } else {
        let decimals = (precision as i64 - 1 - exp).max(0) as usize;
        format!("{value:.decimals$}")
    };
    if alternate {
        return text;
    }
    match text.split_once('e') {
        Some((mantissa, exp)) => format!("{}e{exp}", trim_zeros(mantissa)),
        None => trim_zeros(&text).to_owned(),
    }
}

fn trim_zeros(number: &str) -> &str {
    if number.contains('.') {
        number.trim_end_matches('0').trim_end_matches('.')
    } else {
        number
    }
}

fn non_finite(value: f64) -> String {
    if value.is_nan() {
        "nan".to_owned()
    } else if value < 0.0 {
        "-inf".to_owned()
    } else {
        "inf".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(bits: u64, size: u8) -> Item {
        Item {
            kind: 0x02,
            value: Value::Number { bits, size },
        }
    }

    fn text(text: &str) -> Item {
        Item {
            kind: 0x22,
            value: Value::Text(text.to_owned()),
        }
    }

    fn private() -> Item {
        Item {
            kind: 0x21,
            value: Value::Private,
        }
    }

    #[test]
    fn integers() {
        let items = [
            number(0xffff_ffff, 4),
            number(0xffff_ffff, 4),
            number(255, 8),
        ];
        assert_eq!(format("%d %u %x", &items), "-1 4294967295 ff");
        assert_eq!(
            format(
                "%#x %#o %X",
                &[number(255, 4), number(8, 4), number(171, 4)]
            ),
            "0xff 010 AB"
        );
        assert_eq!(
            format(
                "[%5d|%-5d|%05d]",
                &[number(42, 4), number(42, 4), number(42, 4)]
            ),
            "[   42|42   |00042]"
        );
        assert_eq!(
            format(
                "%+d %.3d %lld",
                &[number(5, 4), number(7, 4), number(u64::MAX, 8)]
            ),
            "+5 007 -1"
        );
        assert_eq!(
            format("%p %c", &[number(0x1000, 8), number(65, 1)]),
            "0x1000 A"
        );
    }

    #[test]
    fn strings_and_annotations() {
        let items = [text("one"), private(), text("three")];
        assert_eq!(
            format("%s %{private}s %{public}@!", &items),
            "one <private> three!"
        );
        assert_eq!(
            format("[%-6s|%6s|%.2s]", &[text("ab"), text("ab"), text("abc")]),
            "[ab    |    ab|abc]"
        );
        assert_eq!(
            format(
                "%s",
                &[Item {
                    kind: 0x40,
                    value: Value::Null
                }]
            ),
            "(null)"
        );
    }

    #[test]
    fn missing_items_and_percent() {
        assert_eq!(
            format("%d%% of %s", &[number(50, 4)]),
            "50% of <Missing message data>"
        );
        assert_eq!(format("100% sure", &[]), "100% sure");
        assert_eq!(format("%{public}%s", &[text("x")]), "%{public}x");
    }

    #[test]
    fn widths_and_precisions_from_items() {
        let count = Item {
            kind: 0x12,
            value: Value::Count(3),
        };
        assert_eq!(format("%.*s", &[count.clone(), text("abc")]), "abc");
        assert_eq!(format("%*d", &[number(4, 4), number(7, 4)]), "   7");
        assert_eq!(
            format("%s", &[count, text("skip the count")]),
            "skip the count"
        );
    }

    #[test]
    fn floats() {
        let half = 0.5f64.to_bits();
        assert_eq!(format("%f", &[number(half, 8)]), "0.500000");
        assert_eq!(
            format("%.2f %.f", &[number(half, 8), number(2.5f64.to_bits(), 8)]),
            "0.50 2"
        );
        assert_eq!(
            format("%e", &[number(1234.5f64.to_bits(), 8)]),
            "1.234500e+03"
        );
        assert_eq!(
            format("%g %g", &[number(half, 8), number(1e-5f64.to_bits(), 8)]),
            "0.5 1e-05"
        );
        assert_eq!(
            format("%g", &[number(100_000.0_f64.to_bits(), 8)]),
            "100000"
        );
        assert_eq!(
            format("%g", &[number(1_234_567.0_f64.to_bits(), 8)]),
            "1.23457e+06"
        );
    }

    #[test]
    fn empty_format_shows_the_first_item() {
        assert_eq!(format("", &[text("only")]), "only");
        assert_eq!(format("", &[]), "");
    }
}
