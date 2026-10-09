// Exact RFC 3339 instants. No Date.parse, floating fractions or rounding.
const TIMESTAMP = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$/;

export function instantNanoseconds(value) {
  if (typeof value !== 'string') throw new TypeError('timestamp must be an RFC 3339 string');
  const match = TIMESTAMP.exec(value);
  if (!match || match[0] !== value) throw new RangeError('timestamp must have an explicit offset and at most nine fractional digits');
  const [, y, mo, d, h, mi, s, fraction = '', offset] = match;
  const [year, month, day, hour, minute, second] = [y, mo, d, h, mi, s].map(Number);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59)
    throw new RangeError('timestamp has invalid calendar or clock fields');
  const calendar = new Date(0);
  // setUTCFullYear preserves years 0000..0099; Date.UTC treats them as 1900..1999.
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(hour, minute, second, 0);
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day)
    throw new RangeError('timestamp has invalid Gregorian calendar fields');
  let offsetMinutes = 0;
  if (offset !== 'Z') {
    const offsetHour = Number(offset.slice(1, 3));
    const offsetMinute = Number(offset.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59 || offset === '-00:00')
      throw new RangeError('timestamp has an invalid or unknown offset');
    offsetMinutes = (offsetHour * 60 + offsetMinute) * (offset[0] === '+' ? 1 : -1);
  }
  const wholeMilliseconds = BigInt(calendar.getTime()) - BigInt(offsetMinutes) * 60_000n;
  return wholeMilliseconds * 1_000_000n + BigInt(fraction.padEnd(9, '0'));
}
