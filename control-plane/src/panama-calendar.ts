import type { ArcoRightType } from './types';

/**
 * Computes Easter Sunday (UTC) for a given Gregorian year using the
 * Anonymous Gregorian algorithm (Meeus/Jones/Butcher).
 */
export function computeEasterSundayUtc(year: number): Date {
  const a = year % 19;
  const b = Math.floor(year / 100);
  const c = year % 100;
  const d = Math.floor(b / 4);
  const e = b % 4;
  const f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4);
  const k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31); // 3 = March, 4 = April
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return new Date(Date.UTC(year, month - 1, day));
}

function formatUtcDateKey(date: Date): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function addUtcCalendarDays(date: Date, days: number): Date {
  const next = new Date(date.getTime());
  next.setUTCDate(next.getUTCDate() + days);
  return next;
}

/**
 * Returns the set of official Republic of Panama national holiday keys (YYYY-MM-DD)
 * for a given year:
 * - 1-Ene (Año Nuevo)
 * - 9-Ene (Día de los Mártires)
 * - Martes de Carnaval (Easter - 47 days)
 * - Viernes Santo (Easter - 2 days)
 * - 1-May (Día del Trabajo)
 * - 3-Nov (Separación de Colombia)
 * - 4-Nov (Día de los Símbolos Patrios)
 * - 5-Nov (Consolidación en Colón)
 * - 10-Nov (Primer Grito de Independencia en La Villa de Los Santos)
 * - 28-Nov (Independencia de España)
 * - 8-Dic (Día de las Madres)
 * - 20-Dic (Día de Duelo Nacional)
 * - 25-Dic (Navidad)
 */
export function getPanamaHolidaysForYear(year: number): Set<string> {
  const easter = computeEasterSundayUtc(year);
  const martesCarnaval = addUtcCalendarDays(easter, -47);
  const viernesSanto = addUtcCalendarDays(easter, -2);

  return new Set<string>([
    `${year}-01-01`,
    `${year}-01-09`,
    formatUtcDateKey(martesCarnaval),
    formatUtcDateKey(viernesSanto),
    `${year}-05-01`,
    `${year}-11-03`,
    `${year}-11-04`,
    `${year}-11-05`,
    `${year}-11-10`,
    `${year}-11-28`,
    `${year}-12-08`,
    `${year}-12-20`,
    `${year}-12-25`,
  ]);
}

const holidayCache = new Map<number, Set<string>>();

function getCachedHolidays(year: number): Set<string> {
  let set = holidayCache.get(year);
  if (!set) {
    set = getPanamaHolidaysForYear(year);
    holidayCache.set(year, set);
  }
  return set;
}

export function isPanamaBusinessDay(date: Date): boolean {
  const dow = date.getUTCDay();
  if (dow === 0 || dow === 6) {
    return false;
  }
  const key = formatUtcDateKey(date);
  return !getCachedHolidays(date.getUTCFullYear()).has(key);
}

function toDate(input: Date | string): Date {
  if (input instanceof Date) {
    return new Date(input.getTime());
  }
  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) {
    return new Date(`${input}T12:00:00.000Z`);
  }
  const parsed = new Date(input);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`Invalid date value: ${input}`);
  }
  return parsed;
}

/**
 * Adds `businessDays` Panama business days to `startDate`, skipping weekends
 * and official Panama national holidays while preserving the UTC time-of-day.
 */
export function addPanamaBusinessDays(startDate: Date | string, businessDays: number): Date {
  const start = toDate(startDate);
  if (businessDays === 0) {
    return start;
  }

  const step = businessDays > 0 ? 1 : -1;
  let remaining = Math.abs(businessDays);
  let cursor = new Date(start.getTime());

  while (remaining > 0) {
    cursor = addUtcCalendarDays(cursor, step);
    if (isPanamaBusinessDay(cursor)) {
      remaining -= 1;
    }
  }
  return cursor;
}

/**
 * Counts the signed number of Panama business days from `startDate` (exclusive)
 * to `dueDate` (inclusive). Positive when `dueDate` is in the future, 0 on the
 * same date, negative when overdue.
 */
export function businessDaysRemaining(startDate: Date | string, dueDate: Date | string): number {
  const start = toDate(startDate);
  const due = toDate(dueDate);

  const startDay = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
  const dueDay = new Date(Date.UTC(due.getUTCFullYear(), due.getUTCMonth(), due.getUTCDate()));

  if (startDay.getTime() === dueDay.getTime()) {
    return 0;
  }

  const forward = dueDay.getTime() > startDay.getTime();
  const step = forward ? 1 : -1;
  let count = 0;
  let cursor = startDay;

  while (cursor.getTime() !== dueDay.getTime()) {
    cursor = addUtcCalendarDays(cursor, step);
    if (isPanamaBusinessDay(cursor)) {
      count += step;
    }
  }
  return count;
}

/**
 * Returns the Panama Ley 81 / DE 285 SLA in business days for an ARCO right:
 * - ACCESO, PORTABILIDAD -> 10 business days
 * - RECTIFICACION, CANCELACION, OPOSICION -> 5 business days
 */
export function getDsarSlaBusinessDays(rightType: ArcoRightType): number {
  if (rightType === 'ACCESO' || rightType === 'PORTABILIDAD') {
    return 10;
  }
  return 5;
}
