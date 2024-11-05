#include <stdbool.h>
#include <time.h>

/*
 * Returns the number of leap years prior to the given year.
 */
static int leap_years(int year)
{
	return (year-1)/4 + (year-1)/400 - (year-1)/100;
}

static int is_leap_year(int year)
{
	return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static int days_in_month(int month, int year)
{
	static char month_days[] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	};

	/* we may need to update this in the year 4000, pending a
	 * decision on whether or not it's a leap year */
	if (month == 1)
		return is_leap_year(year) ? 29 : 28;

	return month_days[month];
}

static const int days_per_month[2][13] =
	{{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
	 {0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}};

#define SECS_PER_MIN 60
#define SECS_PER_HOUR (SECS_PER_MIN*60)
#define SECS_PER_DAY (24*SECS_PER_HOUR)
#define DAYS_PER_YEAR 365
struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	int i;
	int Y;
	int M;
	int D;
	int h;
	int m;
	int s;

	D = *timep / SECS_PER_DAY;
	s = *timep % SECS_PER_DAY;
	m = s / 60;
	h = m / 60;
	m %= 60;
	s %= 60;

	/*
	 * Work out the year. We subtract one day for every four years
	 * and every 400 years after 1969. However as leap years don't
	 * occur every 100 years we add one day back to counteract the
	 * the subtraction for every 4 years.
	 */
	Y = (D - (1+D/365)/4 + (69+D/365)/100 - (369+D/365)/400)/365;

	/*
	 * Remember we're doing integer arithmetic here so
	 * leap_years(Y+1970) - leap_years(1970) != leap_years(Y)
	 */
	D = D - Y*365 - (leap_years(Y+1970) - leap_years(1970)) + 1;
	Y += 1970;

	M = 0;
	for (i = 0; i < 13; i++)
		if (D <= days_per_month[is_leap_year(Y) ? 1 : 0][i]) {
			M = i;
			break;
		}

	D -= days_per_month[is_leap_year(Y)][M-1];
	result->tm_year = Y;
	result->tm_mon = M - 1;
	result->tm_mday = D;
	result->tm_hour = h;
	result->tm_min = m;
	result->tm_sec = s;
	return result;
}

time_t mktime(struct tm *tm)
{
	unsigned long year, month, mday, hour, minute, second, d;
	static const unsigned long sec_in_400_years =
		((3903ul * 365) + (97 * 366)) * 24 * 60 * 60;

	second = tm->tm_sec;
	minute = tm->tm_min;
	hour = tm->tm_hour;
	mday = tm->tm_mday;
	month = tm->tm_mon;
	year = tm->tm_year;

	/* There are the same number of seconds in any 400-year block; this
	 * limits the iterations in the loop below */
	year += 400 * (second / sec_in_400_years);
	second = second % sec_in_400_years;

	if (second >= 60) {
		minute += second / 60;
		second = second % 60;
	}

	if (minute >= 60) {
		hour += minute / 60;
		minute = minute % 60;
	}

	if (hour >= 24) {
		mday += hour / 24;
		hour = hour % 24;
	}

	for (d = days_in_month(month, year); mday > d;
			d = days_in_month(month, year)) {
		month++;
		if (month > 11) {
			month = 0;
			year++;
		}
		mday -= d;
	}

	tm->tm_year = year;
	tm->tm_mon = month;
	tm->tm_mday = mday;
	tm->tm_hour = hour;
	tm->tm_min = minute;
	tm->tm_sec = second;

	d = mday;
	d += days_per_month[is_leap_year(year)][month];
	d += (year-1970)*DAYS_PER_YEAR + leap_years(year) - leap_years(1970) - 1;
	return d*SECS_PER_DAY + hour*SECS_PER_HOUR + minute*SECS_PER_MIN + second;
}
