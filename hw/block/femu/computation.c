uint64_t count_bits(char *buf)
{
        int i, j;
        char c;
        uint64_t count =0;

        for (i = 0 ; i < 4096 ; i++) {
                c = buf[i];
                for (j = 0 ; j < 8 ; j++) {
                        if (c & (1 << j)) {
                                count +=  1;
                        }
                }
        }
        return count;
}

uint64_t get_disk_pointer(char *buf)
{
	uint64_t *p = buf;
	return p[0];
}

// we use rdtsc based delay instead of usleep() or delay()
void inline add_delay(unsigned long long t)
{
	unsigned long long current_time, req_time;
	current_time = cpu_get_host_ticks();
	req_time = current_time + t;
	while( cpu_get_host_ticks()  < req_time);
}
