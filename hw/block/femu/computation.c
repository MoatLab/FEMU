int count_bits(char *buf)
{
        int i, j;
        char c;
        int count =0;

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

int get_disk_pointer(char *buf)
{
	int *p = buf;
	return p[0];
}

void inline add_delay(uint32_t micro_seconds) {
	unsigned long long current_time, req_time;
	current_time = cpu_get_host_ticks();
	req_time = current_time + (micro_seconds);
	while( cpu_get_host_ticks()  < req_time);
}
