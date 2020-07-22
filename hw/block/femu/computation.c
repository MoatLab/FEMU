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
	uint64_t *p = (uint64_t *)buf;
	return p[0];
}
