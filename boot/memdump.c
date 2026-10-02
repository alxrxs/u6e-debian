/* memdump <phys hex> <bytes>: copy a physical range to stdout through /dev/mem */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
int main(int argc, char **argv)
{
	unsigned long addr = strtoul(argv[1], NULL, 16), len = strtoul(argv[2], NULL, 0);
	int fd = open("/dev/mem", O_RDONLY | O_SYNC);
	void *p = fd < 0 ? MAP_FAILED : mmap(NULL, len, PROT_READ, MAP_SHARED, fd, addr);
	if (p == MAP_FAILED) { perror("memdump"); return 1; }
	return write(1, p, len) == (ssize_t)len ? 0 : 1;
}
