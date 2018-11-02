#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/random.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>

int main(int argc, char **argv)
{
	int fd = open("/dev/random", O_RDWR);

	int count = 1024;

	if (ioctl(fd, RNDADDTOENTCNT, &count) != 0) {
		printf("RNDADDENTROPY failed: %s\n",strerror(errno));
		return 1;
	}

	return 0;
}
