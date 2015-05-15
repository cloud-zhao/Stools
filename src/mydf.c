#include <stdio.h>
#include <stdlib.h>
#include <sys/statfs.h>

int main(int argc,char *argv[]){
        unsigned long long free_disk=0;
        unsigned long long total_disk=0;
	float free_rate=0;
        struct statfs disk_info;

        if(argc != 2){
                printf("Error:Parameters defect\n");
		exit(1);
	}

        if(statfs(argv[1],&disk_info)>=0){
                free_disk=((unsigned long long)disk_info.f_bfree * (unsigned long long)disk_info.f_bsize)/(unsigned long long)1024;
                total_disk=((unsigned long long)disk_info.f_blocks * (unsigned long long)disk_info.f_bsize)/(unsigned long long)1024;
/*                printf("%llu\t\t%llu\n",free_disk,total_disk); */
		free_rate=((float)free_disk/(float)total_disk)*(float)100;
		printf("Disk free rate:%0.1f\n",free_rate);
        }
	exit(0);
}
