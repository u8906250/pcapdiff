#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h>

//#define	MATCH_PCAP_HEADER

#define GET32(buf)	((((*(buf)     )&0xff)<<24) + \
			((((*(buf))>>8 )&0xff)<<16) + \
			((((*(buf))>>16)&0xff)<< 8) + \
			((((*(buf))>>24)&0xff)))
void
dump_data(uint8_t *data, int len)
{
	int     i;
	int     j;
	int     k;
	for(i=0;i<len;i+=16) {
		printf("%8.8x ", i);
		k = len - i;
		if (k > 16)
			k = 16;
		k += i;
		for(j=i; j<(i+16); j++) {
			if (j < k)
				printf("%2.2x ", data[j] );
			else
				printf("   ");
		}
		printf("  ");
		for(j=i; j<k; j++) {
			printf("%c", isprint(data[j]) ? data[j] : '.' );
		}
		printf("\n");
	}
}

typedef struct {
	uint32_t        magic;          /* TCPDUMP_MAGIC = 0xa1b2c3d4 */
	uint16_t        version_major;  /* 2 */
	uint16_t        version_minor;  /* 4 */
	uint32_t        thiszone;       /* gmt to local correction */
	uint32_t        sigfigs;        /* accuracy of timestamps */
	uint32_t        snaplen;        /*maxlen saved portion of each pkt */
	uint32_t        linktype;       /* data link type (LINKTYPE_ * ) */
} __attribute ((packed)) pcap_file_header_t;


typedef struct {
	uint32_t        ts1;            /* time stamp */
	uint32_t        ts2;            /* time stamp */
	uint32_t        caplen;         /* length of portion present */
	uint32_t        len;            /* length this packet (off wire) */
} __attribute ((packed)) pcap_sf_pkthdr_t;

struct pfile_idx {
	pcap_sf_pkthdr_t *phdr;
	int len;
	uint8_t hit;
};

struct pfile {
	char *path;
	int fd;
	int filesize;
	void *mem;
	struct pfile_idx *pidx;
	int pidx_top;
};

static inline int
pfile_idx_match (struct pfile_idx *a, struct pfile_idx *b)
{
	if (a->len != b->len)
		return 0;
#ifdef	MATCH_PCAP_HEADER
	if (!memmem(a->phdr, a->len+sizeof(pcap_sf_pkthdr_t), b->phdr, b->len+sizeof(pcap_sf_pkthdr_t)))
		return 0;
#else
	if (!memmem((uint8_t *)a->phdr+sizeof(pcap_sf_pkthdr_t), a->len, (uint8_t *)b->phdr+sizeof(pcap_sf_pkthdr_t), b->len)) 
		return 0;
#endif
	return 1;
}

int
pfile_init(struct pfile *pf, char *path)
{
	memset (pf, 0, sizeof(struct pfile));
	pf->path = path;
	pf->fd = -1;

	struct stat st;
	if (stat(pf->path, &st) == -1 || st.st_size <= 0)
		return -1;
	pf->filesize = st.st_size;
	pf->fd = open (pf->path, O_RDONLY);
	if (pf->fd == -1) {
		printf ("ERR: %s - %s\n", pf->path, strerror(errno));
		return -1;
	}
	pf->mem = mmap (NULL, pf->filesize, PROT_READ, MAP_PRIVATE, pf->fd, 0);
	if (pf->mem == MAP_FAILED) {
		printf ("ERR: %s - %s\n", pf->path, strerror(errno));
		close (pf->fd);
		pf->fd = -1;
		return -1;
	}

	pcap_file_header_t *gphdr = (pcap_file_header_t *)pf->mem;
	if (gphdr->magic != 0xa1b2c3d4 && gphdr->magic != 0xd4c3b2a1) {
		printf ("ERR: magic %08x incorrect\n", gphdr->magic);
		munmap (pf->mem, pf->filesize);
		pf->mem = NULL;
		close (pf->fd);
		pf->fd = -1;
		return -1;
	}

	int byte_sw = (gphdr->magic == 0xa1b2c3d4) ? 0: 1;

	uint8_t *data = pf->mem + sizeof(pcap_file_header_t);
	int len = pf->filesize - sizeof(pcap_file_header_t);

	pcap_sf_pkthdr_t *phdr;
	int offset=0;
	int packet_count=0;
	while (offset < len) {
		phdr = (pcap_sf_pkthdr_t *)(data + offset);
		offset += (sizeof(pcap_sf_pkthdr_t) + (byte_sw? GET32(&phdr->len) : phdr->len));
		packet_count ++;
	}
	pf->pidx = (struct pfile_idx *)calloc(packet_count, sizeof(struct pfile_idx));
	offset = 0;
	while (offset < len) {
		phdr = (pcap_sf_pkthdr_t *)(data + offset);
		pf->pidx[pf->pidx_top].len = (byte_sw? GET32(&phdr->len) : phdr->len);
		offset += (sizeof(pcap_sf_pkthdr_t) + pf->pidx[pf->pidx_top].len);
		pf->pidx[pf->pidx_top++].phdr = phdr;
	}
	return 0;
}

void
pfile_release(struct pfile *pf)
{
	if (pf->mem) {
		munmap (pf->mem, pf->filesize);
		pf->mem = NULL;
	}
	if (pf->fd > -1) {
		close (pf->fd);
		pf->fd = -1;
	}
	if (pf->pidx)
		free (pf->pidx);
}

void
pfile_diff2file (struct pfile *pf1, struct pfile *pf2, char *out)
{
	//FIXME other magic numbers
	pcap_file_header_t pcap_header = {0xa1b2c3d4, 2, 4, 0, 0, 65535, 1};
	FILE *fp=fopen(out, "w");
	if (fp) {
		fwrite (&pcap_header, sizeof(pcap_header), 1, fp);
		int i;
		for (i=0; i<pf1->pidx_top; i++) {
			if (!pf1->pidx[i].hit) {
				fwrite (pf1->pidx[i].phdr, pf1->pidx[i].len+sizeof(pcap_sf_pkthdr_t), 1, fp);
			}
		}
		for (i=0; i<pf2->pidx_top; i++) {
			if (!pf2->pidx[i].hit) {
				fwrite (pf2->pidx[i].phdr, pf2->pidx[i].len+sizeof(pcap_sf_pkthdr_t), 1, fp);
			}
		}
		fclose (fp);
	}
}

int
pcap_diff (char *in1, char *in2, char *out)
{
	struct pfile pf1;
	struct pfile pf2;
	
	if (pfile_init(&pf1, in1) == -1) {
		return -1;
	}
	if (pfile_init(&pf2, in2) == -1) {
		pfile_release(&pf1);
		return -1;
	}
	int i,j;
	for (i=0; i<pf1.pidx_top; i++) {
		for (j=0; j<pf2.pidx_top; j++) {
			if (!pf2.pidx[j].hit && pfile_idx_match(&pf2.pidx[j], &pf1.pidx[i])) {
				pf1.pidx[i].hit ++;
				pf2.pidx[j].hit ++;
				break;
			}
		}
	}

	int pf1hit=0;
	for (i=0; i<pf1.pidx_top; i++) {
		if (!pf1.pidx[i].hit) {
			pf1hit++;

		}
	}
	int pf2hit=0;
	for (i=0; i<pf2.pidx_top; i++) {
		if (!pf2.pidx[i].hit) {
			pf2hit++;
		}
	}
	printf ("%d diffs\n", pf1hit+pf2hit);
	if (out && pf1hit+pf2hit>0) {
		pfile_diff2file(&pf1, &pf2, out);
	}

	pfile_release(&pf1);
	pfile_release(&pf2);
	return 0;
}

int
main (int argc, char *argv[])
{
	if (argc < 3) {
		printf ("%s file1 file2 [output]\n", argv[0]);
		return -1;
	}
	char *file1 = argv[1];
	char *file2 = argv[2];
	char *out = argv[3];
		
	pcap_diff(file1, file2, out);
	return 0;
}
