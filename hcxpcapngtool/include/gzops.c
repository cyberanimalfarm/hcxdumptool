#include <zlib.h>

#include "gzops.h"

/*===========================================================================*/
bool testgzipfile(char *pcapinname)
{
	int pcapr_fd;
	uint32_t magicnumber;

	pcapr_fd = open(pcapinname, O_RDONLY);
	if (pcapr_fd == -1)
		return false;
	magicnumber = getmagicnumber(pcapr_fd);
	close(pcapr_fd);
#ifdef BIG_ENDIAN_HOST
	magicnumber = byte_swap_32(magicnumber);
#endif
	if ((magicnumber & 0xffff) != GZIPMAGICNUMBER)
		return false;
	if (((magicnumber >> 16) & 0xff) != DEFLATE)
		return false;
	return true;
}
/*===========================================================================*/
bool decompressgz(char *gzname, char *tmpoutname)
{
	FILE *fhin = NULL;
	FILE *fhout = NULL;
	z_stream strm;
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];

	memset(&strm, 0, sizeof(strm));
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.next_in = in;
	strm.avail_in = 0;
	inflateInit2(&strm, windowBits | ENABLE_ZLIB_GZIP);
	printf("decompressing %s to %s\n", basename(gzname), tmpoutname);
	fhin = fopen(gzname, "r");
	if (fhin == NULL)
	{
		printf("failed to decompress%s\n", gzname);
		return false;
	}

	fhout = fopen(tmpoutname, "w");
	if (fhin == NULL)
	{
		printf("failed to decompress%s\n", tmpoutname);
		return false;
	}

	while (1)
	{
		int bytes_read;
		int zlib_status;
		bytes_read = fread(in, sizeof(char), sizeof(in), fhin);
		if (ferror(fhin))
		{
			inflateEnd(&strm);
			printf("failed to decompress %s\n", gzname);
			fclose(fhout);
			fclose(fhin);
			return false;
		}
		strm.avail_in = bytes_read;
		strm.next_in = in;
		do
		{
			unsigned have;
			strm.avail_out = CHUNK;
			strm.next_out = out;
			zlib_status = inflate(&strm, Z_NO_FLUSH);
			switch (zlib_status)
			{
			case Z_OK:
			case Z_STREAM_END:
			case Z_BUF_ERROR:
				break;
			default:
				inflateEnd(&strm);
				printf("failed to decompress %s\n", gzname);
				return false;
			}
			have = CHUNK - strm.avail_out;
			fwrite(out, sizeof(unsigned char), have, fhout);
		} while (strm.avail_out == 0);
		if (feof(fhin))
		{
			inflateEnd(&strm);
			break;
		}
	}
	fclose(fhout);
	fclose(fhin);
	return true;
}
/*===========================================================================*/

int compressgz(char *sourcename, char *destname)
{
	int level = Z_DEFAULT_COMPRESSION;

	FILE *source;
	FILE *dest;
	if (source = fopen(sourcename, O_RDONLY) == NULL)
	{
		printf("failed to compress%s\n", sourcename);
		return false;
	}
	if (dest = fopen(destname, O_WRONLY) == NULL)
	{
		printf("failed to compress%s\n", sourcename);
		return false;
	}

	int ret, flush;
	unsigned have;
	z_stream strm;
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];

	/* allocate deflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	ret = deflateInit(&strm, level);
	if (ret != Z_OK)
		fclose(source);
		fclose(dest);
		printf("failed to compress%s\n", sourcename);
		return false;

	/* compress until end of file */
	do
	{
		strm.avail_in = fread(in, 1, CHUNK, source);
		if (ferror(source))
		{
			(void)deflateEnd(&strm);
			fclose(source);
			fclose(dest);
			printf("failed to compress%s\n", sourcename);
			return false;
		}
		flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
		strm.next_in = in;

		/* run deflate() on input until output buffer not full, finish
		   compression if all of source has been read in */
		do
		{
			strm.avail_out = CHUNK;
			strm.next_out = out;
			ret = deflate(&strm, flush);   /* no bad return value */
			assert(ret != Z_STREAM_ERROR); /* state not clobbered */
			have = CHUNK - strm.avail_out;
			if (fwrite(out, 1, have, dest) != have || ferror(dest))
			{
				(void)deflateEnd(&strm);
				fclose(source);
				fclose(dest);
				printf("failed to compress%s\n", sourcename);
				return false;
			}
		} while (strm.avail_out == 0);
		assert(strm.avail_in == 0); /* all input will be used */

		/* done when last data in file processed */
	} while (flush != Z_FINISH);
	assert(ret == Z_STREAM_END); /* stream will be complete */

	/* clean up and return */
	(void)deflateEnd(&strm);
	fclose(source);
	fclose(dest);
	return true;
}