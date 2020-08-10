#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <sys/stat.h>
#include <tomcrypt.h>
#include <tommath.h>


#define PORT 1234    /* the port client will be connecting to */

#define MAXDATASIZE 128 /* max number of bytes we can get at once */

rsa_key pubkey,prikey;
int prng_idx,hash_idx;

void hexdump_memory(unsigned char *buf, size_t byte_count) {
  unsigned long byte_offset_start = 0;
  if (byte_count % 16)
    printf("hexdump_memory called with non-full line\n");
  for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
          byte_offset += 16) {
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      linep += sprintf(linep, "%02hhx ", (unsigned char)buf[byte_offset + i]);
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<16; i++) {
      char c = buf[byte_offset + i];
      if (isalnum(c) || ispunct(c) || c == ' ') {
        *(linep++) = c;
      } else {
        *(linep++) = '.';
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }
}


uint32_t read_file(void **buf, const char *path)
{
	FILE *fptr = fopen(path, "rb");
	struct stat st;
	uint32_t size_file;
	uint32_t size_buf;
	uint32_t res;
	
	if (!fptr)
	{
		printf("No such file or dir\n");
		return 0;
	}
	stat(path, &st);
	size_file = st.st_size;
	size_buf = size_file+((16-(size_file%16))%16);
	*buf = malloc(size_buf);
	memset(*buf, 0, size_buf);
	res = fread(*buf, 1, size_file, fptr);
	fclose(fptr);
	if(res != size_file)
	{
		printf("Error in read file\n");
		return res;
	}
	//hexdump_memory(*buf, size_buf);
	return size_buf;
}


static void prepare_keys(){
	unsigned char* pubkeybuffer,*prikeybuffer;
	unsigned long pubkeybuffersize, prikeybuffersize;
	int err, n;
	pubkeybuffersize = read_file(&pubkeybuffer, "public.der");
	prikeybuffersize = read_file(&prikeybuffer, "private.der");
	err = rsa_import(pubkeybuffer, pubkeybuffersize, &pubkey);
	if (err != CRYPT_OK)
	{
		printf("rsa_import err:%s\n", error_to_string(err));
		return;
	}
	n = rsa_get_size(&pubkey);
	printf("pubkeysize = %d\n",n);
	 // Import from the secret key string to become rsa_key decryption use
	err = rsa_import(prikeybuffer, prikeybuffersize, &prikey);
	if (err != CRYPT_OK)
	{
		printf("rsa_import err:%s\n", error_to_string(err));
		return;
	}
	n = rsa_get_size(&prikey);
	if (n < 0)
	{
		printf("rsa_get_size err:%s\n", error_to_string(err));
		return;
	}
	printf("prikeysize = %d\n",n);
	free(pubkeybuffer);
	free(prikeybuffer);
}


int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char *buf;
	struct hostent *he;
	struct sockaddr_in their_addr; /* connector's address information */

	if (argc != 2) {
		fprintf(stderr,"usage: client hostname\n");
		exit(1);
	}

	if ((he=gethostbyname(argv[1])) == NULL) {  /* get the host info */
		herror("gethostbyname");
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	their_addr.sin_family = AF_INET;      /* host byte order */
	their_addr.sin_port = htons(PORT);    /* short, network byte order */
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	bzero(&(their_addr.sin_zero), 8);     /* zero the rest of the struct */

	if (connect(sockfd, (struct sockaddr *)&their_addr, \
										  sizeof(struct sockaddr)) == -1) {
		perror("connect");
		exit(1);
	}
	char* out_buf = malloc(128);
	unsigned long out_len;
	int stat;
	memset(out_buf, 0, 128);
	
	buf = malloc(128);
	memset(buf,0,128);
	// Bind the math library
	ltc_mp = ltm_desc;
	// Register random number generator
	register_prng(&sprng_desc);
	prng_idx = find_prng("sprng");
	// Register the hash operation library
	register_hash(&sha1_desc);
	hash_idx = find_hash("sha1");	
	prepare_keys();
	
	if (send(sockfd, "Hello\n", 6, 0) == -1){
		perror("send");
		exit(1);
	}
	if ((numbytes=recv(sockfd, buf, 6, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	buf[numbytes] = '\0';
	printf("Received text=: %s \n", buf);
	if ((numbytes=recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	printf("----------------------------------------------------------------------------\n");
	hexdump_memory(buf,128);
	printf("----------------------------------------------------------------------------\n");

    char *id =malloc(128);
	rsa_decrypt_key_ex(buf, 128, id, &out_len, (const unsigned char*)"UnicornCTF2020", 14, 
			hash_idx, LTC_PKCS_1_V1_5, &stat, &prikey);
	if(stat){
		id[out_len]='\0';
		printf("Success decrypt, id is %s\n",id);
	}
	char* data = malloc(0x10);
	strcpy(data,"Hello\n");
	out_len = 128;
	int result = rsa_encrypt_key_ex(data, 6, out_buf, &out_len, (const unsigned char*)"UnicornCTF2020", 14, NULL, 
		prng_idx, hash_idx, LTC_PKCS_1_V1_5, &pubkey);
	if(result){
		printf("Something went wrong, result %d\n",result);
	}
	printf("Ok\n");
	printf("----------------------------------------------------------------------------\n");
	hexdump_memory(out_buf,128);
	printf("----------------------------------------------------------------------------\n");
	if (send(sockfd, out_buf, 128, 0) == -1){
		perror("send");
		exit(1);
	}
	printf("Ok, sended\n");
	if ((numbytes=recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	if ((numbytes=recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	buf[numbytes]='\0';
	printf(buf,id);
	printf("\n");
	close(sockfd);

	return 0;
}