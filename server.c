#define _POSIX_SOURCE

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#define MAX_FILE_SIZ 512 /* in KiB */
#define MAX_FILES 1000
#define PORT 81

#define DEBUG 1

#define GET 1
#define POST 2
#define HEAD 3
#define PUT 4
#define DELETE 5
#define BIG_BUF_SIZ (1024 + MAX_FILE_SIZ * 1024)

typedef struct __file_info_ {
	unsigned int id;
	unsigned int len;
	void * data;
} file_info;

file_info ring[MAX_FILES];
static unsigned int ring_pos = 0;
static unsigned int ring_files = 0;
static unsigned int current_bytes = 0;
static unsigned int last_id;

static void init_id(){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	last_id = (unsigned int)(tv.tv_usec);
	if(last_id == 0)
		last_id = 1;
}

static unsigned int new_id(){
	last_id++;
	if(last_id < 1)
		last_id = 1;
	return last_id;
}

static void save_file(const file_info * fi){
	if(ring_files < MAX_FILES){
		ring[ring_pos].id = fi->id;
		ring[ring_pos].len = fi->len;
		ring[ring_pos].data = fi->data;
		current_bytes += fi->len;
		++ring_files;
	}else{
		current_bytes -= ring[ring_pos].len;
		free(ring[ring_pos].data);
		ring[ring_pos].id = fi->id;
		ring[ring_pos].len = fi->len;
		ring[ring_pos].data = fi->data;
		current_bytes += fi->len;
	}
	ring_pos++;
	ring_pos %= MAX_FILES;

	/* print memory used */
	if(current_bytes > 4194304){
		printf("Mem.Used: %u MiB across %u files;", current_bytes / 10488576, ring_files);
	}else
		if(current_bytes > 4096)
			printf("Mem.Used: %u KiB across %u files;", current_bytes / 1024, ring_files);
		else
			printf("Mem.Used: %u bytes across %u files;", current_bytes, ring_files);

	unsigned int avg_bytes = current_bytes / ring_files;
	if(avg_bytes > 4194304){
		printf(" Avg.Size: %u MiB\n", avg_bytes / 10488576);
	}else
		if(avg_bytes > 4096)
			printf(" Avg.Size: %u KiB\n", avg_bytes / 1024);
		else
			printf(" Avg.Size: %u bytes\n", avg_bytes);
}

static const file_info * find_file(unsigned int id, unsigned int l, unsigned int r){
	if(r <= l)
		return NULL;
	unsigned int m = (l + r) / 2;
	if(ring[m].id == id)
		return &ring[m];
	if(ring[m].id < id)
		return find_file(id, m + 1, r);
	return find_file(id, l, m);
}

static const file_info * get_file(unsigned int id){
	if(ring_files == 0)
		return NULL;
	if(ring_files < MAX_FILES)
		return find_file(id, 0, ring_pos);
	else{
		const file_info * ret = find_file(id, 0, ring_pos);
		if(ret == NULL)
			return find_file(id, ring_pos, MAX_FILES);
	}
	return NULL;
}

static unsigned int copy_while_alphanumeric(char * src, char * dst, unsigned int dst_siz){
	unsigned int ret = 0;
	while(ret < dst_siz - 1 && src[ret] != 0){
		if((src[ret] >= '0' && src[ret] <= '9') || (src[ret] >= 'a' && src[ret] <= 'z') || (src[ret] >= 'A' && src[ret] <= 'Z') || src[ret] == '/'){
			dst[ret] = src[ret];
			++ret;
		}else
			break;
	}
	dst[ret] = 0;
	return ret;
}

static unsigned int copy_while_numeric(char * src, char * dst, unsigned int dst_siz){
	unsigned int ret = 0;
	while(ret < dst_siz - 1 && src[ret] != 0){
		if(src[ret] >= '0' && src[ret] <= '9'){
			dst[ret] = src[ret];
			++ret;
		}else
			break;
	}
	dst[ret] = 0;
	return ret;
}

static void parse(char * buffer, char * request_method, char * request_method_str, char * request_uri, unsigned int uri_sz){
	unsigned int i = 0;
	while(i < 9 && buffer[i] != ' '){
		request_method_str[i] = buffer[i];
		++i;
	}
	request_method_str[i] = 0;
	
	if(strcmp(request_method_str, "GET") == 0)
		*request_method = GET;
	else
		if(strcmp(request_method_str, "HEAD") == 0)
			*request_method = HEAD;
		else
			if(strcmp(request_method_str, "POST") == 0)
				*request_method = POST;
			else	
				if(strcmp(request_method_str, "PUT") == 0)
					*request_method = PUT;
				else	
					if(strcmp(request_method_str, "DELETE") == 0)
						*request_method = DELETE;
					else
						*request_method = 0;	

	buffer += i + 1;
	copy_while_alphanumeric(buffer, request_uri, uri_sz);
}

static file_info * load_file(const char * filename){
	char buffer[8 * 1024];
	FILE * f = fopen(filename, "r");
	unsigned int size = 0;
	int r;
	while((r = fread(buffer, 1, 8 * 1024 - size, f)) > 0)
		size += r;
	fclose(f);
	file_info * ret = (file_info *)malloc(sizeof(file_info));
	ret->id = 0;
	ret->len = size;
	ret->data = malloc(ret->len);
	memcpy(ret->data, buffer, ret->len);
	return ret;
}

static void full_write(int socket, char * buffer, unsigned int size){
	int w;
	while((w = write(socket, buffer, size)) > 0){
		buffer += w;
		size -= w;
	}
}

static void return_msg(int code, char * text, const char * msg, int socket){
	char buffer[2048];
	snprintf(buffer, 2048, "HTTP/1.0 %d %s\nContent-Length: %lu\nServer: myn3\r\n\r\n%s", code, text, strlen(msg), msg);
	full_write(socket, buffer, strlen(buffer));
	printf("%d %s %s\n", code, text, msg);
}

static void return_file(int code, char * text, const file_info * fi, int socket){
	char buffer[1024];
	snprintf(buffer, 1024, "HTTP/1.0 %d %s\nContent-Length: %u\nServer: myn3\r\n\r\n", code, text, fi->len);
	full_write(socket, buffer, strlen(buffer));
	full_write(socket, fi->data, fi->len);
	printf("%d %s\n", code, text);
}

static void return_hyperlink_to_file(const file_info * fi, int socket){
	char buffer[2048];
	char text[1024];
	snprintf(text, 1024, "<html><body>Your file is available <a href=\"%d\">here</a>.</body></html>", fi->id);
	snprintf(buffer, 2048, "HTTP/1.0 200 OK\nContent-Length: %lu\nServer: myn3\r\n\r\n%s", strlen(text), text);
	full_write(socket, buffer, strlen(buffer));
	printf("200 OK\n");
}

static char * find_mem(char * hay, unsigned int h_len, char * needle, unsigned int n_len){
	unsigned int i = 0;
	unsigned int hi = 0;
	while(h_len - hi >= n_len){
		int found = 1;
		for(i = 0; i < n_len; ++i)
			if(hay[hi + i] != needle[i]){
				found = 0;
				break;
			}
		if(found)
			return hay + hi;
		hi++;
	}
	return NULL;
}

static char * find_in_between(char * s, unsigned int len, char * l, char * r, unsigned int * flen){
	char * r1 = find_mem(s, len, l, strlen(l));
	if(r1 == NULL)
		return NULL;
	r1 += strlen(l);
	char * r2 = find_mem(r1, len - (r1 - s), r, strlen(r));
	if(r2 == NULL)
		return NULL;
	*flen = r2 - r1;
	return r1;
}

static file_info * parse_data(char * buffer, unsigned int len, char * not_an_image, char * too_large, char * format_error, char * out_of_memory, char * format_error_or_too_large){

	char * content_type_str = "Content-Type: image/";
	if(find_mem(buffer, len > 1024 ? 1024 : len, content_type_str, strlen(content_type_str)) == NULL){
		*not_an_image = 1;
		return NULL;
	}

	/* find content marker */
	unsigned int blen;
	char * bstart = find_in_between(buffer, len > 1024 ? 1024 : len, " boundary=", "\r", &blen);
	if(bstart == NULL || blen > 99){
		*format_error = 1;
		return NULL;
	}

	char boundary[100];
	memcpy(boundary, bstart, blen);
	boundary[blen] = 0;

	/* find content */
	bstart = find_mem(bstart, len - (bstart - buffer), "\r\n\r\n", 4);
	if(bstart == NULL){
		*format_error = 1;
		return NULL;
	}
	bstart = find_mem(bstart, len - (bstart - buffer), boundary, strlen(boundary));
	if(bstart == NULL){
		*format_error = 1;
		return NULL;
	}
	bstart = find_mem(bstart, len - (bstart - buffer), "\r\n\r\n", 4);
	if(bstart == NULL){
		*format_error = 1;
		return NULL;
	}

	char * cstart = find_mem(bstart, len - (bstart - buffer), boundary, strlen(boundary));
	if(bstart == NULL){
		*format_error = 1;
		return NULL;
	}

	/* padding fixes */
	bstart += 4;
	cstart -= 4;

	unsigned int clen = cstart - bstart;

	/* save data */
	file_info * ret = (file_info *)malloc(sizeof(file_info));
	if(ret == NULL){
		*out_of_memory = 1;
		return NULL;
	}
	ret->id = new_id();
	ret->len = clen;
	ret->data = malloc(ret->len);
	if(ret->data == NULL){
		*out_of_memory = 1;
		free(ret);
		return NULL;
	}
	memcpy(ret->data, bstart, clen);
	return ret;
}

static ssize_t parse_content_length(char * buffer, unsigned int rd){
	char * str = "Content-Length: ";
	char * s = strstr(buffer, str);
	if(s == NULL)
		return 0;
	s += strlen(str);
	char buf[15];
	copy_while_numeric(s, buf, 15);
	int content_length = atoi(buf);
	if(content_length < 1)
		return 0;
	s = strstr(s, "\r\n\r\n");
	if(s == NULL)
		return 0;
	s += 4;
	/*
	printf("(already read: %lu header: %lu content-length: %lu)\n", rd, (s - buffer), content_length);
	*/
	return content_length + (s - buffer);
}

static void close_socket(int socket){
	shutdown(socket, SHUT_WR);
	char buffer[512];
	int r;
	while((r = read(socket, buffer, 512)) > 0);
	shutdown(socket, SHUT_RD);
	close(socket);
}

int main(int argc, char * argv[]){
	init_id();
	struct _sa {
		void (*sa_handler)(int);
	} sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if(sigaction(SIGPIPE, (struct sigaction *)&sa, NULL) != 0){
		printf("Failed to start ignoring pipe error signals.\n");
		return 1;
	}
	struct sockaddr_in servaddr;
	struct sockaddr_in cliaddr;
	socklen_t clilen;

	printf("Starting... ");
	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd == -1){
		printf("Failed to create socket\n");
		return 1;
	}
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);
	if(bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0){
		printf("Failed to bind socket with port %u\n", PORT);
		return 1;
	}
	if(listen(listenfd, 128) != 0){
		printf("Failed to listen on socket\n");
		return 1;
	}
	printf("\rServer started\n");

	char buffer[BIG_BUF_SIZ];
	file_info * index_get_file = load_file("index.htm");

	unsigned int connection_nr = 0;
	while(1){
		buffer[0] = 0;
		clilen = sizeof(cliaddr);
		int client_fd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

		++connection_nr;
		printf("Connection #%u established\n", connection_nr);

		unsigned int request_size = 0;
		int r;
		unsigned int total_size = 0;
		while(request_size < 1024 && (r = read(client_fd, buffer + request_size, BIG_BUF_SIZ - request_size)) > 0){
			request_size += r;
			buffer[request_size] = 0;
			if(strstr(buffer, "\r\n\r\n") != NULL){
				total_size = parse_content_length(buffer, request_size); /* 0 if unavailable */
				break;
			}
		}

		if(total_size >= BIG_BUF_SIZ){
			return_msg(400, "Bad Request", "Request too large.", client_fd);
			close_socket(client_fd);
			continue;
		}

		if(total_size != 0){
			total_size -= request_size;
			while(total_size > 0 && (r = read(client_fd, buffer + request_size, total_size)) > 0){
				request_size += r;
				total_size -= r;
			}
		}

		char request_method = 0;
		char request_method_str[10];
		char request_uri[13];
		parse(buffer, &request_method, request_method_str, request_uri, 13);
		if(request_method == 0)
			printf("UNKN %s\n", request_uri);
		else
			printf("%s %s\n", request_method_str, request_uri);

		switch(request_method){
			case GET:
				if(request_uri[0] == '/'){
					if(request_uri[1] == 0)
						return_file(200, "OK", index_get_file, client_fd);
					else{
						char id_buf[20];
						copy_while_numeric(request_uri + 1, id_buf, 20);
						int id = atoi(id_buf);
						if(id < 1)
							return_msg(400, "Bad Request", "Access denied.", client_fd);
						else{
							const file_info * fi = get_file(id);
							if(fi == NULL)
								return_msg(404, "Not Found", "File not found.", client_fd);
							else
								return_file(200, "OK", fi, client_fd);
						}
					}
				}else
					return_msg(400, "Bad Request", "Access denied.", client_fd);
				break;
			case POST:
				if(strcmp(request_uri, "/") == 0){
					char not_an_image = 0;
					char too_large = 0;
					char format_error = 0;
					char out_of_memory = 0;
					char format_error_or_too_large = 0;
					file_info * data = parse_data(buffer, request_size, &not_an_image, &too_large, &format_error, &out_of_memory, &format_error_or_too_large);
					if(not_an_image)
						return_msg(400, "Bad Request", "File is not an image.", client_fd);
					else
						if(too_large)
							return_msg(400, "Bad Request", "File is too large.", client_fd);
						else
							if(format_error)
								return_msg(400, "Bad Request", "Malformed request.", client_fd);
							else
								if(out_of_memory)
									return_msg(400, "Bad Request", "System out of memory", client_fd);
								else
									if(format_error_or_too_large)
										return_msg(400, "Bad Request", "File is too large or the request was malformed.", client_fd);
									else
										if(data == NULL){
											return_msg(400, "Bad Request", "Unspecified error parsing request.", client_fd);
										}else{
											save_file(data);
											return_hyperlink_to_file(data, client_fd);
											free(data);
										}
				}else
					return_msg(400, "Bad Request", "Access denied.", client_fd);
				break;
			default:
				return_msg(400, "Bad Request", "Access denied.", client_fd);
		}
		close_socket(client_fd);
	}

	return 0;
}
