#include <stdio.h>
#include <string.h>
#define DLL_EXPORTS
#include "so_stdio.h"
#define BUFFSIZE 4096
typedef struct _so_file {
	#if defined(__linux__)
	int file;
	#elif defined(_WIN32)
	HANDLE file;
	PROCESS_INFORMATION child;
	#else
	#error"Unknown platform"
	#endif
	unsigned char BUFF[BUFFSIZE];
	int offset_in;
	int offset_out;
	int dim_out;
	int so_eof;
	int flag_error;
	int flags;
} SO_FILE;

#if defined(__linux__)
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#define SHELL "/bin/sh"
int parse(char *mode, int *flag)
{
	int rw, pr;

	switch (*mode++) {
	case 'r':
		rw = O_RDONLY;
		pr = 0;
		break;
	case 'w':
		rw = O_WRONLY;
		pr = O_CREAT | O_TRUNC;
		break;
	case 'a':
		rw = O_WRONLY;
		pr = O_CREAT | O_APPEND;
		break;
	default:
		return SO_EOF;
	}

	if (*mode == '+') {
		rw ^= rw;
		pr |= O_RDWR;
	} else if (*mode != '\0') {
		return SO_EOF;
	}
	*flag = pr | rw;
	return *flag;
}
#elif defined(_WIN32)
#include <windows.h>
int parse(char *mode, int *flag)
{
	static int flags[4];
	static int call;

	if (mode != NULL) {
		switch (*mode++) {
		case 'r':
			flags[0] = GENERIC_READ;
			flags[1] = FILE_SHARE_READ|FILE_SHARE_WRITE;
			flags[2] = OPEN_EXISTING;
			flags[3] = FILE_ATTRIBUTE_READONLY;
			if (*mode == '+') {
				flags[0] |= GENERIC_WRITE;
				flags[3] = FILE_ATTRIBUTE_NORMAL;
			} else if (*mode != '\0') {
				return SO_EOF;
			}
			break;
		case 'w':
			flags[0] = GENERIC_WRITE | GENERIC_READ;
			flags[1] = FILE_SHARE_READ|FILE_SHARE_WRITE;
			flags[2] = CREATE_ALWAYS;
			flags[3] = FILE_ATTRIBUTE_NORMAL;
			if (*mode == '+')
				flags[0] |= GENERIC_READ;
			else if (*mode != '\0')
				return SO_EOF;
			break;
		case 'a':
			flags[0] = FILE_APPEND_DATA;
			flags[1] = FILE_SHARE_READ|FILE_SHARE_WRITE;
			flags[2] = OPEN_ALWAYS;
			flags[3] = FILE_ATTRIBUTE_NORMAL;
			if (*mode == '+')
				flags[0] |= GENERIC_READ;
			else if (*mode != '\0')
				return SO_EOF;
			break;
		default:
			return SO_EOF;
		}
		*flag = flags[0];
		call = 0;
		return 0;
	} else {
		return flags[call++];
	}
}
#else
#error"Unknown platform"
#endif

SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	#if defined(_WIN32)
	int flag1, flag2, flag3, flag4;
	#endif
	SO_FILE *FILE;
	int flags;

	flags = 0;
	if (!pathname || !mode)
		return NULL;
	FILE = calloc(1, sizeof(SO_FILE));
	if (!FILE)
		return NULL;
	flags = parse((char *)mode, &flags);
	if (flags < 0) {
		free(FILE);
		return NULL;
	}
	#if defined(__linux__)
	FILE->file = open(pathname, flags, 0644);
	if (FILE->file < 0) {
		free(FILE);
		return NULL;
	}
	#elif defined(_WIN32)
	flag1 = parse(NULL, NULL);
	flag2 = parse(NULL, NULL);
	flag3 = parse(NULL, NULL);
	flag4 = parse(NULL, NULL);
	FILE->file =  CreateFile(pathname, flag1,
		flag2, NULL, flag3, flag4, NULL);
	if (FILE->file == INVALID_HANDLE_VALUE) {
		free(FILE);
		return NULL;
	}
	#else
	#error"Unknown platform"
	#endif
	FILE->flags = flags;
	return FILE;
}

#if defined(__linux__)
int so_fileno(SO_FILE *stream)
#elif defined(_WIN32)
HANDLE so_fileno(SO_FILE *stream)
#else
#error"Unknown platform"
#endif
{
	return stream->file;
}

int so_fflush(SO_FILE *stream)
{
	#if defined(__linux__)
	int rt;
	#elif defined(_WIN32)
	BOOL rc;
	#endif
	int size, i;

	if (stream->offset_in > 0) {
		if (stream->offset_out < stream->dim_out) {
			#if defined(__linux__)
			rt = lseek(stream->file,
			stream->offset_out - stream->dim_out, SEEK_CUR);
			if (rt < 0) {
				stream->flag_error = 1;
				return SO_EOF;
			}
			#elif defined(_WIN32)
			rc = SetFilePointer(stream->file, stream->offset_out
				- stream->dim_out, NULL, SEEK_CUR);
			if (rc == INVALID_SET_FILE_POINTER)
				return SO_EOF;
			#else
			#error"Unknown platform"
			#endif
			stream->offset_out = 0;
			stream->dim_out = 0;
		}
		i = 0;
		while (stream->offset_in > 0) {
			#if defined(__linux__)
			size = write(stream->file,
				stream->BUFF + i, stream->offset_in);
			if (size < 0) {
				stream->flag_error = 1;
				return SO_EOF;
			}
			#elif defined(_WIN32)
			rc = WriteFile(stream->file, stream->BUFF + i,
						stream->offset_in, &size, NULL);
			if (!rc)
				return SO_EOF;
			#else
			#error"Unknown platform"
			#endif
			stream->offset_in -= size;
			i += size;
		}
	}
	return 0;
}

int so_fseek(SO_FILE *stream, long offset, int whence)
{
	#if defined(_WIN32)
	BOOL rc;
	#endif
	int rt;

	if (stream->offset_in > 0) {
		rt = so_fflush(stream);
		if (rt < 0) {
			stream->flag_error = 1;
			return SO_EOF;
		}
	}
	stream->offset_out = 0;
	stream->so_eof = 0;
	stream->dim_out = 0;
	#if defined(__linux__)
	rt = lseek(stream->file, offset, whence);
	if (rt < 0) {
		stream->flag_error = 1;
		return SO_EOF;
	}
	#elif defined(_WIN32)
	rc = SetFilePointer(stream->file, offset,
							NULL, whence);
	if (rc == INVALID_SET_FILE_POINTER)
		return SO_EOF;
	#else
	#error"Unknown platform"
	#endif
	return 0;
}

int so_fclose(SO_FILE *stream)
{
	#if defined(_WIN32)
	BOOL rc;
	#endif
	int rt;

	if (!stream)
		return SO_EOF;
	if (stream->offset_in > 0) {
		rt = so_fflush(stream);
		if (rt < 0) {
			free(stream);
			return SO_EOF;
		}
	}
	#if defined(__linux__)
	rt = close(stream->file);
	free(stream);
	if (rt < 0)
		return SO_EOF;
	#elif defined(_WIN32)
	rc = CloseHandle(stream->file);
	free(stream);
	if (rc == 0)
		return SO_EOF;
	#else
	#error"Unknown platform"
	#endif
	return 0;
}

int so_fgetc(SO_FILE *stream)
{
	#if defined(_WIN32)
	BOOL rt;
	#endif
	int size;

	if (stream->offset_out == stream->dim_out) {
		#if defined(__linux__)
		size = read(stream->file, stream->BUFF, BUFFSIZE);
		if (size < 0) {
			stream->flag_error = 1;
			return SO_EOF;
		}
		#elif defined(_WIN32)
		rt = ReadFile(stream->file, stream->BUFF,
				BUFFSIZE, &size, NULL);
		if (rt == 0) {
			stream->flag_error = 1;
			return SO_EOF;
		}
		#else
		#error"Unknown platform"
		#endif
		stream->dim_out = size;
		stream->offset_out = 0;
		if (size == 0) {
			stream->so_eof = 1;
			return SO_EOF;
		}

	}
	return (int)stream->BUFF[stream->offset_out++];
}

int so_fputc(int c, SO_FILE *stream)
{
	int rt;

	if (stream->offset_in == BUFFSIZE) {
		rt = so_fflush(stream);
		if (rt < 0) {
			stream->flag_error = 1;
			return SO_EOF;
		}
		stream->offset_in = 0;
	}
	stream->BUFF[stream->offset_in++] = (unsigned char) c;
	return c;
}

size_t so_fread(void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	int i, rt;
	int size_buf;

	size_buf = size * nmemb;
	for (i = 0; i < size_buf; i++) {
		rt = so_fgetc(stream);
		if (rt < 0 && i/size == 0)
			return 0;
		else if (rt < 0 && i/size > 0)
			return i/size;
		*(((unsigned char *) ptr) + i) = rt;
	}
	return i/size;
}

size_t so_fwrite(const void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	int rt;
	size_t size_buf, i;

	size_buf = size * nmemb;
	for (i = 0; i < size_buf; i++) {
		rt = so_fputc(*(((unsigned char *) ptr) + i), stream);
		if (rt < 0)
			return rt;
	}
	return i/size;
}
int so_feof(SO_FILE *stream)
{
	return stream->so_eof == 0?0:1;
}
int so_ferror(SO_FILE *stream)
{
	return stream->flag_error;
}
long so_ftell(SO_FILE *stream)
{
	long offset;

	#if defined(__linux__)
	offset = lseek(stream->file, 0, SEEK_CUR);
	#elif defined(_WIN32)
	offset = SetFilePointer(stream->file, 0,
							NULL, SEEK_CUR);
	#else
	#error"Unknown platform"
	#endif
	if (stream->offset_in > 0)
		return offset + stream->offset_in;
	else if (stream->offset_out < stream->dim_out)
		return offset - stream->dim_out + stream->offset_out;
	else
		return offset;
}

#if defined(__linux__)
SO_FILE *so_popen(const char *command, const char *type)
{
	int flag, pid, pipes[2], rt, fd, child_fd, parent_fd;
	SO_FILE *com;

	com = (SO_FILE *)calloc(1, sizeof(SO_FILE));
	if (!com)
		return NULL;
	flag = 0;
	flag = parse((char *)type, &flag);
	if (flag == SO_EOF) {
		free(com);
		return NULL;
	}
	rt = pipe(pipes);
	if (rt < 0) {
		free(com);
		return NULL;
	}
	if (flag & O_WRONLY) {
		parent_fd = pipes[1];
		child_fd = pipes[0];
		fd = 0;
	} else {
		parent_fd = pipes[0];
		child_fd = pipes[1];
		fd = 1;
	}
	pid = fork();
	switch (pid) {
	case -1:
		close(parent_fd);
		close(child_fd);
		free(com);
		return NULL;
	case 0:
		close(parent_fd);
		dup2(child_fd, fd);
		close(child_fd);
		execl(SHELL, "sh", "-c", command, NULL);
		_exit(1);
	default:
		close(child_fd);
		com->file = parent_fd;
		com->flags = pid;
	}
	return com;
}
int so_pclose(SO_FILE *stream)
{
	int rt, pid, s;

	pid = stream->flags;
	rt = so_fclose(stream);
	rt = waitpid(pid, &s, 0);
	return rt == -1 ? -1 : s;
}
#elif defined(_WIN32)
#define SHELL "cmd //C "
SO_FILE *so_popen(const char *command, const char *type)
{
/*
 *	int flag, rt, size;
 *	HANDLE pipeR, pipeW, child_fd, parent_fd;
 *	SO_FILE *com;
 *	STARTUPINFO child;
 *	PROCESS_INFORMATION p;
 *	char *comm;
 *	BOOL bRet;
 *	size = strlen(SHELL);
 *	comm = calloc(strlen(command) + size, sizeof(char));
 *	if (!comm)
 *		return NULL;
 *	memcpy(comm, SHELL, size);
 *	memcpy(comm + size, command, strlen(command) + 1);
 *	com = (SO_FILE *)calloc(1, sizeof(SO_FILE));
 *	if (!com) {
 *		free(comm);
 *		return NULL;
 *	}
 *	flag = 0;
 *	parse((char *)type, &flag);
 *	if (flag == SO_EOF) {
 *		free(comm);
 *		free(com);
 *		return NULL;
 *	}
 *	rt = CreatePipe(&pipeR, &pipeW, NULL, 0);
 *	if (!rt) {
 *		free(comm);
 *		free(com);
 *		return NULL;
 *	}
 *	ZeroMemory( &p, sizeof(PROCESS_INFORMATION) );
 *	ZeroMemory( &child, sizeof(STARTUPINFO) );
 *	if (flag & GENERIC_WRITE) {
 *		parent_fd = pipeR;
 *		if (!SetHandleInformation(pipeW, HANDLE_FLAG_INHERIT, 0)) {
 *			free(comm);
 *			free(com);
 *			return NULL;
 *		}
 *		child.hStdInput = pipeW;
 *
 *		child_fd = pipeW;
 *	} else {
 *		parent_fd = pipeW;
 *		if (!SetHandleInformation(pipeR, HANDLE_FLAG_INHERIT, 0)) {
 *			free(comm);
 *			free(com);
 *			return NULL;
 *		}
 *		child.hStdOutput = pipeR;
 *		child_fd = pipeW;
 *	}
 *	bRet = CreateProcess(NULL, comm, NULL, NULL,
 *			TRUE, 0, NULL, NULL, &child, &p);
 *	if (!bRet) {
 *		printf( "CreateProcess failed (%d).\n", GetLastError());
 *		CloseHandle(child_fd);
 *		CloseHandle(parent_fd);
 *		free(comm);
 *		free(com);
 *		return NULL;
 *	}
 *	CloseHandle(child_fd);
 *	com->file = parent_fd;
 *	com->child = p;
 *	free(comm);
 *	return com;
 */
	return NULL;
}
int so_pclose(SO_FILE *stream)
{
/*
 *	int rt;
 *	HANDLE pid;
 *
 *	pid = stream->child.hProcess;
 *	rt = so_fclose(stream);
 *	rt = WaitForSingleObject(pid, INFINITE);
 *	return rt == WAIT_FAILED ? -1 : 0;
 */
	return 0;
}
#else
#error"Unknown platform"
#endif
