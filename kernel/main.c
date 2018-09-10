
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
main.c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Forrest Yu, 2005
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"

/*****************************************************************************
*                               kernel_main
*****************************************************************************/
/**
* jmp from kernel.asm::_start.
*
*****************************************************************************/

char location[128] = "/";
char filepath[128] = "";
char users[2][128] = { "empty", "empty" };
char passwords[2][128];
char files[20][128];
char userfiles[20][128];
int filequeue[50];
int filecount = 0;
int usercount = 0;
int isEntered = 0;
int UserState = 0;
//int UserSwitch = 0;
int leiflag = 0;

PUBLIC int kernel_main()
{
	disp_str("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

	int i, j, eflags, prio;
	u8  rpl;
	u8  priv; /* privilege */

	struct task * t;
	struct proc * p = proc_table;
	char * stk = task_stack + STACK_SIZE_TOTAL;

	for (i = 0; i < NR_TASKS + NR_PROCS; i++, p++, t++) {
		if (i >= NR_TASKS + NR_NATIVE_PROCS) {
			p->p_flags = FREE_SLOT;
			continue;
		}

		if (i < NR_TASKS) {     /* TASK */
			t = task_table + i;
			priv = PRIVILEGE_TASK;
			rpl = RPL_TASK;
			eflags = 0x1202;/* IF=1, IOPL=1, bit 2 is always 1 */
			prio = 15;
		}
		else {                  /* USER PROC */
			t = user_proc_table + (i - NR_TASKS);
			priv = PRIVILEGE_USER;
			rpl = RPL_USER;
			eflags = 0x202;	/* IF=1, bit 2 is always 1 */
			prio = 5;
		}

		strcpy(p->name, t->name);	/* name of the process */
		p->p_parent = NO_TASK;

		if (strcmp(t->name, "INIT") != 0) {
			p->ldts[INDEX_LDT_C] = gdt[SELECTOR_KERNEL_CS >> 3];
			p->ldts[INDEX_LDT_RW] = gdt[SELECTOR_KERNEL_DS >> 3];

			/* change the DPLs */
			p->ldts[INDEX_LDT_C].attr1 = DA_C | priv << 5;
			p->ldts[INDEX_LDT_RW].attr1 = DA_DRW | priv << 5;
		}
		else {		/* INIT process */
			unsigned int k_base;
			unsigned int k_limit;
			int ret = get_kernel_map(&k_base, &k_limit);
			assert(ret == 0);
			init_desc(&p->ldts[INDEX_LDT_C],
				0, /* bytes before the entry point
				   * are useless (wasted) for the
				   * INIT process, doesn't matter
				   */
				(k_base + k_limit) >> LIMIT_4K_SHIFT,
				DA_32 | DA_LIMIT_4K | DA_C | priv << 5);

			init_desc(&p->ldts[INDEX_LDT_RW],
				0, /* bytes before the entry point
				   * are useless (wasted) for the
				   * INIT process, doesn't matter
				   */
				(k_base + k_limit) >> LIMIT_4K_SHIFT,
				DA_32 | DA_LIMIT_4K | DA_DRW | priv << 5);
		}

		p->regs.cs = INDEX_LDT_C << 3 | SA_TIL | rpl;
		p->regs.ds =
			p->regs.es =
			p->regs.fs =
			p->regs.ss = INDEX_LDT_RW << 3 | SA_TIL | rpl;
		p->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;
		p->regs.eip = (u32)t->initial_eip;
		p->regs.esp = (u32)stk;
		p->regs.eflags = eflags;

		p->ticks = p->priority = prio;
		strcpy(p->name, t->name);	/* name of the process */
		p->pid = i;			/* pid */
		p->run_count = 0;
		p->run_state = 1;

		p->p_flags = 0;
		p->p_msg = 0;
		p->p_recvfrom = NO_TASK;
		p->p_sendto = NO_TASK;
		p->has_int_msg = 0;
		p->q_sending = 0;
		p->next_sending = 0;

		for (j = 0; j < NR_FILES; j++)
			p->filp[j] = 0;

		stk -= t->stacksize;
	}

	k_reenter = 0;
	ticks = 0;

	p_proc_ready = proc_table;

	init_clock();
	init_keyboard();

	restart();

	while (1) {}
}


/*****************************************************************************
*                                get_ticks
*****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}


/**
* @struct posix_tar_header
* Borrowed from GNU `tar'
*/
struct posix_tar_header
{				/* byte offset */
	char name[100];		/*   0 */
	char mode[8];		/* 100 */
	char uid[8];		/* 108 */
	char gid[8];		/* 116 */
	char size[12];		/* 124 */
	char mtime[12];		/* 136 */
	char chksum[8];		/* 148 */
	char typeflag;		/* 156 */
	char linkname[100];	/* 157 */
	char magic[6];		/* 257 */
	char version[2];	/* 263 */
	char uname[32];		/* 265 */
	char gname[32];		/* 297 */
	char devmajor[8];	/* 329 */
	char devminor[8];	/* 337 */
	char prefix[155];	/* 345 */
						/* 500 */
};

/*****************************************************************************
*                                untar
*****************************************************************************/
/**
* Extract the tar file and store them.
*
* @param filename The tar file.
*****************************************************************************/
void untar(const char * filename)
{
	printf("[extract `%s'\n", filename);
	int fd = open(filename, O_RDWR);
	assert(fd != -1);

	char buf[SECTOR_SIZE * 16];
	int chunk = sizeof(buf);
	int i = 0;
	int bytes = 0;

	while (1) {
		bytes = read(fd, buf, SECTOR_SIZE);
		assert(bytes == SECTOR_SIZE); /* size of a TAR file
									  * must be multiple of 512
									  */
		if (buf[0] == 0) {
			if (i == 0)
				printf("    need not unpack the file.\n");
			break;
		}
		i++;

		struct posix_tar_header * phdr = (struct posix_tar_header *)buf;

		/* calculate the file size */
		char * p = phdr->size;
		int f_len = 0;
		while (*p)
			f_len = (f_len * 8) + (*p++ - '0'); /* octal */

		int bytes_left = f_len;
		int fdout = open(phdr->name, O_CREAT | O_RDWR | O_TRUNC);
		if (fdout == -1) {
			printf("    failed to extract file: %s\n", phdr->name);
			printf(" aborted]\n");
			close(fd);
			return;
		}
		printf("    %s\n", phdr->name);
		while (bytes_left) {
			int iobytes = min(chunk, bytes_left);
			read(fd, buf,
				((iobytes - 1) / SECTOR_SIZE + 1) * SECTOR_SIZE);
			bytes = write(fdout, buf, iobytes);
			assert(bytes == iobytes);
			bytes_left -= iobytes;
		}
		close(fdout);
	}

	if (i) {
		lseek(fd, 0, SEEK_SET);
		buf[0] = 0;
		bytes = write(fd, buf, 1);
		assert(bytes == 1);
	}

	close(fd);

	printf(" done, %d files extracted]\n", i);
}

/*****************************************************************************
*                                shabby_shell
*****************************************************************************/
/**
* A very very simple shell.
*
* @param tty_name  TTY file name.
*****************************************************************************/
PUBLIC void clear()
{
	int i = 0;
	for (i = 0; i < 30; i++)
		printf("\n");
}

/*PUBLIC void clear() {
int i = 0;
disp_pos = 0;
for(i=0;i<3000;i++){
disp_str(" ");
}
disp_pos = 0;
//printf("%d",console_table[current_console].cursor);
printf("%d",console_table[current_console].crtc_start);
console_table[current_console].crtc_start = 0;
console_table[current_console].cursor = 0;
printf(" %d",current_console);

clear_screen(0,console_table[current_console].cursor);
console_table[current_console].crtc_start = 0;
console_table[current_console].cursor = 0;
}*/

void shabby_shell(const char* tty_name){
	int fd_stdin  = open(tty_name, O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	char rdbuf[128];//读取的命令
	char cmd[128];//指令
	char arg1[128];//参数1
	char arg2[128];//参数2
	char buf[1024];


	initFs();
	while(1){
		if(usercount == 0){
			printf("Enter Admin Password:");
			char buf[128];
			int r = read(0, buf, 128);
			buf[r] = 0;
			if(strcmp(buf, "admin") == 0){
				strcpy(location, "/");
				UserState = 3;
				break;			
			}
			else
				printf("Password Error!\n");
		}
		else{
			//printf("%d",usercount);
			int isGet = 0;
			printf("Enter User Name:");
			char buf[128];
			int r = read(0, buf, 128);
			buf[r] = 0;
			int i;
			for(i=0;i<usercount;i++){
				if(strcmp(buf, users[i]) == 0 && strcmp(buf, "empty") != 0){
					printf("Enter %s Password:");
					char buf[128];
					int r = read(0, buf, 128);
					buf[r] = 0;					
					if(strcmp(buf, passwords[i]) == 0){
						strcpy(location, users[i]);
						UserState = i+1;
						isGet = 1;
						break;
					}			
				}
			}
			if(isGet)
				break;
			else
				printf("Password Error Or User Not Exist!\n");		
		}		
	}

	while (1) {
		//init char array
		clearArr(rdbuf, 128);
		clearArr(cmd, 128);
		clearArr(arg1, 128);
		clearArr(arg2, 128);
		clearArr(buf, 1024);
		if(UserState == 3)
			printf("[Admin@miaOS]%s# ",location);
		else
			printf("[%s@miaOS]/%s$ ",users[UserState-1],location);
		//write(1, "$ ", 2);
		int r = read(0, rdbuf, 70);
		rdbuf[r] = 0;

		int argc = 0;
		char * argv[PROC_ORIGIN_STACK];
		char * p = rdbuf;
		char * s;
		int word = 0;
		char ch;
		do {
			ch = *p;
			if (*p != ' ' && *p != 0 && !word) {
				s = p;
				word = 1;
			}
			if ((*p == ' ' || *p == 0) && word) {
				word = 0;
				argv[argc++] = s;
				*p = 0;
			}
			p++;
		} while(ch);
		argv[argc] = 0;

		int fd = open(argv[0], O_RDWR);

		if (fd == -1) {//从这里开始处理

			if (rdbuf[0]) {
				int i = 0, j = 0;
				/* get command */
				while (rdbuf[i] != ' ' && rdbuf[i] != 0)
				{
					cmd[i] = rdbuf[i];
					i++;
				}
				i++;
				/* get arg1 */
				while(rdbuf[i] != ' ' && rdbuf[i] != 0)
        			{
            				arg1[j] = rdbuf[i];
            				i++;
            				j++;
        			}
        			i++;
        			j = 0;
				/* get arg2 */
       				while(rdbuf[i] != ' ' && rdbuf[i] != 0)
        			{
            				arg2[j] = rdbuf[i];
            				i++;
            				j++;
        			}
				//去空格，指令参数分离
				//cmd arg1 arg2

				//解析命令

				 //帮助
				if(strcmp(cmd, "help") == 0){
					showhelp();
				}
				else if(strcmp(cmd, "clear") == 0){
					clear();
					welcome();
				}//文件
				else if(strcmp(cmd, "sudo") == 0){
					printf("Enter Admin Password:");
					char buf[128];
					int r = read(0, buf, 128);
					buf[r] = 0;
					if(strcmp(buf, "admin") == 0){
						strcpy(location, "/");
						UserState = 3;			
					}
					else
						printf("Password Error!\n");
				}
				else if(strcmp(cmd, "add") == 0){
					addUser(arg1,arg2);
				}
				else if(strcmp(cmd, "move") == 0){
					moveUser(arg1,arg2);
				}
				else if(strcmp(cmd, "shiftlog") == 0){
					shift(arg1,arg2);
				}
				else if(strcmp(cmd, "create") == 0){
					createFilepath(arg1);
					createFile(filepath, arg2, 1);
					clearArr(filepath, 128);

				}
				else if(strcmp(cmd, "read") == 0)
				{
					createFilepath(arg1);
					readFile(filepath);
					clearArr(filepath, 128);	
				}
				/* edit a file appand */
				else if(strcmp(cmd, "edit+") == 0)
				{	
					createFilepath(arg1);
					editAppand(filepath, arg2);
					clearArr(filepath, 128);
				}
				/* edit a file cover */
				else if(strcmp(cmd, "edit") == 0)
				{
					createFilepath(arg1);
					editCover(filepath, arg2);
					clearArr(filepath, 128);
				}
				/* delete a file */
				else if(strcmp(cmd, "delete") == 0)
				{
					createFilepath(arg1);
					deleteFile(filepath);
					clearArr(filepath, 128);
				}
				/* ls */
				else if(strcmp(cmd, "ls") == 0)
				{
					ls();
				}
				else if(strcmp(cmd, "ps") == 0){
					showProcess();
				}else if(strcmp(cmd, "kill") == 0){
					killpro(arg1);
				}else if(strcmp(cmd, "pause") == 0){
					pausepro(arg1);
				}else if(strcmp(cmd, "resume") == 0){
					resume(arg1);
				}else if(strcmp(cmd, "chess") == 0){
					playchess(0,1);
				}else if(strcmp(cmd, "gomoku") == 0){
					gomoku();
				}else{
					continue;
				}
				//printf("cmd %s\n",cmd);
			}

		}
		else {
			close(fd);
			int pid = fork();
			if (pid != 0) { /* parent */
				int s;
				wait(&s);
			}
			else {	/* child */
				execv(argv[0], argv);
			}
		}
	}

	close(1);
	close(0);
}

void killpro(char *a){
	if (strcmp(a, "a") == 0){
		proc_table[6].p_flags = 1;
		showProcess();	
	}
	else if(strcmp(a, "b") == 0){
		proc_table[7].p_flags = 1;
		showProcess();
	}
	else if(strcmp(a, "c") == 0){
		proc_table[8].p_flags = 1;
		showProcess();
	}
}

void pausepro(char *a){
	if (strcmp(a, "a") == 0){
		proc_table[6].run_state = 0;
		showProcess();	
	}
	else if(strcmp(a, "b") == 0){
		proc_table[7].run_state = 0;
		showProcess();
	}
	else if(strcmp(a, "c") == 0){
		proc_table[8].run_state = 0;
		showProcess();
	}
}

void resume(char *a){
	if (strcmp(a, "a") == 0){
		proc_table[6].run_state = 1;
		showProcess();	
	}
	else if(strcmp(a, "b") == 0){
		proc_table[7].run_state = 1;
		showProcess();
	}
	else if(strcmp(a, "c") == 0){
		proc_table[8].run_state = 1;
		showProcess();
	}
}

void clearArr(char *arr, int length)
{
    int i;
    for (i = 0; i < length; i++)
        arr[i] = 0;
}

	/* Get File Pos */
int getPos()
{
	int i = 0;
	for (i = 0; i < 500; i++)
	{
		if (filequeue[i] == 1)
			return i;
	}
}

int len(char* a){
    int ans=0;
    int i;
    for(i=0;i<16;i++){
        if(a[i]==0)
            break;
        ans++;
    }
    return ans;
}

int vertify()
{
	if (UserState == 0)
	{
		printf("Permission deny!!\n");
		return 0;
	}
	else
		return 1;
}

	/* Create Filepath */
void createFilepath(char * filename)
{
	int k = 0, j = 0;
		
	for (k = 0; k < len(location); k++)
	{
		filepath[k] = location[k];
	}
	filepath[k] = '_';
	k++;
	for(j = 0; j < strlen(filename); j++, k++)
	{	
		filepath[k] = filename[j];
	}
	filepath[k] = '\0';
}

	/* Update FileLogs */
void updateFileLogs()
{
	int i = 0, count = 0;
	editCover("fileLogs", "");
	while (count <= filecount - 1)
	{
		if (filequeue[i] == 0)
		{
			i++;
			continue;
		}
		char filename[128];
		int len = strlen(files[count]);
		strcpy(filename, files[count]);
		filename[len] = ' ';
		filename[len + 1] = '\0';
		//printf("%s\n", filename);
		editAppand("fileLogs", filename);
		count++;
		i++;
	}
}

	/* Update myUsers */
void updateMyUsers()
{
	int i = 0, count = 0;
	editCover("myUsers", "");
	if (strcmp(users[0], "empty") != 0)
	{
		editAppand("myUsers", users[0]);
		editAppand("myUsers", " ");
	}
	else
	{
		editAppand("myUsers", "empty ");
	}
	if (strcmp(users[1], "empty") != 0)
	{
		editAppand("myUsers", users[1]);
		editAppand("myUsers", " ");
	}
	else
	{
		editAppand("myUsers", "empty ");
	}
}

	/* Update myUsersPassword */
void updateMyUsersPassword()
{
	int i = 0, count = 0;
	editCover("myUsersPassword", "");
	if (strcmp(passwords[0], "") != 0)
	{
		editAppand("myUsersPassword", passwords[0]);
		editAppand("myUsersPassword", " ");
	}
	else
	{
		editAppand("myUsersPassword", "empty ");
	}
	if (strcmp(passwords[1], "") != 0)
	{
		editAppand("myUsersPassword", passwords[1]);
		editAppand("myUsersPassword", " ");
	}
	else
	{
		editAppand("myUsersPassword", "empty ");
	}
}

	/* Add FIle Log */
void addLog(char * filepath)
{
	int pos = -1, i = 0;
	pos = getPos();
	filecount++;
	strcpy(files[pos], filepath);
	updateFileLogs();
	filequeue[pos] = 0;
	if (strcmp("/", location) != 0)
	{
		int fd = -1, k = 0, j = 0;
		char filename[128];
		while (k < strlen(filepath))
		{
			if (filepath[k] != '_')
				k++;
			else
				break;
		}
		k++;
		while (k < strlen(filepath))
		{
			filename[j] = filepath[k];
			k++;
			j++;
		}
		filename[j] = '\0';
		if (strcmp(location, users[0]) == 0)
		{
			editAppand("user1", filename);
			editAppand("user1", " ");
		}
		else if(strcmp(location, users[1]) == 0)
		{
			editAppand("user2", filename);
			editAppand("user2", " ");
		}
	}
}

	/* Delete File Log */
void deleteLog(char * filepath)
{
	int i = 0, fd = -1;
	for (i = 0; i < filecount; i++)
	{
		if (strcmp(filepath, files[i]) == 0)
		{
			strcpy(files[i], "empty");
			int len = strlen(files[i]);
			files[i][len] = '0' + i;
			files[i][len + 1] = '\0';
			fd = open(files[i], O_CREAT | O_RDWR);
			close(fd);
			filequeue[i] = 1;
			break;
		}
	}
	filecount--;
	updateFileLogs();
}

void showhelp(){
	printf(" _________________________________________________________________ \n");
	printf("|          instruction           |             function           |\n");
	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	printf("| help                           | show help table                |\n");
	printf("| sudo                           | obtain administrator privileges|\n");
	printf("| add      [username] [password] | add user                       |\n");
	printf("| move     [username] [password] | remove user                    |\n");
	printf("| shiftlog [username] [password] | shift to user                  |\n");
	printf("| ls                             | show file list                 |\n");
	printf("| read     [filename]            | read file                      |\n");
	printf("| create   [filename] [content]  | create file                    |\n");
	printf("| edit+    [filename] [content]  | edit file, append content      |\n");
	printf("| edit     [filename] [content]  | edit file, cover content       |\n");
	printf("| delete   [filename]            | delete file                    |\n");
	printf("| proc                           | show running process table     |\n");
	printf("| kill     [proc.no]             | kill process                   |\n");
	printf("| pause    [proc.no]             | pause process                  |\n");
	printf("| resume   [proc.no]             | resume process                 |\n");
	printf("\n");
	printf(" Applications: fuckLandlord, chess\n");

}


/* Init FS */
void initFs()
{
	int fd = -1, n = 0, i = 0, count = 0, k = 0;
	char bufr[1024] = "";
	char bufp[1024] = "";
	char buff[1024] = "";

	for (i = 0; i < 500; i++)
		filequeue[i] = 1;

	fd = open("myUsers", O_RDWR);
	close(fd);
	fd = open("myUsersPassword", O_RDWR);
	close(fd);
	fd = open("fileLogs", O_RDWR);
	close(fd);
	fd = open("user1", O_RDWR);
	close(fd);
	fd = open("user2", O_RDWR);
	close(fd);
	/* init users */
	fd = open("myUsers", O_RDWR);
	n = read(fd, bufr, 1024);
	bufr[strlen(bufr)] = '\0';
	for (i = 0; i < strlen(bufr); i++)
	{
		if (bufr[i] != ' ')
		{
			users[count][k] = bufr[i];
			k++;
		}
		else
		{
			while (bufr[i] == ' ')
			{
				i++;
				if (bufr[i] == '\0')
				{
					users[count][k] = '\0';
					if (strcmp(users[count], "empty") != 0)
						usercount++;
					count++;
					break;
				}
			}
			if (bufr[i] == '\0')
			{
				break;
			}
			i--;
			users[count][k] = '\0';
			if (strcmp(users[count], "empty") != 0)
						usercount++;
			k = 0;
			count++;
		}
	}
	close(fd);
	count = 0;
	k = 0;
	
	/* init password */
	fd = open("myUsersPassword", O_RDWR);
	n = read(fd, bufp, 1024);
	for (i = 0; i < strlen(bufp); i++)
	{
		if (bufp[i] != ' ')
		{
			passwords[count][k] = bufp[i];
			k++;
		}
		else
		{
			while (bufp[i] == ' ')
			{
				i++;
				if (bufp[i] == '\0')
				{
					count++;
					break;
				}
			}
			if (bufp[i] == '\0')
				break;
			i--;
			passwords[count][k] = '\0';
			k = 0;
			count++;
		}
	}
	close(fd);
	count = 0;
	k = 0;

	/* init files */
	fd = open("fileLogs", O_RDWR);
	n = read(fd, buff, 1024);
	for (i = 0; i <= strlen(buff); i++)
	{
		if (buff[i] != ' ')
		{
			files[count][k] = buff[i];
			k++;
		}
		else
		{
			while (buff[i] == ' ')
			{
				i++;
				if (buff[i] == '\0')
				{
					break;
				}
			}
			if (buff[i] == '\0')
			{
				files[count][k] = '\0';
				count++;
				break;
			}
			i--;
			files[count][k] = '\0';
			k = 0;
			count++;
		}
	}
	close(fd);
	
	int empty = 0;
	for (i = 0; i < count; i++)
	{
		char flag[7];
		strcpy(flag, "empty");
		flag[5] = '0' + i;
		flag[6] = '\0';
		fd = open(files[i], O_RDWR);
		close(fd);
	
		if (strcmp(files[i], flag) != 0)
			filequeue[i] = 0;
		else
			empty++;
	}
	filecount = count - empty;
}

/* Create File */
void createFile(char * filepath, char * buf, int flag)
{
	int fd = -1, i = 0, pos;	
	pos = getPos();
	char f[7];
	strcpy(f, "empty");
	f[5] = '0' + pos;
	f[6] = '\0';
	if (strcmp(files[pos], f) == 0 && flag == 1)
	{
		unlink(files[pos]);
	}

	fd = open(filepath, O_CREAT | O_RDWR);
	printf("file name: %s content: %s\n", filepath, buf);
	if(fd == -1)
	{
		printf("Fail, please check and try again!!\n");
		return;
	}
	if(fd == -2)
	{
		printf("Fail, file exsists!!\n");
		return;
	}
	//printf("%s\n", buf);
	
	write(fd, buf, strlen(buf));
	close(fd);
	
	/* add log */
	if (flag == 1)
		addLog(filepath);
		
}


/* Read File */
void readFile(char * filepath)
{
	if (vertify() == 0)
		return;

	int fd = -1;
	int n;
	char bufr[1024] = "";
	fd = open(filepath, O_RDWR);
	if(fd == -1)
	{
		printf("Fail, please check and try again!!\n");
		return;
	}
	n = read(fd, bufr, 1024);
	bufr[n] = '\0';
	printf("%s(fd=%d) : %s\n", filepath, fd, bufr);
	close(fd);
}

/* Edit File Appand */
void editAppand(char * filepath, char * buf)
{
	if (vertify() == 0)
		return;

	int fd = -1;
	int n, i = 0;
	char bufr[1024] = "";
	char empty[1024];
	
	for (i = 0; i < 1024; i++)
		empty[i] = '\0';
	fd = open(filepath, O_RDWR);
	if(fd == -1)
	{
		printf("Fail, please check and try again!!\n");
		return;
	}

	n = read(fd, bufr, 1024);
	n = strlen(bufr);
	
	for (i = 0; i < strlen(buf); i++, n++)
	{	
		bufr[n] = buf[i];
		bufr[n + 1] = '\0';
	}
	write(fd, empty, 1024);
	fd = open(filepath, O_RDWR);
	write(fd, bufr, strlen(bufr));
	close(fd);
}

/* Edit File Cover */
void editCover(char * filepath, char * buf)
{
	
	if (vertify() == 0)
		return;

	int fd = -1;
	int n, i = 0;
	char bufr[1024] = "";
	char empty[1024];
	
	for (i = 0; i < 1024; i++)
		empty[i] = '\0';

	fd = open(filepath, O_RDWR);
	//printf("%d",fd);
	if (fd == -1)
		return;
	write(fd, empty, 1024);
	close(fd);
	fd = open(filepath, O_RDWR);
	write(fd, buf, strlen(buf));
	close(fd);
}

/* Delete File */
void deleteFile(char * filepath)
{
	if (vertify() == 0)
		return;
	if (usercount == 0)
	{
		printf("Fail!\n");
		return;
	}
	editCover(filepath, "");
	//printf("%s",filepath);
	int a = unlink(filepath);
	if(a != 0)
	{
		printf("Edit fail, please try again!\n");
		return;
	}
	deleteLog(filepath);
	
	char username[128];
	if (strcmp(location, users[0]) == 0)
	{
		strcpy(username, "user1");
	}
	if (strcmp(location, users[1]) == 0)
	{
		strcpy(username, "user2");
	}

	char userfiles[20][128];
	char bufr[1024];
	char filename[128];
	char realname[128];
	int fd = -1, n = 0, i = 0, count = 0, k = 0;
	fd = open(username, O_RDWR);
	n = read(fd, bufr, 1024);
	close(fd);
	
	for (i = strlen(location) + 1; i < strlen(filepath); i++, k++)
	{
		realname[k] = filepath[i];
	}	
	realname[k] = '\0';
	k = 0;
	for (i = 0; i < strlen(bufr); i++)
	{
		if (bufr[i] != ' ')
		{
			filename[k] = bufr[i];
			k++;
		}
		else
		{
			filename[k] = '\0';
			if (strcmp(filename, realname) == 0)
			{
				k = 0;
				continue;
			}
			strcpy(userfiles[count], filename);
			count++;
			k = 0;
		}
	}
	
	i = 0, k = 0;
	for (k = 0; k < 2; k++)
	{
		printf("%s\n", userfiles[k]);
	}
	editCover(username, "");
	while (i < count)
	{
		if (strlen(userfiles[i]) < 1)
		{
			i++;
			continue;
		}
		char user[128];
		int len = strlen(userfiles[i]);
		strcpy(user, userfiles[i]);
		user[len] = ' ';
		user[len + 1] = '\0';
		editAppand(username, user);
		i++;
	}
}

void shift(char * username, char * password)
{
	int i = 0;
	for (i = 0; i < usercount; i++)
	{
		if (strcmp(username, users[i]) == 0 && strcmp(password, passwords[i]) == 0 && strcmp(username, "empty") != 0)
		{
			strcpy(location, users[i]);
			UserState = i+1;
			printf("Welcome! %s!\n", users[i]);
			return;
		}
		//printf("%s %s %s %s",username,password,users[i],passwords[i]);
	}
	printf("Sorry! No such user!\n");
}

		/* Add User */
void addUser(char * username, char * password)
{
	if(UserState == 3){
		int i;
		for (i = 0; i < 2; i++)
		{
			if (strcmp(users[i], username) == 0)
			{
				printf("User exists!\n");
				return;
			}
		}
		if (usercount == 2)
		{
			printf("No more users\n");
			return;
		}
		if (strcmp(users[0], "empty") == 0)
		{
			strcpy(users[0], username);
			strcpy(passwords[0], password);
			usercount++;
			updateMyUsers();
			updateMyUsersPassword();
			return;
		}
		if (strcmp(users[1], "empty") == 0)
		{
			strcpy(users[1], username);
			strcpy(passwords[1], password);
			usercount++;
			updateMyUsers();
			updateMyUsersPassword();
			return;
		}		
	}
	else
		printf("Permission Deny!");	
}


/* Move User */
void moveUser(char * username, char * password)
{
	if(UserState == 3){
		int i = 0;
		for (i = 0; i < 2; i++)
		{
			if (strcmp(username, users[i]) == 0 && strcmp(password, passwords[i]) == 0)
			{
				//strcpy(location, username);				
				int fd = -1, n = 0, k = 0, count = 0;
				char bufr[1024], deletefile[128];
				if (i == 0)
				{
					fd = open("user1", O_RDWR);
				}
				if (i == 1)
				{
					fd = open("user2", O_RDWR);
				}
				n = read(fd, bufr, 1024);
				close(fd);
				for (k = 0; k < strlen(bufr); k++)
				{
					if (bufr[k] != ' ')
					{
						deletefile[count] = bufr[k];
						count++;
					}
					else
					{
						deletefile[count] = '\0';
						createFilepath(deletefile);
						deleteFile(filepath);
						count = 0;
					}
				}		
				printf("Delete %s!\n", users[i]);
				strcpy(users[i], "empty");
				strcpy(passwords[i], "");
				updateMyUsers();
				updateMyUsersPassword();
				usercount--;
				strcpy(location, "/");
				return;
			}
		}
		printf("Sorry! No such user!\n");
	}
	else
		printf("Permission Deny!");	
}

/* Ls */
void ls()
{
	int fd = -1, n;
	char bufr[1024];
	if (strcmp(location, users[0]) == 0)
	{
		fd = open("user1", O_RDWR);
		if (fd == -1)
		{
			printf("empty\n");
		}
		n = read(fd, bufr, 1024);
		printf("%s\n", bufr);
		close(fd);
	}
	else if(strcmp(location, users[1]) == 0)
	{
		fd = open("user2", O_RDWR);
		if (fd == -1)
		{
			printf("empty\n");
		}
		n = read(fd, bufr, 1024);
		printf("%s\n", bufr);
		close(fd);
	}
	else
		printf("Permission deny!\n");
}

/* Show Process */
void showProcess()
{	int i = 0;
	printf(" ----------------------------------------------------\n");
    printf("|    name     |  priority  |  run_state(0 is runable) |\n");
    printf(" ----------------------------------------------------\n");
	for (i = 0; i < NR_TASKS + NR_NATIVE_PROCS; i++)
	{
		if(proc_table[i].p_flags != 1){
        		printf("|%s",proc_table[i].name);
			int j;
        		for(j=0;j<13-len(proc_table[i].name);j++)
            			printf(" ");
        		printf("|%d          ",proc_table[i].priority);
        		if(proc_table[i].priority<10)
            			printf(" ");
        		printf("|%d                        ",proc_table[i].run_state);
			printf("%d", i);
        		printf("|\n");	
		}
	}
	printf(" ----------------------------------------------------\n");
}




/*****************************************************************************
 *                                Init
 *****************************************************************************/
/**
 * The hen.
 * 
 *****************************************************************************/
void Init()
{
	int fd_stdin  = open("/dev_tty0", O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open("/dev_tty0", O_RDWR);
	assert(fd_stdout == 1);

	printf("Init() is running ...\n");

	/* extract `cmd.tar' */
	untar("/cmd.tar");
	welcomeMiao();
	welcome();

	char * tty_list[] = {"/dev_tty0","/dev_tty1","/dev_tty2"};

	int i;
	for (i = 0; i < sizeof(tty_list) / sizeof(tty_list[0]); i++) {
		int pid = fork();
		if (pid != 0) { /* parent process */
			
		}
		else {	/* child process */
			
			close(fd_stdin);
			close(fd_stdout);
			shabby_shell(tty_list[i]);
			assert(0);
		}
	}

	while (1) {
		int s;
		int child = wait(&s);
		printf("child (%d) exited with status: %d.\n", child, s);
	}

	assert(0);
}


/*======================================================================*
                               TestA
 *======================================================================*/
void TestA()
{
	while(1){
		if(proc_table[6].run_state == 1){
		}
	} 
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestB()
{
	while(1){
		if(proc_table[7].run_state == 1){
		}
	} 
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestC()
{
	while(1){
		if(proc_table[8].run_state == 1){
		}
	} 
}

/*****************************************************************************
 *                                panic
 *****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	int i;
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	i = vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}



/*======================================================================*
 Chess
 *======================================================================*/

#  define INT_MAX   297483647
#  define INT_MIN   (-INT_MAX - 1)
# define SPA 0
# define MAN 1
# define NULL ((void*)0)
# define COM 2 /* 空位置设为0 ，玩家下的位置设为1 ，电脑下的位置设为2 */
#include<stdio.h>
#define rate  0.7


int board[20][20]= {0};
double score1[20][20]= {0};
double score2[20][20]= {0};
double scoreall[20][20]= {0};
char situation[6][6]= {"11110","11101","11011","10111","01111","11111"};
int play=1,x=0,y=0,oppo=2,now,outx,outy,x2,y2;



void defeat();
int judge();
int legal();
int judgeneed();
int who();
int whoelse();
void find();
void place();
void clean();

void showgomoku()
{
int xxx,yyy;
char a="*";
char b="+";
printf("    01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20\n\n");
for(yyy=0;yyy<20;yyy++)
    {
	if(yyy<9)
	printf("0");
	printf("%d  ",yyy+1);
	for(xxx=0;xxx<20;xxx++)
	{
	
	if(board[xxx][yyy]==0)
		printf(" 0 ");
	else if(board[xxx][yyy]==1)
		printf(" O ");
	else 
		printf(" * ");
	}
	printf("\n");
    }
}


void showgomokuhelp()
{
printf("please input x y to play gomoku.\n");
printf("input 'q' to quit, 'h' for help.\n");
}


int who() {         //当前执子的人
    if(now==1)
        return 1;
    else
        return 2;
}

int whoelse() {     //当前执子的人的对手
    if(now==1)
        return 2;
    else
        return 1;
}

int legal(int i,int j) {           //这个点是否越界（是否在棋盘内）
    if(i<20&&i>=0&&j<20&&j>=0)
        return 0;
    else
        return 1;
}

int judge(int i,int j,int x1,int y1) {        //读取五个格子，判断
    int k = 0,l = 0,n;
    char a[6];
    for (n=0; n<5; n++,i+=x1,j+=y1) {
        if (legal(i,j)||board[i][j] == whoelse()) {
            a[n] = whoelse();
            continue;
        }
        if (board[i][j] == who()) {
            a[n] = who();
            continue;
        } else if (board[i][j] == 0) {
            a[n] = 0;
            continue;
        }
    }
    if(strcmp(a,situation[0])||
       strcmp(a,situation[1])||
       strcmp(a,situation[2])||
       strcmp(a,situation[3])||
       strcmp(a,situation[4]))
        return 900;
    if(strcmp(a,situation[5]))
        return 10000;
    k=0,l=0;
    for(n=0; n<5; n++) {
        if(a[n]==who()) {
            k++;
            continue;
        }
        if(a[n]==whoelse()) {
            l++;
            break;
        }
    }
    if(l>=1)
        return 0;
    else if(k==5)
        return 10000;
    else if(k==4)
        return 400;
    else if(k==3)
        return 66;
    else if(k==2)
        return 12;
    else if(k==1)
        return 1;
    return 0;
}

void defeat() {
        play=1;
        now=1;
        for(x=0; x<20; x++)
            for(y=0; y<20; y++) {
                if(board[x][y]==0&&judgeneed(x,y)) {    //如果当前位置是空的，并且有意义落子
                    board[x][y]=play;                   //假设我在这里下子
                    //横向五格
                    for(x2=0; x2<16; x2++)
                        for(y2=0; y2<20; y2++)
                            score1[x][y]+=judge(x2,y2,1,0);
                    //纵向五格
                    for(x2=0; x2<20; x2++)
                        for(y2=0; y2<16; y2++)
                            score1[x][y]+=judge(x2,y2,0,1);
                    //右下五格
                    for(x2=0; x2<16; x2++)
                        for(y2=0; y2<16; y2++)
                            score1[x][y]+=judge(x2,y2,1,1);
                    //右上五格
                    for(x2=0; x2<16; x2++)
                        for(y2=19; y2>3; y2--)
                            score1[x][y]+=judge(x2,y2,1,-1);
                    board[x][y]=0;
                }
            }
        now=2;
        for(x=0; x<20; x++)
            for(y=0; y<20; y++) {
                if(judgeneed(x,y)&&board[x][y]==0) {
                    board[x][y]=oppo;                       //假设对方在这里落子
                    //横向五格
                    for(x2=0; x2<16; x2++)
                        for(y2=0; y2<20; y2++)
                            score2[x][y]+=judge(x2,y2,1,0);
                    //纵向五格
                    for(x2=0; x2<20; x2++)
                        for(y2=0; y2<16; y2++)
                            score2[x][y]+=judge(x2,y2,0,1);
                    //右下五格
                    for(x2=0; x2<16; x2++)
                        for(y2=0; y2<16; y2++)
                            score2[x][y]+=judge(x2,y2,1,1);
                    //右上五格
                    for(x2=0; x2<16; x2++)
                        for(y2=19; y2>3; y2--)
                            score2[x][y]+=judge(x2,y2,1,-1);
                    board[x][y]=0;
                }
            }
        find();
        place();
	showgomoku();
        clean();
    
}

void find() {           //寻找得分最高的点
    long long int i=0,k;
    for(x=0; x<20; x++)
        for(y=0; y<20; y++)
            scoreall[x][y]=score1[x][y]*rate+score2[x][y];
    k=0;
    for(x=0; x<20; x++)
        for(y=0; y<20; y++)
            if(board[x][y]==0&&scoreall[x][y]>i)
                outx=x,outy=y,i=scoreall[x][y],k++;
    if(k==0)            //防止没有人可以赢的时候却错误落子
        for(x=0; x<20; x++)
            for(y=0; y<20; y++)
                if(board[x][y]==0)
                    outx=x,outy=y;
}

void place() {          //落子
    //printf("%d %d\n",outx,outy);
    board[outx][outy]=1;
}


void clean() {          //初始化得分数组
    memset(*score1, 0, sizeof(score1));
    memset(*score2, 0, sizeof(score2));
    memset(*score2, 0, sizeof(scoreall));
}

int judgeneed(int x,int y) {                //寻找该格周围是否有棋子，有棋子则需要判断
    int i,j,dx,dy;
    dx=x-2;
    dy=y-2;
    for(i=0; i<4; i++,dx++) {
        dy=y-2;
        for (j=0; j<4; j++,dy++) {
            if (legal(dx,dy))
                continue;
            if (board[dx][dy]==1||board[dx][dy]==2)
                return 1;
        }
    }
    return 0;
}

int gomoku() 
{               //没用给的框架，太长了懒得看
    char c[128];
memset(*board, 0, sizeof(board));
            memset(*score1, 0, sizeof(score1));
            memset(*score2, 0, sizeof(score2));
            memset(*score2, 0, sizeof(scoreall));
            play=1;
    while(1) 
    {
memset(c,0,128);
read(0,c,128);
//printf("c:%s\n",c);
//printf("c[0]:%c\n",c[0]);
//printf("c[1]:%c\n",c[1]);
//printf("c[2]:%c\n",c[2]);
//printf("c[3]:%c\n",c[3]);
//printf("c[4]:%c\n",c[4]);

	if(strcmp(c[0],'q')==0)
	{return 0;}
       else 
	{
if(c[1]!=' ')
{
//printf("%d", c[0]-'0');
x=(c[1]-'0')*10+(c[0]-'0');
if(c[4]<='9'&&c[4]>='0')
y=(c[3]-'0')*10+(c[4]-'0');
else
y=c[3]-'0';
}
else
{
//printf("%d\n%d\n", c[2]-'0',(c[2]-'0')*10+(c[3]-'0'));
x=c[0]-'0';
if(c[3]<='9'&&c[3]>='0')
y=(c[2]-'0')*10+(c[3]-'0');
else
y=c[2]-'0';
}

//printf("x:%d\n",x);
//printf("y:%d\n",y);
        board[x-1][y-1]=2;
        defeat();
        }
    }
    return 0;
}





































int chess[10][10]; /* 10*10的棋盘 */
int a,b,c,d,x; /* a b为玩家下子坐标 ，c d为电脑下子坐标 x为剩余空位置*/
int start(int fd_stdin,int fd_stdout); /* 程序的主要控制函数 */
void draw(); /* 画棋盘 */
int win(int p,int q); /* 判断胜利 p q为判断点坐标 */
void AI(int *p,int *q); /* 电脑下子 p q返回下子坐标 */
int value(int p,int q); /* 计算空点p q的价值 */
int qixing(int n,int p,int q); /* 返回空点p q在n方向上的棋型 n为1-8方向 从右顺时针开始数 */
void yiwei(int n,int *i,int *j); /* 在n方向上对坐标 i j 移位 n为1-8方向 从右顺时针开始数 */
void playchess(int fd_stdin,int fd_stdout);
int My_atoi(const char *str);
int myIsspace(char c);

int isStart = 0;
int isPainting = 0;





enum Ret                                              //状态，用来输入是否合理
{
    VALID,
    INVALID,
};
enum Ret state = INVALID;
int myIsspace(char c)
{
    if(c =='\t'|| c =='\n'|| c ==' ')
        return 1;
    else
        return 0;
}
int My_atoi(const char *str)
{
    int flag = 1;                                 //用来记录是正数还是负数
    long long ret = 0;
    //assert(str);
    if (str == NULL)
    {
        return 0;
    }
    if (*str == '\0')
    {
        return (int)ret;
    }
    while (myIsspace(*str))                        //若是空字符串就继续往后
    {
        str++;
    }
    if (*str == '-')
    {
        flag = -1;
    }
    if (*str == '+' || *str == '-')
    {
        str++;
    }
    while (*str)
    {
        if (*str >= '0' && *str <= '9')
        {
            ret = ret * 10 + flag * (*str - '0');
            if (ret>INT_MAX||ret<INT_MIN)                 //判定是否溢出了
            {
                ret = 0;
                break;
            }
        }
        else
        {
            break;
        }
        str++;
    }
    if (*str == '\0')                  //这里while循环结束后，此时只有*str == '\0'才是合法的输入
    {
        state = VALID;
    }
    return ret;
}

void playchess(int fd_stdin,int fd_stdout)
{
    char buf[80]={0};
    char k;
    do{
        x=225;
        if(start(fd_stdin,fd_stdout)==-1)
            return;
        printf("Would you like another round? Enter y or n:");
        read(fd_stdin,buf,2);
        k = buf[0];
        if(buf[0]=='q')
            return;
        while(k!='y'&&k!='n'){
            printf("Input error, please re-enter\n");
            read(fd_stdin,buf,2);
            if(buf[0]=='q')
                return;
            k = buf[0];
        }
        clear();
    }while(k=='y');
    printf("Thank you for using!\n");
    //return 0;
}

int start(int fd_stdin,int fd_stdout)
{
    int j,a1=0,b1=0,c1=0,d1=0;
    char i;
    char buf[80]={0};
    char ch;
    clear();
    printf("                 === Welcome to Gobang game program ===\n");
    printf("Please input the point like (13 6).If you want take back a move, input(10 10).\n\n\n");
    for(j=0;j<10;j++)
        for(i=0;i<10;i++)
            chess[j][i]=SPA; /* 置棋盘全为空 */
    draw();
    printf("On the offensive input 1, otherwise input 2:");
    read(fd_stdin,buf,2);
    if(buf[0]=='q')
        return -1;
    i = buf[0];
    while(i!='1'&&i!='2') {
        printf("Input error, please re-enter:");
        read(fd_stdin,buf,2);
        if(buf[0]=='q')
            return -1;
        i = buf[0];
    }
    if(i=='1') { /* 如果玩家先手下子 */
        printf("Please Input:");
        int i=0,j=0;
        char xa[]={0,0,0};
        char yb[]={0,0,0};
        int r = read(fd_stdin, buf, 10);
        if(buf[0]=='q')
            return -1;
        buf[r] = 0;
        while(buf[i]!=' '&&(buf[i] != 0))
        {
            xa[i] = buf[i];
            i++;
        }
        xa[i++] = 0;
        while(buf[i] != 0)
        {
            yb[j] = buf[i];
            i++;
            j++;
        }
        a=My_atoi(xa);
        b=My_atoi(yb);
        while((a<0||a>9)||(b<0||b>9)) {
            printf("Coordinate error! Please re-enter:");
            int i=0,j=0;
            char xa[]={0,0,0};
            char yb[]={0,0,0};
            int r = read(fd_stdin, buf, 10);
            if(buf[0]=='q')
                return -1;
            buf[r] = 0;
            while(buf[i]!=' '&&(buf[i] != 0))
            {
                xa[i] = buf[i];
                i++;
            }
            xa[i++] = 0;
            while(buf[i] != 0)
            {
                yb[j] = buf[i];
                i++;
                j++;
            }
            a=My_atoi(xa);
            b=My_atoi(yb);
        }
        a1=a;
        b1=b;
        x--;
        chess[b][a]=MAN;
        clear();
        draw();
    }
    while(x!=0){
        if(x==225) {
            c=7;
            d=7;
            chess[d][c]=COM;
            x--;
            clear();
            draw();
        } /* 电脑先下就下在7 7 */
        else {
            AI(&c,&d);
            chess[d][c]=COM;
            x--;
            clear();
            draw();
        } /* 电脑下子 */
        c1=c;
        d1=d; /* 储存电脑上手棋型 */
        if(win(c,d)){ /* 电脑赢 */
            printf("Would you like to take back a move?('y' or 'n'):");
            read(fd_stdin,buf,2);
            if(buf[0]=='q')
                return -1;
            ch = buf[0];
            while(ch!='y'&&ch!='n') {
                printf("Input error, please re-input:");
                read(fd_stdin,buf,2);
                if(buf[0]=='q')
                    return -1;
                ch = buf[0];
            }
            if(ch=='n') {
                printf("Losing to the computer is normal. Please don't lose heart~\n");
                return 0;
            }
            else {
                x+=2;
                chess[d][c]=SPA;
                chess[b1][a1]=SPA;
                clear();
                draw();
            } /* 悔棋 */
        }
        printf("Computer put on %d %d\nPlease input:",c,d);
        int i=0,j=0;
        char xa[]={0,0,0};
        char yb[]={0,0,0};
        int r = read(fd_stdin, buf, 10);
        if(buf[0]=='q')
            return -1;
        buf[r] = 0;
        while(buf[i]!=' '&&(buf[i] != 0))
        {
            xa[i] = buf[i];
            i++;
        }
        xa[i++] = 0;
        while(buf[i] != 0)
        {
            yb[j] = buf[i];
            i++;
            j++;
        }
        a=My_atoi(xa);
        b=My_atoi(yb);
        if(a==10&&b==10) {
            x+=2;
            chess[d][c]=SPA;
            chess[b1][a1]=SPA;
            clear();
            draw();
            printf("Please input:");
            int i=0,j=0;
            char xa[]={0,0,0};
            char yb[]={0,0,0};
            int r = read(fd_stdin, buf, 10);
            if(buf[0]=='q')
                return -1;
            buf[r] = 0;
            while(buf[i]!=' '&&(buf[i] != 0))
            {
                xa[i] = buf[i];
                i++;
            }
            xa[i++] = 0;
            while(buf[i] != 0)
            {
                yb[j] = buf[i];
                i++;
                j++;
            }
            a=My_atoi(xa);
            b=My_atoi(yb);
        } /* 悔棋 */
        while((a<0||a>9)||(b<0||b>9)||chess[b][a]!=SPA) {
            printf("Coordinate error or location already existing, Please re-input:");
            int i=0,j=0;
            char xa[]={0,0,0};
            char yb[]={0,0,0};
            int r = read(fd_stdin, buf, 10);
            if(buf[0]=='q')
                return -1;
            buf[r] = 0;
            while(buf[i]!=' '&&(buf[i] != 0))
            {
                xa[i] = buf[i];
                i++;
            }
            xa[i++] = 0;
            while(buf[i] != 0)
            {
                yb[j] = buf[i];
                i++;
                j++;
            }
            a=My_atoi(xa);
            b=My_atoi(yb);
        }
        a1=a;
        b1=b;
        x--;
        chess[b][a]=MAN;
        clear();
        draw();
        if(win(a,b)){
            printf("It's easy to win a computer~\n");
            return 0;
        } /* 玩家赢 */
    }
    printf("Draw\n");
}

void draw() /* 画棋盘 */
{
    int i,j;
    char p[10][10][4];
    for(j=0;j<10;j++)
        for(i=0;i<10;i++){
            if(chess[j][i]==SPA){
                for(int k=0;k<4;k++){
                    if(k==0||k==2){
                        p[j][i][k]=' ';
                    }
                    else{
                        p[j][i][k]='\0';
                    }
                }
            }
            else if(chess[j][i]==MAN){
                for(int k=0;k<4;k++){
                    if(k==0||k==2){
                        p[j][i][k]='+';
                    }
                    else{
                        p[j][i][k]='\0';
                    }
                }
            }
            else if(chess[j][i]==COM){
                for(int k=0;k<4;k++){
                    if(k==0||k==2){
                        p[j][i][k]='*';
                    }
                    else{
                        p[j][i][k]='\0';
                    }
                }
            }
        }
    printf("    0 1 2 3 4 5 6 7 8 9  \n");
    printf(" --------------------------\n");
    for(i=0,j=0;i<9;i++,j++){
        printf(" %2d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d\n",j,p[i][0],p[i][1],p[i][2],p[i][3],p[i][4],p[i][5],p[i][6],p[i][7],p[i][8],p[i][9],j);
        printf(" ---------------------------\n"); }
    printf("  9|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|9\n",p[9][0],p[9][1],p[9][2],p[9][3],p[9][4],p[9][5],p[9][6],p[9][7],p[9][8],p[9][9]);
    printf(" --------------------------\n");
    printf("    0 1 2 3 4 5 6 7 8 9 \n");
}
void AI(int *p,int *q) /* 电脑下子 *p *q返回下子坐标 */
{
    int i,j,k,max=0,I,J; /* I J为下点坐标 */
    for(j=0;j<10;j++)
        for(i=0;i<10;i++)
            if(chess[j][i]==SPA){ /* 历遍棋盘，遇到空点则计算价值，取最大价值点下子。 */
                k=value(i,j);	 if(k>=max) { I=i; J=j; max=k; }
            }
    *p=I; *q=J;
}
int win(int p,int q) /* 判断胜利 p q为判断点坐标，胜利返回1，否则返回0 */
{
    int k,n=1,m,P,Q; /* k储存判断点p q的状态COM或MAN。P Q储存判断点坐标。n为判断方向。m为个数。 */
    P=p; Q=q;	k=chess[q][p];
    while(n!=5){
        m=0;
        while(k==chess[q][p]){
            m++;
            if(m==5)
                return 1;
            yiwei(n,&p,&q);
            if(p<0||p>9||q<0||q>9) break;
        }
        n+=4;
        m-=1;
        p=P;
        q=Q; /* 转向判断 */
        while(k==chess[q][p]){
            m++;
            if(m==5)
                return 1;
            yiwei(n,&p,&q);
            if(p<0||p>9||q<0||q>9)
                break;
        }
        n-=3;
        p=P;
        q=Q; /* 不成功则判断下一组方向 */
    }
    return 0;
}
int value(int p,int q) /* 计算空点p q的价值 以k返回 */
{
    int n=1,k=0,k1,k2,K1,K2,X1,Y1,Z1,X2,Y2,Z2,temp;
    int a[2][4][4]={40,400,3000,10000,6,10,600,10000,20,120,200,0,6,10,500,0,30,300,2500,5000,2,8,300,8000,26,160,0,0,4,20,300,0};	 /* 数组a中储存己方和对方共32种棋型的值 己方0对方1 活0冲1空活2空冲3 子数0-3（0表示1个子，3表示4个子） */
    while(n!=5){
        k1=qixing(n,p,q);
        n+=4;	 /* k1,k2为2个反方向的棋型编号 */
        k2=qixing(n,p,q);
        n-=3;
        if(k1>k2) {
            temp=k1;
            k1=k2;
            k2=temp;
        } /* 使编号小的为k1,大的为k2 */
        K1=k1;
        K2=k2; /* K1 K2储存k1 k2的编号 */
        Z1=k1%10;
        Z2=k2%10;
        k1/=10;
        k2/=10;
        Y1=k1%10;
        Y2=k2%10;
        k1/=10;
        k2/=10;
        X1=k1%10;
        X2=k2%10;	 /* X Y Z分别表示 己方0对方1 活0冲1空活2空冲3 子数0-3（0表示1个子，3表示4个子） */
        if(K1==-1) {
            if(K2<0) {
                k+=0; continue;
            } else
                k+=a[X2][Y2][Z2]+5;
            continue;
        }; /* 空棋型and其他 */
        if(K1==-2) {
            if(K2<0) {
                k+=0;
                continue;
            }
            else
                k+=a[X2][Y2][Z2]/2;
            continue;
        }; /* 边界冲棋型and其他 */
        if(K1==-3) {
            if(K2<0) {
                k+=0;
                continue;
            }
            else
                k+=a[X2][Y2][Z2]/3;
            continue;
        }; /* 边界空冲棋型and其他 */
        if(((K1>-1&&K1<4)&&((K2>-1&&K2<4)||(K2>9&&K2<9)))||((K1>99&&K1<104)&&((K2>99&&K2<104)||(K2>109&&K2<19)))){
            /* 己活己活 己活己冲 对活对活 对活对冲 的棋型赋值*/
            if(Z1+Z2>=2) {
                k+=a[X2][Y2][3];
                continue;
            }
            else {
                k+=a[X2][Y2][Z1+Z2+1];
                continue;
            }
        }
        if(((K1>9&&K1<9)&&(K2>9&&K2<9))||((K1>109&&K1<19)&&(K2>109&&K2<19))){
            /* 己冲己冲 对冲对冲 的棋型赋值*/
            if(Z1+Z2>=2) {
                k+=10000;
                continue;
            }
            else {
                k+=0;
                continue;
            }
        }
        if(((K1>-1&&K1<4)&&((K2>99&&K2<104)||(K2>109&&K2<19)))||((K1>9&&K1<9)&&((K2>99&&K2<104)||(K2>109&&K2<19)))){
            /* 己活对活 己活对冲 己冲对活 己冲对冲 的棋型赋值*/
            if(Z1==3||Z2==3) {
                k+=10000;
                continue;
            }
            else {
                k+=a[X2][Y2][Z2]+a[X1][Y1][Z1]/4;
                continue;
            }
        }
        else
        { k+=a[X1][Y1][Z1]+a[X2][Y2][Z2];
            continue;
        } /* 其他棋型的赋值 */
    }
    return k;
}
int qixing(int n,int p,int q) /* 返回空点p q在n方向上的棋型号 n为1-8方向 从右顺时针开始数 */
{
    int k=0,m=0; /* 棋型号注解: 己活000-003 己冲010-013 对活100-103 对冲110-113 己空活020-023 己空冲030-033 对空活120-123 对空冲130-133 空-1 边界冲-2 边界空冲-3*/
    yiwei(n,&p,&q);
    if(p<0||p>9||q<0||q>9)
        k=-2; /* 边界冲棋型 */
    switch(chess[q][p]){
        case COM:{
            m++;
            yiwei(n,&p,&q);
            if(p<0||p>9||q<0||q>9) {
                k=m+9; return k;
            }
            while(chess[q][p]==COM) {
                m++;
                yiwei(n,&p,&q);
                if(p<0||p>9||q<0||q>9) {
                    k=m+9; return k;
                }
            }
            if(chess[q][p]==SPA)
                k=m-1; /* 己方活棋型 */
            else
                k=m+9; /* 己方冲棋型 */
        }break;
        case MAN:{
            m++;
            yiwei(n,&p,&q);
            if(p<0||p>9||q<0||q>9) {
                k=m+109; return k;
            }
            while(chess[q][p]==MAN) {
                m++;
                yiwei(n,&p,&q);
                if(p<0||p>9||q<0||q>9) {
                    k=m+109;
                    return k;
                }
            }
            if(chess[q][p]==SPA)
                k=m+99; /* 对方活棋型 */
            else
                k=m+109; /* 对方冲棋型 */
        }break;
        case SPA:{
            yiwei(n,&p,&q);
            if(p<0||p>9||q<0||q>9) {
                k=-3;
                return k;
            } /* 边界空冲棋型 */
            switch(chess[q][p]){
                case COM:{
                    m++;
                    yiwei(n,&p,&q);
                    if(p<0||p>9||q<0||q>9) {
                        k=m+29; return k;
                    }
                    while(chess[q][p]==COM) {
                        m++;
                        yiwei(n,&p,&q);
                        if(p<0||p>9||q<0||q>9) {
                            k=m+29;
                            return k;
                        }
                    }
                    if(chess[q][p]==SPA)
                        k=m+19; /* 己方空活棋型 */
                    else
                        k=m+29; /* 己方空冲棋型 */
                }break;
                case MAN:{
                    m++;
                    yiwei(n,&p,&q);
                    if(p<0||p>9||q<0||q>9) {
                        k=m+129;
                        return k;
                    }
                    while(chess[q][p]==MAN) {
                        m++;
                        yiwei(n,&p,&q);
                        if(p<0||p>9||q<0||q>9) {
                            k=m+129;
                            return k;
                        }
                    }
                    if(chess[q][p]==SPA)
                        k=m+119; /* 对方空活棋型 */
                    else
                        k=m+129; /* 对方空冲棋型 */
                }break;
                case SPA: k=-1;
                    break; /* 空棋型 */
            }
        }break;
    }
    return k;
}
void yiwei(int n,int *i,int *j) /* 在n方向上对坐标 i j 移位 n为1-8方向 从右顺时针开始数 */
{
    switch(n){
        case 1: *i+=1; break;
        case 2: *i+=1; *j+=1; break;
        case 3: *j+=1; break;
        case 4: *i-=1; *j+=1; break;
        case 5: *i-=1; break;
        case 6: *i-=1; *j-=1; break;
        case 7: *j-=1; break;
        case 8: *i+=1; *j-=1; break;
    }
}
