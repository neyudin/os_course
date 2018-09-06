#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "defs.h"
#include "x86.h"
#include "elf.h"

enum//my enum
{
  PATH_MAX = 100,
  MAX_EXEC_NUM = 6
};

int
exec(char *path, char **argv, int cur_exec_num)
{
  if (cur_exec_num > MAX_EXEC_NUM) {
    return -1;
  }
  char *s, *last;
  int i, off;
  uint argc, sz, sp, ustack[3+MAXARG+1];
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pde_t *pgdir, *oldpgdir;
  /**my variables*/
  char checkstr[3] = {0};
  char *prev_argv[MAXARG] = {0};
  char new_path[PATH_MAX] = {0};
  char *temp_1, *temp_2;
  int dif, count, already_read;
  /**my variables*/

  begin_op();
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);
  pgdir = 0;

  // Check ELF header
  if(readi(ip, (char*)&elf, 0, sizeof(elf)) < sizeof(elf)) {/**my development*/
    goto good;
  }
  if(elf.magic != ELF_MAGIC) {
    good:
    for (dif = sizeof(checkstr), already_read = 0; dif > 0; dif -= count) {
      count = readi(ip, (char *) checkstr + already_read, already_read, 1);
      if (count <= 0) {
        goto bad;
      }
      already_read += count;
    }
    if (checkstr[0] != '#' || checkstr[1] != '!' || checkstr[2] != '/') {
      goto bad;
    }
    for (dif = 1, already_read = 0; dif > 0; dif -= count) {
      count = readi(ip, (char *) new_path + already_read, 2 + already_read, 1);
      if (count <= 0) {
        goto bad;
      }
      already_read += count;
      ++dif;
      if (new_path[already_read - 1] == '\n') {
        new_path[already_read - 1] = 0;
        break;
      }
    }
    if (argv[MAXARG - 2]) {
      goto bad;
    }
    for (i = 0; i < MAXARG; ++i) {
      prev_argv[i] = argv[i];
    }
    for (i = 1, temp_2 = argv[0]; i < MAXARG; ++i) {
      temp_1 = argv[i];
      argv[i] = temp_2;
      temp_2 = temp_1;
    }
    argv[0] = new_path;
    argv[1] = path;
    iunlockput(ip);
    end_op();
    ip = 0;
    if (exec(new_path, argv, ++cur_exec_num) != 0) {
      for (i = 0; i < MAXARG; ++i) {
        argv[i] = prev_argv[i];
      }
      return -1;
    }
    return 0;
  }/**my development*/

  if((pgdir = setupkvm()) == 0)
    goto bad;

  // Load program into memory.
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, (char*)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if(loaduvm(pgdir, (char*)ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  // Allocate two pages at the next page boundary.
  // Make the first inaccessible.  Use the second as the user stack.
  sz = PGROUNDUP(sz);
  if((sz = allocuvm(pgdir, sz, sz + 2*PGSIZE)) == 0)
    goto bad;
  clearpteu(pgdir, (char*)(sz - 2*PGSIZE));
  sp = sz;

  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp = (sp - (strlen(argv[argc]) + 1)) & ~3;
    if(copyout(pgdir, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[3+argc] = sp;
  }
  ustack[3+argc] = 0;

  ustack[0] = 0xffffffff;  // fake return PC
  ustack[1] = argc;
  ustack[2] = sp - (argc+1)*4;  // argv pointer

  sp -= (3+argc+1) * 4;
  if(copyout(pgdir, sp, ustack, (3+argc+1)*4) < 0)
    goto bad;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(proc->name, last, sizeof(proc->name));

  // Commit to the user image.
  oldpgdir = proc->pgdir;
  proc->pgdir = pgdir;
  proc->sz = sz;
  proc->tf->eip = elf.entry;  // main
  proc->tf->esp = sp;
  switchuvm(proc);
  freevm(oldpgdir);
  return 0;

 bad:
  if(pgdir)
    freevm(pgdir);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}
