// libzpoline.so

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <dis-asm.h>
#include <sched.h>
#include <dlfcn.h>

// 注：syscall 调用时，%rdi、%rsi、%rdx、%r10、%r8、%r9 依次存储传入系统调用的参数
// 调用链：asm_syscall_hook -> syscall_hook -> enter_syscall -> syscall

#define SUPPLEMENTAL__REWRITTEN_ADDR_CHECK 1

// 重写地址检查
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK

/*
 * SUPPLEMENTAL: 重写地址检查
 *
 * NOTE: 这个 ifdef 部分是补充性的。 如果您想快速了解zpoline的核心机制，请跳过这里。
 *       
 * the objective of this part is to terminate
 * a null pointer function call.
 *
 * an example is shown below.
 * --
 * void (*null_fn)(void) = NULL;
 *
 * int main(void) {
 *   null_fn();
 *   return 0;
 * }
 * --
 *
 * usually, the code above will cause a segmentation
 * fault because no memory is mapped to address 0 (NULL).
 *
 * however, zpoline maps memory to address 0. therefore, the
 * code above continues to run without causing the fault.
 *
 * this behavior is unusual, thus, we wish to avoid this.
 *
 * our approach here is:
 *
 *   1. during the binrary rewriting phase, record
 *      the addresses of the rewritten syscall/sysenter
 *      instructions (record_replaced_instruction_addr).
 *
 *   2. in the hook function, we check wheter the caller's
 *      address is the one that we conducted the rewriting
 *      or not (is_replaced_instruction_addr).
 *
 *      if not, it means that the program reaches the hook
 *      funtion without going through our replaced callq *%rax.
 *      this typically occurs the program was like the example
 *      code above. after we detect this type of irregular hook
 *      entry, we terminate the program.
 *
 * assuming 0xffffffffffff (256TB : ((1UL << 48) - 1)) as max virtual address (48-bit address)
 *
 */

#define BM_SIZE ((1UL << 48) >> 3)
static char *bm_mem = NULL;

static void bitmap_set(char bm[], unsigned long val)
{
	bm[val >> 3] |= (1 << (val & 7));
}

static bool is_bitmap_set(char bm[], unsigned long val)
{
	return (bm[val >> 3] & (1 << (val & 7)) ? true : false);
}

static void record_replaced_instruction_addr(uintptr_t addr)
{
	assert(addr < (1UL << 48));
	bitmap_set(bm_mem, addr);
}

static bool is_replaced_instruction_addr(uintptr_t addr)
{
	assert(addr < (1UL << 48));
	return is_bitmap_set(bm_mem, addr);
}

#endif

// 外部文件定义了名为 syscall_addr 的函数，不接受任何参数，返回值为 void
// 其余函数类似
extern void syscall_addr(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void asm_syscall_hook(void);

// 用于嵌入汇编代码
void ____asm_impl(void)
{
	// enter_syscall 触发了 syscall
	// volatile 表示不要对这段内联汇编进行优化
	// .globl enter_syscall 表示将 enter_syscall 声明为全局符号
	asm volatile (
	".globl enter_syscall \n\t"
	"enter_syscall: \n\t"
	"movq %rdi, %rax \n\t"                       // rax <- rdi
	"movq %rsi, %rdi \n\t"                       // rdi <- rsi
	"movq %rdx, %rsi \n\t"                       // rsi <- rdx
	"movq %rcx, %rdx \n\t"                       // rdx <- rcx
	"movq %r8, %r10 \n\t"                        // r10 <- r8
	"movq %r9, %r8 \n\t"                         // r8  <- r9
	"movq 8(%rsp),%r9 \n\t"                      // r9  <- [rsp+8]
	".globl syscall_addr \n\t"                   // syscall
	"syscall_addr: \n\t"
	"syscall \n\t"
	"ret \n\t"
	);


	// asm_syscall_hook 是 trampoline 代码首先到达的地址
	// 下面的过程调用名为 syscall_hook 的 C 函数
	// 在 syscall_hook 的入口点，寄存器值遵循 syscall 的调用约定
	asm volatile (
	".globl asm_syscall_hook \n\t"
	"asm_syscall_hook: \n\t"
	"popq %rax \n\t"                             // 重新 pop 到 %rax

	// 忽略 pushed 0x90 for 0xeb 0x6a 0x90 if case 2
	"pushq %rdi \n\t"                           
	"pushq %rax \n\t"                            
	"movabs $0xaaaaaaaaaaaaaaab, %rdi \n\t"      
	"imul %rdi, %rax \n\t"                       
	"cmp %rdi, %rax \n\t"                        // cmp 0xaaaaaaaaaaaaaaab, rax*0xaaaaaaaaaaaaaaab
	"popq %rax \n\t"                            
	"popq %rdi \n\t"                            
	"jb skip_pop \n\t"
	"addq $8, %rsp \n\t"                         // jb: rsp <- rsp+8

	"skip_pop: \n\t"
	"cmpq $15, %rax \n\t"                        // cmp 15, rax
	"je do_rt_sigreturn \n\t"                    // je do_rt_sigreturn

	"pushq %rbp \n\t"
	"movq %rsp, %rbp \n\t"
	"andq $-16, %rsp \n\t"                       // 16 字节对齐
	"pushq %r11 \n\t"
	"pushq %r9 \n\t"
	"pushq %r8 \n\t"
	"pushq %rdi \n\t"
	"pushq %rsi \n\t"
	"pushq %rdx \n\t"
	"pushq %rcx \n\t"
	/* syscall_hook 的参数 */
	"pushq 8(%rbp) \n\t"	                     // push [rbp+8]
	"pushq %rax \n\t"                            // push rax
	"pushq %r10 \n\t"                            // push r10
	"callq syscall_hook \n\t"
	"popq %r10 \n\t"
	"addq $16, %rsp \n\t"	
	"popq %rcx \n\t"
	"popq %rdx \n\t"
	"popq %rsi \n\t"
	"popq %rdi \n\t"
	"popq %r8 \n\t"
	"popq %r9 \n\t"
	"popq %r11 \n\t"
	"leaveq \n\t"                                // %rsp <- %rbp, popq %rbp
	"retq \n\t"

	"do_rt_sigreturn:"
	"addq $8, %rsp \n\t"
	"jmp syscall_addr \n\t"
	);
}

// hook_fn 是一个函数指针，指向 enter_syscall
static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, int64_t a6, int64_t a7) = enter_syscall;

// 定义了 syscall_hook 的函数，其中参数 __rcx 在函数中未被使用
long syscall_hook(int64_t rdi, int64_t rsi, int64_t rdx, int64_t __rcx __attribute__((unused)), int64_t r8, int64_t r9, int64_t r10_on_stack, int64_t rax_on_stack, int64_t retptr)
{
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
	/*
	 * retptr is the caller's address, namely.
	 * "supposedly", it should be callq *%rax that we replaced.
	 */
	if (!is_replaced_instruction_addr(retptr - 2 /* 2 is the size of syscall/sysenter */)) {
		/*
		 * here, we detected that the program comes here
		 * without going through our replaced callq *%rax.
		 *
		 * this can should a bug of the program.
		 *
		 * therefore, we stop the program by int3.
		 */
		asm volatile ("int3");
	}
#endif
	// rax_on_stack 指的是系统调用号
	if (rax_on_stack == __NR_clone3)
		// 高级进程创建，则系统调用不可用，从而回退到 clone 系统调用（普通进程创建）
		return -ENOSYS;

	if (rax_on_stack == __NR_clone) {
		if (rdi & CLONE_VM) {
			// 新进程与父进程共享虚拟内存空间
			// 将返回地址保存到栈上
			rsi -= sizeof(uint64_t);
			*((uint64_t *) rsi) = retptr;
		}
	}
	// 调用 enter_syscall
	return hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
}

struct disassembly_state {
	char *code;
	size_t off;
};

// 重写代码的函数 do_rewrite ，由反汇编器调用
#ifdef NEW_DIS_ASM
static int do_rewrite(void *data, enum disassembler_style style ATTRIBUTE_UNUSED, const char *fmt, ...)
#else
// data 中 code+off 指的是地址，fmt 是此地址对应的指令字符
static int do_rewrite(void *data, const char *fmt, ...)
#endif
{
	struct disassembly_state *s = (struct disassembly_state *) data;
	char buf[4096];
	va_list arg;
	va_start(arg, fmt);
	vsprintf(buf, fmt, arg);
	// 将 syscall 与 sysenter 换为 callq *%rax
	if (!strncmp(buf, "syscall", 7) || !strncmp(buf, "sysenter", 8)) {
		uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
		if ((uintptr_t) ptr == (uintptr_t) syscall_addr) {
			// 此时 code+off 就是指向替换后的 syscall 地址，这是在 trampoline 中的，不必重新复写
			// 跳过将 syscall 替换为 enter_syscall，以便它可以进行 syscall
			goto skip;
		}
		ptr[0] = 0xff; // callq
		ptr[1] = 0xd0; // *%rax
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
		record_replaced_instruction_addr((uintptr_t) ptr);
#endif
	}
skip:
	va_end(arg);
	return 0;
}

// 使用反汇编器查找 syscall 与 sysenter，并进行重写
static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot)
{
	struct disassembly_state s = { 0 };
	// 将 code 指向的内存变为可读可写
	assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
	disassemble_info disasm_info = { 0 };
#ifdef NEW_DIS_ASM
	init_disassemble_info(&disasm_info, &s, (fprintf_ftype) printf, do_rewrite);
#else
	// 反汇编结果通过 do_rewrite 处理
	// 初始化 disasm_info，并指定输出流 s 与输出函数 do_rewrite
	init_disassemble_info(&disasm_info, &s, do_rewrite);
#endif
	// 架构：Intel x86
	disasm_info.arch = bfd_arch_i386;
	// 类型：x86-64
	disasm_info.mach = bfd_mach_x86_64;
	disasm_info.buffer = (bfd_byte *) code;
	disasm_info.buffer_length = code_size;
	disassemble_init_for_target(&disasm_info);
	// disasm 是指向反汇编函数的指针
	disassembler_ftype disasm;
	disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
	s.code = code;
	// 反汇编代码，并将结果保存到 disasm_info 中
	// 每次 disasm 执行完后，就运行 do_rewrite
	while (s.off < code_size)
		s.off += disasm(s.off, &disasm_info);
	// 将内存还原
	assert(!mprotect(code, code_size, mem_prot));
}

// 二进制重写的入口点
static void rewrite_code(void)
{
	FILE *fp;
	// 获得当前进程的内存映射
	/*
		7fffd8e7e000-7fffd8e9f000 rw-p 00000000 00:00 0           [stack]
		7fffd8ebf000-7fffd8ec2000 r--p 00000000 00:00 0           [vvar]
		7fffd8ec2000-7fffd8ec3000 r-xp 00000000 00:00 0           [vdso]
	*/
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);
	{
		char buf[4096];
		// 循环读取 4096 字节的内存，也就是一行
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			// 不对 stack 与 vsyscall 所占的内存做处理
			if (((strstr(buf, "stack") == NULL) && (strstr(buf, "vsyscall") == NULL))) {
				int i = 0;
				char addr[65] = { 0 };
				char *c = strtok(buf, " ");
				while (c != NULL) {
					switch (i) {
					case 0:
						// 7fffd8e7e000-7fffd8e9f000
						strncpy(addr, c, sizeof(addr) - 1);
						break;
					case 1:
						// rw-p
						{
							int mem_prot = 0;
							{
								size_t j;
								for (j = 0; j < strlen(c); j++) {
									if (c[j] == 'r')
										mem_prot |= PROT_READ;
									if (c[j] == 'w')
										mem_prot |= PROT_WRITE;
									if (c[j] == 'x')
										mem_prot |= PROT_EXEC;
								}
							}
							// 如果 code 可执行，那么就进行重写
							if (mem_prot & PROT_EXEC) {
								size_t k;
								// 找到 '-'
								for (k = 0; k < strlen(addr); k++) {
									if (addr[k] == '-') {
										addr[k] = '\0';
										break;
									}
								}
								{
									int64_t from, to;
									from = strtol(&addr[0], NULL, 16);
									if (from == 0) {
										// 起始地址为 0 时为 trampoline 代码，故跳过
										break;
									}
									to = strtol(&addr[k + 1], NULL, 16);
									disassemble_and_rewrite((char *) from, (size_t) to - from, mem_prot);
								}
							}
						}
						bereak;
					}
					if (i == 1)
						break;
					c = strtok(NULL, " ");
					i++;
				}
			}
		}
	}
	fclose(fp);
}

#define NR_syscalls (512)

static void setup_trampoline(void)
{
	void *mem;

	// 分配虚拟地址 0
	mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (mem == MAP_FAILED) {
		fprintf(stderr, "map failed\n");
		fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
		exit(1);
	}

	{
		/*
			论文中在 0-512 中填充 nop(0x90)
			优化后填充 0xeb 0x6a 0x90

			* case 1 : jmp to n * 3 + 0
			* jmp 0x6a（相对跳转）
			* nop
			* jmp 0x6a
			* nop

			* case 2 : jmp to n * 3 + 1
			* push 0x90
			* jmp 0x6a
			* nop
			* jmp 0x6a

			* case 3 : jmp to n * 3 + 2
			* nop
			* jmp 0x6a
			* nop
			* jmp 0x6a			

			对于 case 2，我们忽略堆栈中的 0x90
		*/
		int i;
		for (i = 0; i < NR_syscalls; i++) {
			if (NR_syscalls - 0x6a - 2 < i)
				// 404 -> 512 设置为 nop
				((uint8_t *) mem)[i] = 0x90;
			else {
				// 0 -> 404 设置为 0xeb 0x6a 0x90
				int x = i % 3;
				switch (x) {
				case 0:
					((uint8_t *) mem)[i] = 0xeb;
					break;
				case 1:
					((uint8_t *) mem)[i] = 0x6a;
					break;
				case 2:
					((uint8_t *) mem)[i] = 0x90;
					break;
				}
			}
		}
	}

	/* 
		放置跳转到 asm_syscall_hook 的代码，写以下代码：
		* push   %rax
		* movabs [asm_syscall_hook], %rax
		* jmpq   *%rax		
	*/

	// 在用 movabs [asm_syscall_hook],%rax 覆盖之前将 %rax 保存在堆栈上，并且保存的 %rax 在 asm_syscall_hook 中恢复
	// 50 --- push   %rax
	((uint8_t *) mem)[NR_syscalls + 0x0] = 0x50;
	// 48 b8 [64-bit addr (8-byte)] --- movabs [asm_syscall_hook], %rax
	((uint8_t *) mem)[NR_syscalls + 0x1] = 0x48;
	((uint8_t *) mem)[NR_syscalls + 0x2] = 0xb8;
	((uint8_t *) mem)[NR_syscalls + 0x3] = ((uint64_t) asm_syscall_hook >> (8 * 0)) & 0xff;
	((uint8_t *) mem)[NR_syscalls + 0x4] = ((uint64_t) asm_syscall_hook >> (8 * 1)) & 0xff;
	((uint8_t *) mem)[NR_syscalls + 0x5] = ((uint64_t) asm_syscall_hook >> (8 * 2)) & 0xff;
	((uint8_t *) mem)[NR_syscalls + 0x6] = ((uint64_t) asm_syscall_hook >> (8 * 3)) & 0xff;
	((uint8_t *) mem)[NR_syscalls + 0x7] = ((uint64_t) asm_syscall_hook >> (8 * 4)) & 0xff;
	((uint8_t *) mem)[NR_syscalls + 0x8] = ((uint64_t) asm_syscall_hook >> (8 * 5)) & 0xff;
	((uint8_t *) mem)[NR_syscalls + 0x9] = ((uint64_t) asm_syscall_hook >> (8 * 6)) & 0xff;
	((uint8_t *) mem)[NR_syscalls + 0xa] = ((uint64_t) asm_syscall_hook >> (8 * 7)) & 0xff;
	// ff e0 --- jmpq   *%rax
	((uint8_t *) mem)[NR_syscalls + 0xb] = 0xff;
	((uint8_t *) mem)[NR_syscalls + 0xc] = 0xe0;

	// 改为仅执行内存 XOM，这样的话如果出现 NULL 指针访问，则会报分段错误
	assert(!mprotect(0, 0x1000, PROT_EXEC));
}

// 加载 hooklib
static void load_hook_lib(void)
{
	void *handle;
	{
		const char *filename;
		filename = getenv("LIBZPHOOK");
		if (!filename) {
			fprintf(stderr, "env LIBZPHOOK is empty, so skip to load a hook library\n");
			return;
		}
		// 使用 dlmopen 加载库，创建一个新的命名空间，共享库符号不会与其他命名空间共享
		handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
		if (!handle) {
			fprintf(stderr, "dlmopen failed: %s\n\n", dlerror());
			fprintf(stderr, "NOTE: this may occur when the compilation of your hook function library misses some specifications in LDFLAGS. or if you are using a C++ compiler, dlmopen may fail to find a symbol, and adding 'extern \"C\"' to the definition may resolve the issue.\n");
			exit(1);
		}
	}
	{
		// 从动态链接库中找 __hook_init 函数
		int (*hook_init)(long, ...);
		hook_init = dlsym(handle, "__hook_init");
		assert(hook_init);
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
		assert(hook_init(0, &hook_fn, bm_mem) == 0);
#else
		assert(hook_init(0, &hook_fn) == 0);
#endif
	}
}

// __zpoline_init 代表在程序加载时自动执行
__attribute__((constructor(0xffff))) static void __zpoline_init(void)
{
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
	assert((bm_mem = mmap(NULL, BM_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
			-1, 0)) != MAP_FAILED);
#endif
	setup_trampoline();
	rewrite_code();
	load_hook_lib();
}
