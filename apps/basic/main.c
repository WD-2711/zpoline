// libzphook_basic.so 钩子函数

#include <stdio.h>

// 返回值为 *syscall_fn_t，7 个 long 的参数
typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

static long hook_function(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	// a1 是系统调用号
	printf("output from hook_function: syscall number %ld\n", a1);
	// 使用原本的处理函数继续向下处理
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

// 到达 hook 点就运行 __hook_init
// sys_call_hook_ptr 是原本应该运行的处理函数
int __hook_init(long placeholder __attribute__((unused)), void *sys_call_hook_ptr)
{
	printf("output from __hook_init: we can do some init work here\n");
	// 使用 next_sys_call 保存原本的处理函数 sys_call_hook_ptr
	next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
	// 将 sys_call_hook_ptr 更新为 hook_function
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

	return 0;
}

