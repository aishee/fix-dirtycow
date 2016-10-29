#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dmitry Bilunov");
MODULE_DESCRIPTION
    ("Patch to mitigate the CVE-2016-5195 vulnerability (Dirty COW)");
MODULE_VERSION("0.1");

static long ptr_inline = 0, ptr_redirect = 0, ptr_marker = 0, ptr_l64 = 0;
module_param(ptr_inline, long, S_IRUGO);
MODULE_PARM_DESC(ptr_inline, "Inlined address of pte_unmap_unlock");

module_param(ptr_redirect, long, S_IRUGO);
MODULE_PARM_DESC(ptr_redirect, "Address of indirect call to L150");

module_param(ptr_marker, long, S_IRUGO);
MODULE_PARM_DESC(ptr_marker, "Address of faultin_page flags writer");

module_param(ptr_l64, long, S_IRUGO);
MODULE_PARM_DESC(ptr_l64, "Address of L64");

static uint16_t *t1 = 0;
static uint32_t *t2 = 0;	// & ffffff
static uint16_t *jne = 0;	// 0f 85
static uint32_t *movrdi = 0;	// 4c 89 f0 & fffff0

static uint32_t jne_restore;
static uint64_t movrdi_restore;
static uint32_t t2_restore;

static unsigned long cr0;

extern void cowcleaner_can_follow_write_pte(void);
extern void cowcleaner_inject(void);
extern uint32_t cowcleaner_l64;
extern uint32_t cowcleaner_l150;
extern uint64_t cowcleaner_prologue;
extern uint64_t cowcleaner_epilogue;

static int __init cowcleaner_init(void)
{
	int cpu;

	printk(KERN_INFO "cowcleaner: Performing sanity checks...\n");
	if (ptr_marker == 0) {
		printk(KERN_INFO
		       "cowcleaner: Please specify the ptr_marker parameter.\n");
		return -EINVAL;
	}
	if (ptr_l64 == 0) {
		printk(KERN_INFO
		       "cowcleaner: Please specify the ptr_l64 parameter.\n");
		return -EINVAL;
	}
	if (ptr_inline == 0 && ptr_redirect == 0) {
		printk(KERN_INFO
		       "cowcleaner: Please specify either ptr_inline or ptr_redirect parameter.\n");
		return -EINVAL;
	}
	if (ptr_inline != 0 && ptr_redirect != 0) {
		printk(KERN_INFO
		       "cowcleaner: Please specify exactly one of ptr_inline or ptr_redirect parameters.\n");
		return -EINVAL;
	}
/*
ptr_marker:
ffffffff81172ec8: a8 08                 test   $0x8,%al
ffffffff81172eca: 0f 84 c3 fe ff ff     je     0xffffffff81172d93
ffffffff81172ed0: 44 89 e8              mov    %r13d,%eax
ffffffff81172ed3: 83 e0 fe              and    $0xfffffffe,%eax
ffffffff81172ed6: f6 43 50 02           testb  $0x2,0x50(%rbx)
ffffffff81172eda: 44 0f 44 e8           cmove  %eax,%r13d
ffffffff81172ede: e9 b0 fe ff ff        jmpq   0xffffffff81172d93

patch to:
             ed3: 80 cc 40              or     $0x40,%ah
*/
	t1 = (uint16_t *) ptr_marker;
	if (*t1 != 0x08a8) {
		printk(KERN_INFO "cowcleaner: Invalid marker value!\n");
		return -EINVAL;
	}
	t2 = (uint32_t *) (ptr_marker + 11);
	if ((*t2 & 0xffffff) == 0x40cc80) {
		printk(KERN_INFO "cowcleaner: Already patched.\n");
		return 0;
	} else if ((*t2 & 0xffffff) != 0xfee083) {
		printk(KERN_INFO "cowcleaner: Unexpected marker value: %x!\n",
		       *t2);
		t2 = (uint32_t *) ptr_marker;
		{
			int i;
			for (i = 0; i < 16; i++)
				printk(KERN_DEBUG "cowcleaner[%x]: %x\n", i,
				       t2[i]);
		}
		return -EINVAL;
	}
	if (ptr_inline != 0) {
		movrdi = (uint32_t *) ptr_inline;
		if ((*movrdi & 0xf0ffff) != 0xf0894c) {
			printk(KERN_INFO
			       "cowcleaner: Invalid ptr_inline value: %x.\n",
			       *movrdi);
			return -EINVAL;
		}
	} else if (ptr_redirect != 0) {
		jne = (uint16_t *) ptr_redirect;
		if (*jne != 0x850f && *jne != 0x840f) {
			printk(KERN_INFO
			       "cowcleaner: Invalid ptr_redirect value: %x.\n",
			       *jne);
			return -EINVAL;
		}
	}

	cpu = get_cpu();
	local_irq_disable();
	if (ptr_inline != 0) {
		uint32_t inline_offset;
		movrdi_restore = *((uint64_t *) ptr_inline);
		inline_offset =
		    (long)(ptr_inline) - (uint64_t) & cowcleaner_epilogue;
		cr0 = read_cr0();
		write_cr0(cr0 & (~0x10000));
		cowcleaner_prologue =
		    (movrdi_restore & 0xffffffffffffULL) |
		    (0x9090000000000000ULL);
		cowcleaner_epilogue =
		    0x90909000000000e9ULL | ((uint64_t) inline_offset << 8);
		*(uint64_t *) ptr_inline =
		    0x9000000000e9ULL |
		    ((((long)&cowcleaner_inject) - ptr_inline -
		      5) << 8) | (movrdi_restore & 0xffff000000000000ULL);
		cowcleaner_l64 = ptr_l64 - ((long)&cowcleaner_l64) - 4;
	} else if (ptr_redirect != 0) {
		jne_restore = *(uint32_t *) (ptr_redirect + 2);
		cr0 = read_cr0();
		write_cr0(cr0 & (~0x10000));
		cowcleaner_l150 =
		    jne_restore + ptr_redirect - (long)&cowcleaner_l150 + 2;
		cowcleaner_l64 = ptr_l64 - ((long)&cowcleaner_l64) - 4;
		*(uint32_t *) (ptr_redirect + 2) =
		    ((long)cowcleaner_can_follow_write_pte) - ptr_redirect - 6;
	}
	t2_restore = *t2;
	*t2 = (*t2 & 0xff000000) | 0x40cc80;
	write_cr0(cr0);
	put_cpu();
	local_irq_enable();

	printk(KERN_INFO "cowcleaner: Started!\n");
	return 0;
}

static void __exit cowcleaner_exit(void)
{
	cr0 = read_cr0();
	write_cr0(cr0 & (~0x10000));
	if (ptr_redirect != 0) {
		*(uint32_t *) (ptr_redirect + 2) = jne_restore;
	}
	if (ptr_inline != 0) {
		*((uint64_t *) ptr_inline) = movrdi_restore;
	}
	*t2 = t2_restore;
	write_cr0(cr0);
	printk(KERN_INFO "cowcleaner: Restored!\n");
}

module_init(cowcleaner_init);
module_exit(cowcleaner_exit);
