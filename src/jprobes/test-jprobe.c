#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>

struct jprobe_mapping_elem {
	struct jprobe *jp;
	char *symbol;
	void *fp;
};

void jp_ecryptfs_kill_block_super(struct super_block *sb)
{
	printk(KERN_INFO "sb = [0x%p]\n", sb);
	jprobe_return();
}

struct jprobe_mapping_elem jprobe_mapping[] = {
	{NULL, "ecryptfs_kill_block_super", jp_ecryptfs_kill_block_super},
};

static int __init test_jprobe_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jprobe_mapping); i++) {
		jprobe_mapping[i].jp = kmalloc(sizeof(struct jprobe),
					       GFP_KERNEL);
		jprobe_mapping[i].jp->entry = jprobe_mapping[i].fp;
		jprobe_mapping[i].jp->kp.addr = (kprobe_opcode_t *)
			kallsyms_lookup_name(jprobe_mapping[i].symbol);
		if (jprobe_mapping[i].jp->kp.addr == NULL) {
			printk(KERN_NOTICE "Unable to find symbol [%s]\n",
			       jprobe_mapping[i].symbol);
			return 1;
		}
		register_jprobe(jprobe_mapping[i].jp);
	}
        return 0;
}

static void __exit test_jprobe_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jprobe_mapping); i++) {
		unregister_jprobe(jprobe_mapping[i].jp);
		kfree(jprobe_mapping[i].jp);
	}
}

module_init(test_jprobe_init);
module_exit(test_jprobe_exit);
MODULE_LICENSE("GPL");
