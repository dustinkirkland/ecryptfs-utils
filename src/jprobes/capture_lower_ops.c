/**
 * Capture statistics from read and writes; export them to /dev/ecryptfs
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/mount.h>

struct jprobe_mapping_elem {
	struct jprobe *jp;
	char *symbol;
	void *fp;
};

int jp_do_umount(struct vfsmount *mnt, int flags)
{
	printk(KERN_INFO "%s: mnt = [0x%p]; flags = [0x%x]\n", __FUNCTION__,
	       mnt, flags);
	jprobe_return();
	return 0;
}

void jp_ecryptfs_kill_block_super(struct super_block *sb)
{
	printk(KERN_INFO "%s: sb = [0x%p]\n", __FUNCTION__, sb);
	jprobe_return();
}

void jp_ecryptfs_put_super(struct super_block *sb)
{
	printk(KERN_INFO "%s: sb = [0x%p]\n", __FUNCTION__, sb);
	jprobe_return();
}

void jp_ecryptfs_umount_begin(struct vfsmount *vfsmnt, int flags)
{
	printk(KERN_INFO "%s: vfsmnt = [0x%p]; flags = [0x%.8x]\n",
	       __FUNCTION__, vfsmnt, flags);
	jprobe_return();
}

int jp_ecryptfs_get_sb(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *raw_data,
		       struct vfsmount *mnt)
{
	printk(KERN_INFO "%s: fs_type = [0x%p]; flags = [0x%.8x], dev_name = "
	       "[%s], raw_data = [0x%p], mnt = [0x%p]\n",
	       __FUNCTION__, fs_type, flags, dev_name, raw_data, mnt);
	jprobe_return();
	return 0;
}

int jp_get_sb_nodev(struct file_system_type *fs_type,
		    int flags, void *data,
		    int (*fill_super)(struct super_block *, void *, int),
		    struct vfsmount *mnt)
{
	printk(KERN_INFO "%s: fs_type = [0x%p]; flags = [0x%.8x], data = "
	       "[0x%p], mnt = [0x%p]\n",
	       __FUNCTION__, fs_type, flags, data, mnt);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_fill_super(struct super_block *sb, void *raw_data, int silent)
{
	printk(KERN_INFO "%s: sb = [0x%p]; raw_data = [0x%p], silent = [%d]\n",
	       __FUNCTION__, sb, raw_data, silent);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_read_super(struct super_block *sb, const char *dev_name)
{
	printk(KERN_INFO "%s: sb = [0x%p]; dev_name = [%s]\n",
	       __FUNCTION__, sb, dev_name);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_interpose(struct dentry *lower_dentry, struct dentry *dentry,
			  struct super_block *sb, int flag)
{
	printk(KERN_INFO "%s: lower_dentry = [0x%p]; dentry = [0x%p]; sb = "
	       "[0x%p]; flag = [0x%.8x]\n", __FUNCTION__, lower_dentry, dentry,
	       sb, flag);
	if (flag)
		printk(KERN_INFO "%s: d_add() will be called\n", __FUNCTION__);
	else
		printk(KERN_INFO "%s: d_instantiate() will be called\n",
		       __FUNCTION__);
	jprobe_return();
	return 0;
}

asmlinkage long jp_sys_umount(char __user * name, int flags)
{
	char *tmp = getname(name);

	if (!IS_ERR(tmp)) {
		printk(KERN_INFO "%s: name = [%s]; flags = [0x%x]\n",
		       __FUNCTION__, tmp, flags);
		putname(tmp);
	} else 
		printk(KERN_INFO "%s: (getname failed); flags = [0x%x]\n",
		       __FUNCTION__, flags);
	jprobe_return();
	return 0;	
}

struct jprobe_mapping_elem jprobe_mapping[] = {
	{NULL, "ecryptfs_kill_block_super", jp_ecryptfs_kill_block_super},
	{NULL, "ecryptfs_put_super", jp_ecryptfs_put_super},
	{NULL, "sys_umount", jp_sys_umount},
/*	{NULL, "ecryptfs_interpose", jp_ecryptfs_interpose} */
};

static int __init jprobe_mount_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jprobe_mapping); i++) {
		jprobe_mapping[i].jp = kmalloc(sizeof(struct jprobe),
					       GFP_KERNEL);
		jprobe_mapping[i].jp->entry = jprobe_mapping[i].fp;
		jprobe_mapping[i].jp->kp.addr = (kprobe_opcode_t *)
		  kallsyms_lookup_name(jprobe_mapping[i].symbol);
		if (jprobe_mapping[i].jp->kp.addr == NULL) {
			int j;

			printk(KERN_NOTICE "Unable to find symbol [%s]\n",
			       jprobe_mapping[i].symbol);
			for (j = 0; j < i; j++) {
				unregister_jprobe(jprobe_mapping[j].jp);
				kfree(jprobe_mapping[j].jp);
			}
			return -EINVAL;
		}
		register_jprobe(jprobe_mapping[i].jp);
	}
        return 0;
}

static void __exit jprobe_mount_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jprobe_mapping); i++) {
		unregister_jprobe(jprobe_mapping[i].jp);
		kfree(jprobe_mapping[i].jp);
	}
}

module_init(jprobe_mount_init);
module_exit(jprobe_mount_exit);
MODULE_LICENSE("GPL");
