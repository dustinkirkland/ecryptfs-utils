/**
 * jprobe module for debugging eCryptfs mount operations
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

struct ecryptfs_crypt_stat {
	int v;
};

/* file private data. */
struct ecryptfs_file_info {
	struct file *wfi_file;
	struct ecryptfs_crypt_stat *crypt_stat;
};

static inline struct ecryptfs_file_info *
ecryptfs_file_to_private(struct file *file)
{
	return (struct ecryptfs_file_info *)file->private_data;
}

static inline struct file *ecryptfs_file_to_lower(struct file *file)
{
	return ((struct ecryptfs_file_info *)file->private_data)->wfi_file;
}

/* inode private data. */
struct ecryptfs_inode_info {
	struct inode *wii_inode;
	struct inode vfs_inode;
	struct ecryptfs_crypt_stat crypt_stat;
};

static inline struct inode *ecryptfs_inode_to_lower(struct inode *inode)
{
	return ((struct ecryptfs_inode_info *)inode->i_private)->wii_inode;
}

int jp_ecryptfs_release(struct inode *inode, struct file *file)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);
	struct ecryptfs_file_info *file_info = ecryptfs_file_to_private(file);
	struct inode *lower_inode = ecryptfs_inode_to_lower(inode);
	int fcnt;

/*	fput(lower_file);
	inode->i_blocks = lower_inode->i_blocks;
	kmem_cache_free(ecryptfs_file_info_cache, file_info); */
	printk(KERN_INFO "%s: inode = [0x%p]; file = [0x%p]; lower_file = "
	       "[0x%p]; file_info = [0x%p]; lower_inode = [0x%p]\n",
	       __FUNCTION__, inode, file, lower_file, file_info, lower_inode);
	fcnt = atomic_read(&lower_file->f_count);
	printk(KERN_INFO "%s: lower_file->f_count = [%d]\n", __FUNCTION__,
	       fcnt);
	jprobe_return();
	return 0;
}

struct jprobe_mapping_elem jprobe_mapping[] = {
	{NULL, "ecryptfs_release", jp_ecryptfs_release},
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
