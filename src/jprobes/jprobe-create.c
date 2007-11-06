/**
 * jprobe module for debugging eCryptfs file create operations
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/namei.h>

struct jprobe_mapping_elem {
	struct jprobe *jp;
	char *symbol;
	void *fp;
};

int jp_ecryptfs_create(struct inode *directory_inode,
		       struct dentry *ecryptfs_dentry,
		       int mode, struct nameidata *nd)
{
	printk(KERN_INFO "%s: directory_inode = [0x%p]; ecryptfs_dentry = [0x%p]; mode = [%.8x]; nd = [0x%p]\n", __FUNCTION__, directory_inode, ecryptfs_dentry, mode, nd);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_do_create(struct inode *directory_inode,
			  struct dentry *ecryptfs_dentry, int mode,
			  struct nameidata *nd)
{
	printk(KERN_INFO "%s: directory_inode = [0x%p]; ecryptfs_dentry = [0x%p]; mode = [%.4x]; nd = [0x%p]\n", __FUNCTION__, directory_inode, ecryptfs_dentry, mode, nd);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_create_underlying_file(struct inode *lower_dir_inode,
				       struct dentry *lower_dentry,
				       struct dentry *ecryptfs_dentry, int mode,
				       struct nameidata *nd)
{
	printk(KERN_INFO "%s: lower_dir_inode = [0x%p]; lower_dentry = [0x%p]; ecryptfs_dentry = [0x%p]; mode = [%.8x]; nd = [0x%p]\n", __FUNCTION__, lower_dir_inode, lower_dentry, ecryptfs_dentry, mode, nd);
	printk(KERN_INFO "%s: Calling vfs_create()\n", __FUNCTION__);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_interpose(struct dentry *lower_dentry, struct dentry *dentry,
			  struct super_block *sb, int flag)
{
	printk(KERN_INFO "%s: lower_dentry = [0x%p]; dentry = [0x%p]; sb = [0x%p]; flag = [0x%.8x]\n", __FUNCTION__, lower_dentry, dentry, sb, flag);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_initialize_file(struct dentry *ecryptfs_dentry)
{
	printk(KERN_INFO "%s: ecryptfs_dentry = [0x%p]\n", __FUNCTION__, ecryptfs_dentry);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_new_file_context(struct dentry *ecryptfs_dentry)
{
	printk(KERN_INFO "%s: ecryptfs_dentry = [0x%p]\n", __FUNCTION__, ecryptfs_dentry);
	jprobe_return();
	return 0;
}

/* ecryptfs_set_default_crypt_stat_vals */
/* ecryptfs_generate_new_key */
/* ecryptfs_init_crypt_ctx */

int jp_ecryptfs_write_headers(struct dentry *ecryptfs_dentry,
			      struct file *lower_file)
{
	printk(KERN_INFO "%s: ecryptfs_dentry = [0x%p]; lower_file = [0x%p]\n", __FUNCTION__, ecryptfs_dentry, lower_file);
	jprobe_return();
	return 0;
}

struct ecryptfs_crypt_stat;

int jp_ecryptfs_write_headers_virt(char *page_virt,
				   struct ecryptfs_crypt_stat *crypt_stat,
				   struct dentry *ecryptfs_dentry)
{
	printk(KERN_INFO "%s: page_virt = [0x%p]; crypt_stat = [0x%p]; ecryptfs_dentry = [0x%p]\n", __FUNCTION__, page_virt, crypt_stat, ecryptfs_dentry);
	jprobe_return();
	return 0;
}

int jp_grow_file(struct dentry *ecryptfs_dentry, struct file *lower_file,
		 struct inode *inode, struct inode *lower_inode)
{
	printk(KERN_INFO "%s: ecryptfs_dentry = [0x%p]; lower_file = [0x%p]; inode = [0x%p]; lower_inode = [0x%p]\n", __FUNCTION__, ecryptfs_dentry, lower_file, inode, lower_inode);
	jprobe_return();
	return 0;
}

int jp_ecryptfs_fill_zeros(struct file *file, loff_t new_length)
{
	printk(KERN_INFO "%s: file = [0x%p]; new_length = [%llu]\n", __FUNCTION__, file, new_length);
	jprobe_return();
	return 0;
}

/* write_zeros */

int
jp_ecryptfs_write_inode_size_to_header(struct file *lower_file,
				       struct inode *lower_inode,
				       struct inode *inode)
{
	printk(KERN_INFO "%s: lower_file = [0x%p]; lower_inode = [0x%p]; inode = [0x%p]\n", __FUNCTION__, lower_file, lower_inode, inode);
	dump_stack();
	jprobe_return();
	return 0;
}

int jp_ecryptfs_grab_and_map_lower_page(struct page **lower_page,
					char **lower_virt,
					struct inode *lower_inode,
					unsigned long lower_page_index)
{
	printk(KERN_INFO "%s: lower_page = [0x%p]; lower_virt = [0x%p]; lower_inode = [0x%p]; lower_page_index = [%lu]\n", __FUNCTION__, lower_page, lower_virt, lower_inode, lower_page_index);
	jprobe_return();
	return 0;
}

void jp_ecryptfs_unmap_and_release_lower_page(struct page *lower_page)
{
	printk(KERN_INFO "%s: lower_page = [0x%p]\n", __FUNCTION__, lower_page);
	jprobe_return();
	return;
}

int jp_ecryptfs_commit_write(struct file *file, struct page *page,
			     unsigned from, unsigned to)
{
	printk(KERN_INFO "%s: file = [0x%p]; page = [0x%p]; page->mapping = [0x%p]\n", __FUNCTION__, file, page, page->mapping);
	jprobe_return();
	return 0;
}

int
jp_ecryptfs_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	printk(KERN_INFO "%s: inode = [0x%p]; mask = [0x%.8x]; nd = [0x%p]\n", __FUNCTION__, inode, mask, nd);
	if (nd) {
		printk(KERN_INFO "%s: nd->dentry = [0x%p]\n", __FUNCTION__,
		       nd->dentry);
		if (nd->dentry)
			printk(KERN_INFO "%s: nd->dentry->d_fsdata = [0x%p]\n",
			       __FUNCTION__, nd->dentry->d_fsdata);
	}
	jprobe_return();
	return 0;
}

struct dentry *jp_ecryptfs_lookup(struct inode *dir, struct dentry *dentry,
			       struct nameidata *nd)
{
	printk(KERN_INFO "%s: dir = [0x%p]; dentry = [0x%p]; nd = [0x%p]\n",
	       __FUNCTION__, dir, dentry, nd);
	printk(KERN_INFO "%s: dentry->d_name.name = [%s]\n",
	       __FUNCTION__, dentry->d_name.name);
	jprobe_return();
	return NULL;
}

struct jprobe_mapping_elem jprobe_mapping[] = {
	{NULL, "ecryptfs_create", jp_ecryptfs_create},
	{NULL, "ecryptfs_do_create", jp_ecryptfs_do_create},
	{NULL, "ecryptfs_create_underlying_file", jp_ecryptfs_create_underlying_file},
	{NULL, "ecryptfs_interpose", jp_ecryptfs_interpose},
	{NULL, "ecryptfs_initialize_file", jp_ecryptfs_initialize_file},
	{NULL, "ecryptfs_new_file_context", jp_ecryptfs_new_file_context},
	{NULL, "ecryptfs_write_headers", jp_ecryptfs_write_headers},
	{NULL, "ecryptfs_write_headers_virt", jp_ecryptfs_write_headers_virt},
	{NULL, "grow_file", jp_grow_file},
	{NULL, "ecryptfs_fill_zeros", jp_ecryptfs_fill_zeros},
	{NULL, "ecryptfs_write_inode_size_to_header", jp_ecryptfs_write_inode_size_to_header},
	{NULL, "ecryptfs_grab_and_map_lower_page", jp_ecryptfs_grab_and_map_lower_page},
	{NULL, "ecryptfs_unmap_and_release_lower_page", jp_ecryptfs_unmap_and_release_lower_page},
	{NULL, "ecryptfs_commit_write", jp_ecryptfs_commit_write},
	{NULL, "ecryptfs_permission", jp_ecryptfs_permission},
	{NULL, "ecryptfs_lookup", jp_ecryptfs_lookup}
};

static int __init jprobe_create_init(void)
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

static void __exit jprobe_create_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jprobe_mapping); i++) {
		unregister_jprobe(jprobe_mapping[i].jp);
		kfree(jprobe_mapping[i].jp);
	}
}

module_init(jprobe_create_init);
module_exit(jprobe_create_exit);
MODULE_LICENSE("GPL");
