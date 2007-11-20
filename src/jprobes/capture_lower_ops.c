/**
 * Capture statistics from various VFS operations; export them to
 * /dev/ecryptfs via a ring buffer.
 *
 * Originally written to collect data for a term paper in Dr. Adam
 * Klivans' CS395T course on computational machine learning theory.
 *
 * Author: Michael Halcrow <mike@halcrow.us>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/bit_spinlock.h>
#include <linux/sched.h>
#include "ecryptfs_kernel.h"

struct jprobe_mapping_elem {
	struct jprobe *jp;
	char *symbol;
	void *fp;
};

#define MAX_CLO_MSGS 32768

spinlock_t clo_msg_list_spinlock;
size_t num_clo_msgs = 0;

struct clo_msg;

struct clo_msg {
	struct clo_msg *next;
	char *msg;
	size_t size;
	size_t current_read_offset;
};

struct clo_msg *tail_clo_msg = NULL;
struct clo_msg *head_clo_msg = NULL;

/**
 * Copies msg; callee must deallocate msg, and can do so immediately
 * upon return.
 */
static int queue_msg(char *msg)
{
	ssize_t rc;

	spin_lock(&clo_msg_list_spinlock);
	if (num_clo_msgs > MAX_CLO_MSGS) {
		rc = -EBUSY;
		goto out;
	}
	if (!tail_clo_msg) {
		tail_clo_msg = head_clo_msg = kmalloc(sizeof(struct clo_msg),
						      GFP_KERNEL);
		if (!head_clo_msg) {
			rc = -ENOMEM;
			goto out;
		}
	} else {
		tail_clo_msg->next = kmalloc(sizeof(struct clo_msg),
					     GFP_KERNEL);
		if (!tail_clo_msg->next) {
			rc = -ENOMEM;
			goto out;
		}
		tail_clo_msg = tail_clo_msg->next;
	}
	memset(tail_clo_msg, 0, sizeof(*tail_clo_msg));
	tail_clo_msg->size = strlen(msg) + 1;
	tail_clo_msg->msg = kmalloc(tail_clo_msg->size, GFP_KERNEL);
	memcpy(tail_clo_msg->msg, msg, tail_clo_msg->size);
	num_clo_msgs++;
out:
	spin_unlock(&clo_msg_list_spinlock);
	return rc;
}

atomic_t writeno;
int ignore_header_writes = 1;

int jp_ecryptfs_write_lower(struct inode *ecryptfs_inode, char *data,
			    loff_t offset, size_t size)
{
	char tmp;
	char *msg;
	size_t sz;
	struct timespec ts = CURRENT_TIME;
	size_t writeno_tmp = atomic_read(&writeno);
	struct task_struct *task = current;
	char *task_command;
	uid_t task_uid;
	char *filepath;
	struct file *lower_file;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	char *fmt = 
		"\"write\",\"%Zd\",\"%s\",\"%d\",\"%s\",\"%lld\",\"%Zd\","
		"\"%lld\",\"%ld\"\n";
	struct ecryptfs_inode_info *inode_info =
		ecryptfs_inode_to_private(ecryptfs_inode);
	u64 lower_file_size;

	if (offset == 0 && ignore_header_writes == 1)
		goto out;
	task_command = kmalloc(sizeof(task->comm), GFP_KERNEL);
	if (!task_command) {
		printk(KERN_WARNING "%s: Out of memory\n", __FUNCTION__);
		goto out;
	}
        task_lock(task);
        strncpy(task_command, task->comm, sizeof(task->comm));
        task_unlock(task);
	task_uid = task->euid;
	lower_file = inode_info->lower_file;
	lower_dentry = lower_file->f_path.dentry;
	lower_inode = lower_dentry->d_inode;
	lower_file_size = i_size_read(lower_inode);
	filepath = lower_dentry->d_name.name;
	atomic_inc(&writeno);
	sz = (snprintf(&tmp, 0, fmt,
		       writeno_tmp, task_command, task_uid, filepath, offset,
		       size, lower_file_size, ts.tv_sec) + 1);
	msg = kmalloc(sz, GFP_KERNEL);
	if (!msg)
		goto out;
	snprintf(msg, sz, fmt,
		 writeno_tmp, task_command, task_uid, filepath, offset,
		 size, lower_file_size, ts.tv_sec);
	kfree(task_command);
	queue_msg(msg);
	kfree(msg);
out:
	jprobe_return();
	return 0;
}

static ssize_t ecryptfs_dev_read(struct file *filp, char __user *buf,
				 size_t len, loff_t *ppos);
static int ecryptfs_dev_open(struct inode *inode, struct file *file);
static int ecryptfs_dev_release(struct inode *inode, struct file *file);

struct file_operations ecryptfs_fops = {
	.read = ecryptfs_dev_read,
	.open = ecryptfs_dev_open,
	.release = ecryptfs_dev_release,
};

static ssize_t ecryptfs_dev_read(struct file *filp, char __user *buf,
				 size_t len, loff_t *ppos)
{
	ssize_t rc = 0;

	spin_lock(&clo_msg_list_spinlock);
	if (!head_clo_msg)
		goto out;
	if (len >= head_clo_msg->size) {
		struct clo_msg *to_delete;

		if (head_clo_msg == tail_clo_msg)
			tail_clo_msg = NULL;
		memcpy(buf, head_clo_msg->msg, head_clo_msg->size);
		rc = head_clo_msg->size;
		kfree(head_clo_msg->msg);
		to_delete = head_clo_msg;
	        head_clo_msg = head_clo_msg->next;
		kfree(to_delete);
		num_clo_msgs--;
	}
out:
	spin_unlock(&clo_msg_list_spinlock);
	return rc;
}

static int ecryptfs_dev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int ecryptfs_dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

struct jprobe_mapping_elem jprobe_mapping[] = {
	{NULL, "ecryptfs_write_lower", jp_ecryptfs_write_lower},
};

int major;
int minor;
#define ECRYPTFS_DEVICE_NAME "ecryptfs"

static int __init jprobe_ecryptfs_init(void)
{
	int i;
	int rc;

	for (i = 0; i < ARRAY_SIZE(jprobe_mapping); i++) {
		jprobe_mapping[i].jp = kzalloc(sizeof(struct jprobe),
					       GFP_KERNEL);
		jprobe_mapping[i].jp->entry = jprobe_mapping[i].fp;
		jprobe_mapping[i].jp->kp.symbol_name = jprobe_mapping[i].symbol;
		printk(KERN_INFO "%s: Registering jprobe for symbol [%s]\n",
		       __FUNCTION__, jprobe_mapping[i].symbol);
		rc = register_jprobe(jprobe_mapping[i].jp);
		if (rc < 0) {
			int j;

			printk(KERN_NOTICE "Unable to register symbol [%s]\n",
			       jprobe_mapping[i].symbol);
			for (j = 0; j < i; j++) {
				unregister_jprobe(jprobe_mapping[j].jp);
				kfree(jprobe_mapping[j].jp);
			}
			return -EINVAL;
		}
	}
	rc = register_chrdev(0, ECRYPTFS_DEVICE_NAME, &ecryptfs_fops);
	if (rc < 0) {
		printk(KERN_ERR
		       "%s: Error registering chrdev [%s]; rc = [%d]\n",
		       __FUNCTION__, ECRYPTFS_DEVICE_NAME, rc);
		major = -1;
	} else {
		major = rc;
		printk(KERN_INFO "%s: Registered major device [%d]\n",
		       __FUNCTION__, major);
	}
	spin_lock_init(&clo_msg_list_spinlock);
	atomic_set(&writeno, 0);
        return 0;
}

static void __exit jprobe_ecryptfs_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jprobe_mapping); i++) {
		unregister_jprobe(jprobe_mapping[i].jp);
		kfree(jprobe_mapping[i].jp);
	}
	if (major >= 0) {
		unregister_chrdev(major, ECRYPTFS_DEVICE_NAME);
	} else {
		printk(KERN_WARNING "%s: Not unregistering device, since there "
		       "was an error during registration\n", __FUNCTION__);
	}
	spin_lock(&clo_msg_list_spinlock);
	while (head_clo_msg) {
		struct clo_msg *to_delete;

		kfree(head_clo_msg->msg);
		to_delete = head_clo_msg;
		head_clo_msg = head_clo_msg->next;
		kfree(to_delete);
	}
	spin_unlock(&clo_msg_list_spinlock);
}

module_init(jprobe_ecryptfs_init);
module_exit(jprobe_ecryptfs_exit);
MODULE_LICENSE("GPL");
