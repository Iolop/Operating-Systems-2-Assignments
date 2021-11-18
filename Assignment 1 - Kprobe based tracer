// SPDX-License-Identifier: GPL-2.0+
/* kpro-base.c
 *
kmalloc and kfree calls
schedule calls
up and down_interruptible calls
mutex_lock and mutex_unlock calls
 *
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include "tracer.h"


MODULE_DESCRIPTION("kprobe based tracer.");
MODULE_AUTHOR("kpro");
MODULE_LICENSE("GPL");

struct mm_info {
	unsigned long addr;
	unsigned int size;
	struct list_head list;
};

struct my_monitor_process {
	struct list_head list;
	pid_t pid;
	struct mm_info mmi;
	struct list_head head_internal;
	unsigned int kmalloc_call;
	unsigned int kfree_call;
	unsigned int kmalloc_size;
	unsigned int kmalloc_size_before;
	unsigned int kfree_size;
	unsigned int sched;
	unsigned int up;
	unsigned int down;
	unsigned int lock;
	unsigned int unlock;
};

static struct list_head head;

static int kmalloc_entry(struct kretprobe_instance *kret_i, struct pt_regs *regs)
{
	pid_t pid = current->pid;
	size_t size = regs->di;
	struct my_monitor_process *p, *q;

	list_for_each_entry_safe(p, q, &head, list) {
		if (p->pid == pid) {
			p->kmalloc_call++;
			p->kmalloc_size += size;
		}
	}
	return 0;
}

static int kmalloc_ret(struct kretprobe_instance *kret_i, struct pt_regs *regs)
{
	pid_t pid = current->pid;
	unsigned long addr = regs->ax;
	struct my_monitor_process *p, *q;
	struct mm_info *r, *s;
	size_t wantted;

	list_for_each_entry_safe(p, q, &head, list) {
		if (p->pid == pid) {
			wantted = p->kmalloc_size - p->kmalloc_size_before;
			list_for_each_entry_safe(r, s, &p->head_internal, list) {
				if (!r->addr && r->size == wantted)
					r->addr = addr;
			}
		}
	}
	p->kmalloc_size_before = p->kmalloc_size;
	return 0;
}

struct kretprobe kmalloc_probe = {
	.entry_handler = kmalloc_entry,
	.handler = kmalloc_ret,
	.maxactive = 32,
	.kp.symbol_name = KMALLOC_NAME,
};
struct kretprobe *rps[1] = {&kmalloc_probe};

static int add_new_monitor(pid_t pid)
{
	int err = 0;
	struct my_monitor_process *mmp = kzalloc(sizeof(struct my_monitor_process), GFP_KERNEL);

	pr_info("add new monitor %d\n", pid);
	if (!mmp) {
		err = -ENOMEM;
		pr_err("kzalloc failed\n");
		goto out;
	}
	mmp->pid = pid;
	list_add_tail(&mmp->list, &head);
	INIT_LIST_HEAD(&mmp->head_internal);
out:
	return err;
}

static int remove_monitor(pid_t pid)
{
	struct my_monitor_process *p, *q;
	struct mm_info *r, *s;

	pr_info("try to release %d\n", pid);
	list_for_each_entry_safe(p, q, &head, list) {
		if (p->pid == pid) {
			list_for_each_entry_safe(r, s, &p->head_internal, list) {
				list_del(&r->list);
			}
			list_del(&p->list);
		}
		kfree(p);
	}
	return 0;
}

static long my_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		ret = add_new_monitor(arg);
		break;
	case TRACER_REMOVE_PROCESS:
		ret = remove_monitor(arg);
		break;
	default:
		pr_err("unsupported cmd\n");
		break;
	}
	return ret;
}

static const struct file_operations my_misc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = my_misc_ioctl,
};

static void *proc_seq_start(struct seq_file *m, loff_t *pos)
{
	return seq_list_start_head(&head, *pos);
}

static void proc_seq_stop(struct seq_file *m, void *v)
{

}

static void *proc_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &head, pos);
}

static int proc_seq_show(struct seq_file *m, void *v)
{
	struct my_monitor_process *mmp;

	if (v == &head) {
		seq_puts(m, "PID\tkmalloc\tkmalloc_mem\n");
		return 0;
	}
	mmp = list_entry((struct list_head *)v, struct my_monitor_process, list);
	if (mmp)
		seq_printf(m, "%d\t%d\t%d\n", mmp->pid, mmp->kmalloc_call, mmp->kmalloc_size);
	return 0;
}

static const struct seq_operations proc_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.show = proc_seq_show,
	.stop = proc_seq_stop,
};

static int my_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &proc_seq_ops);
}

struct miscdevice my_misc_dev = {
	.minor = MY_MISC_MINOR,
	.name = "tracer",
	.fops = &my_misc_fops,
};
struct proc_ops my_proc_ops = {
	.proc_open    = my_seq_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release,
};

static void release_struct(void)
{
	struct my_monitor_process *p, *q;
	struct mm_info *r, *s;

	list_for_each_entry_safe(p, q, &head, list) {
		list_for_each_entry_safe(r, s, &p->head_internal, list) {
			list_del(&r->list);
		}
		list_del(&p->list);
		kfree(p);
	}

}

static __init int kpro_base_init(void)
{
	INIT_LIST_HEAD(&head);
	struct proc_dir_entry *dir;
	int err = misc_register(&my_misc_dev);

	if (err) {
		pr_info("misc device register failed\n");
		goto out;
	}
	dir = proc_create(PROC_ENTRY_NAME, 0, NULL, &my_proc_ops);
	if (!dir) {
		pr_err("proc create failed\n");
		goto deregister_misc;
	}
	err = register_kretprobes(rps, 1);
	if (err != 0) {
		pr_err("register kretprobes failed\n");
		goto remove_entry;
	}
	return 0;
remove_entry:
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
deregister_misc:
	misc_deregister(&my_misc_dev);
out:
	return -1;
}

static __exit void kpro_base_exit(void)
{
	pr_info("quit module now\n");
	release_struct();
	unregister_kretprobes(rps, 1);
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
	misc_deregister(&my_misc_dev);
}

module_init(kpro_base_init);
module_exit(kpro_base_exit);
