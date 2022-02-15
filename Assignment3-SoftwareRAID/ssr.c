// SPDX-License-Identifier: GPL-2.0+

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "ssr.h"

MODULE_AUTHOR("ssr");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("software raid");

struct my_disk_dev {
	struct request_queue *queue;
	struct gendisk *gd;
	struct work_struct work;
	struct bio *disk1_bio;
	struct bio *disk2_bio;
}g_dev;

static struct block_device *disk1, *disk2;

static blk_qc_t my_submit_bio(struct bio *bio)
{
	/*
	* we need to take care of the crc bio,since each io_vec's size is pagesize 4k
	* crc32 only take 4 bytes,so one bio for crc will return 1024 sectors' crc value
	*/

	struct page *page;
	char *ori_buf;
	struct bio_vec bvec;
	struct bvec_iter iter;
	unsigned int bi_size;
	struct bio *disk1_bio;

	// bio_for_each_bvec(bvec, bio, iter) {
	// 	page = bvec.bv_page;
	// 	bi_size = iter.bi_size;
	// 	buf = kmap_atomic(page);
	// 	pr_info("bi_size=%d, %x %x %x %x %x %x %x %x\n",bi_size, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[4000], buf[2234]);
	// 	kunmap_atomic(buf);
	// }

	// disk1_bio = bio_alloc(GFP_KERNEL, bio->bi_vcnt);
	// if (disk1_bio == NULL)
	// {
	// 	pr_info("[-] ssr: bio_alloc failed...");
	// 	goto end_bio;
	// }
	// bio_for_each_bvec(bvec, bio, iter)
	// {
	// 	struct page *new_page = alloc_page(GFP_KERNEL);
		
	// }
	g_dev.disk1_bio = bio_clone_fast(bio, GFP_KERNEL, 0);
	bio_set_dev(g_dev.disk1_bio, disk1);

	//wake up workqueue
	schedule_work(&g_dev.work);
	flush_scheduled_work();
	pr_info("[+] ssr: finished now...");
end_bio:
	bio_endio(bio);
	return BLK_QC_T_NONE;
}

void my_work_handler(struct work_struct* work)
{
	if(op_is_write(g_dev.disk1_bio->bi_opf))
	{
		pr_info("[+] ssr: submit_bio_wait...");
		submit_bio_wait(g_dev.disk1_bio);
		pr_info("[+] ssr: bio_put...");
		bio_put(g_dev.disk1_bio);
	}
}

static blk_status_t my_queue_rq (struct blk_mq_hw_ctx *hctx,
				const struct blk_mq_queue_data *bd)
{
	struct request *rq;
	struct my_block_dev *dev = hctx->queue->queuedata;
	struct bio_vec bvec;
	struct req_iterator i;

	return BLK_STS_OK;
}

static int my_block_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void my_block_release(struct gendisk *gd, fmode_t mode)
{
}

static struct block_device_operations my_blk_ops =
{
	.owner = THIS_MODULE,
	.submit_bio = my_submit_bio,
	.open = my_block_open,
	.release = my_block_release
};

static struct blk_mq_ops my_queue_ops =
{
	.queue_rq = my_queue_rq,
};

static int create_block_device(struct my_disk_dev *dev)
{
	int err;

	// dev->tag_set.ops = &my_queue_ops;
	// dev->tag_set.nr_hw_queues = 1;
	// dev->tag_set.queue_depth = 128;
	// dev->tag_set.numa_node = NUMA_NO_NODE;
	// dev->tag_set.cmd_size = 0;
	// dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	// err = blk_mq_alloc_tag_set(&dev->tag_set);
	// if (err) {
	// 	pr_err("blk_mq_alloc_tag_set: can't allocate tag set\n");
	// 	goto out;
	// }

	dev->queue = blk_alloc_queue(NUMA_NO_NODE);
	if (IS_ERR(dev->queue)) {
		pr_err("blk_mq_init_queue: out of memory\n");
		err = -ENOMEM;
		goto out;
	}
	// blk_queue_logical_block_size(dev->queue, KERNEL_SECTOR_SIZE);
	// dev->queue->queuedata = dev;

	dev->gd = alloc_disk(SSR_NUM_MINORS);
	if (!dev->gd) {
		pr_err("alloc_disk failed\n");
		err = -ENOMEM;
		goto out_alloc_disk;
	}
	dev->gd->major = SSR_MAJOR;
	dev->gd->first_minor = SSR_FIRST_MINOR;
	dev->gd->fops = &my_blk_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, LOGICAL_DISK_NAME);
	set_capacity(dev->gd, LOGICAL_DISK_SIZE);
	add_disk(dev->gd);
	return 0;

out_alloc_disk:
	blk_cleanup_queue(dev->queue);
// out_blk_init:
// 	blk_mq_free_tag_set(&dev->tag_set);
out:
	return err;
}
static __init int ssr_init(void)
{
	int err = 0;
	INIT_WORK(&g_dev.work, &my_work_handler);
	disk1 = blkdev_get_by_path(PHYSICAL_DISK1_NAME, 
		FMODE_READ | FMODE_WRITE, NULL);
	disk2 = blkdev_get_by_path(PHYSICAL_DISK2_NAME, 
		FMODE_READ | FMODE_WRITE, NULL);
	err = register_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
	if (err < 0) {
		pr_err("register disk ssr failed\n");
		return -EBUSY;
	}
	err = create_block_device(&g_dev);
	if (err) {
		pr_err("create blk ssr failed\n");
		goto unregister_blk;
	}
	return 0;
unregister_blk:
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
	return err;
}

static void delete_block_device(struct my_disk_dev *dev)
{
	if (dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}

	if (dev->queue)
		blk_cleanup_queue(dev->queue);
}
static __exit void ssr_exit(void)
{
	delete_block_device(&g_dev);
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
	blkdev_put(disk1, FMODE_READ | FMODE_WRITE);
	blkdev_put(disk2, FMODE_READ | FMODE_WRITE);
	pr_info("quite module now\n");
}

module_init(ssr_init);
module_exit(ssr_exit);
