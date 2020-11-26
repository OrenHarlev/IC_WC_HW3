
#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <linux/errno.h>

#include "fw.h"
#include "FWPacketMatcher.h"
#include "FWRuleManager.h"
#include "FWLogger.h"


//================== GLOBALS AND MACROS ===========================

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oren Harlev");

//------------------------netfilter--------------------------------

static struct nf_hook_ops *forward_hook_ops = NULL;

//---------------------------sysfs-device---------------------------------

#define SYSFS_CLASS_NAME "FW"
#define DEVICE_NAME "fw_log"

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

//---------------------------logic---------------------------------

RuleManager ruleManager;
Logger logger;

//==================== FUNCTIONS ===========================

//---------------------------device---------------------------------

ssize_t LogRead(struct file *filp, char *buff, size_t length, loff_t *offp)
{
    char logBuff[length];

    ssize_t logLength = ReadLogs(logBuff, length, logger);

    if (logLength <= 0)
    {
        return 0;
    }

    if (copy_to_user(buff, logBuff, logLength))
    {
        return -EFAULT;
    }

    return logLength;
}

int OpenLog(struct inode *_inode, struct file *_file)
{
    ResetLogReader(logger);
}

static struct file_operations fops =
{
    .owner = THIS_MODULE,
    .read = LogRead,
    .open = OpenLog,
};

//------------------------netfilter hooks--------------------------------

static unsigned int FWHook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    log_row_t actionLog;
    int action = MatchRawPacket(skb, state, ruleManager, &actionLog);
    LogAction(actionLog, logger);
    return action;
}

//------------------------sysfs api--------------------------------

ssize_t RulesDisplay(struct device *dev, struct device_attribute *attr, char *buf)
{
    return GetRawRules(ruleManager, buf);
}

ssize_t RulesModify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return UpdateRules(buf, count, ruleManager);
}

ssize_t LogModify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return ResetLogs(logger);
}

static DEVICE_ATTR(RulesAttribute, S_IWUSR | S_IRUGO , RulesDisplay, RulesModify);
static DEVICE_ATTR(LogAttribute, S_IWUSR | S_IRUGO , NULL, LogModify);

//==================== MODULE SETUP =============================

static int __init init(void)
{
    ruleManager = CreateRuleManager();
    logger = CreateLogger();
    if (ruleManager == NULL || logger == NULL)
    {
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        printk(KERN_ERR "Failed to init module: Memory allocation failed.");
        return -1;
    }

    forward_hook_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    if (forward_hook_ops == NULL)
    {
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        printk(KERN_ERR "Failed to init module: Memory allocation failed.");
        return -1;
    }

    forward_hook_ops->hook = (nf_hookfn*)FWHook;
    forward_hook_ops->hooknum = NF_INET_FORWARD;
    forward_hook_ops->pf = PF_INET;
    forward_hook_ops->priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, forward_hook_ops) != 0)
    {
        printk(KERN_ERR "Failed to init module: foeward hook_ops init failed.");
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        kfree(forward_hook_ops);
        return -1;
    }

    //create char device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0)
    {
        printk(KERN_ERR "Failed to init module: register_chrdev failed.");
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        kfree(forward_hook_ops);
        nf_unregister_net_hook(&init_net, forward_hook_ops);
        return -1;
    }

    //create sysfs class
    sysfs_class = class_create(THIS_MODULE, SYSFS_CLASS_NAME);
    if (IS_ERR(sysfs_class))
    {
        printk(KERN_ERR "Failed to init module: class_create failed.");
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        kfree(forward_hook_ops);
        nf_unregister_net_hook(&init_net, forward_hook_ops);
        unregister_chrdev(major_number, DEVICE_NAME);
        return -1;
    }

    //create sysfs device
    sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, SYSFS_CLASS_NAME "_" DEVICE_NAME);
    if (IS_ERR(sysfs_device))
    {
        printk(KERN_ERR "Failed to init module: device_create failed.");
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        kfree(forward_hook_ops);
        nf_unregister_net_hook(&init_net, forward_hook_ops);
        unregister_chrdev(major_number, DEVICE_NAME);
        class_destroy(sysfs_class);
        return -1;
    }

    //create sysfs file attributes
    if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_RulesAttribute.attr))
    {
        printk(KERN_ERR "Failed to init module: device_create_file failed.");
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        kfree(forward_hook_ops);
        nf_unregister_net_hook(&init_net, forward_hook_ops);
        unregister_chrdev(major_number, DEVICE_NAME);
        class_destroy(sysfs_class);
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        return -1;
    }

    //create sysfs file attributes
    if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_LogAttribute.attr))
    {
        printk(KERN_ERR "Failed to init module: device_create_file failed.");
        FreeLogger(logger);
        FreeRuleManager(ruleManager);
        kfree(forward_hook_ops);
        nf_unregister_net_hook(&init_net, forward_hook_ops);
        unregister_chrdev(major_number, DEVICE_NAME);
        class_destroy(sysfs_class);
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_RulesAttribute.attr);
        return -1;
    }

    return 0;
}

static void __exit cleanup(void)
{
    nf_unregister_net_hook(&init_net, forward_hook_ops);
    kfree(forward_hook_ops);

    device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_RulesAttribute.attr);
    device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_LogAttribute.attr);

    device_destroy(sysfs_class, MKDEV(major_number, 0));
    class_destroy(sysfs_class);

    unregister_chrdev(major_number, DEVICE_NAME);

    FreeLogger(logger);
    FreeRuleManager(ruleManager);
}

//---------------------------------------------------------------

module_init(init);
module_exit(cleanup);

//========================= END OF FILE =========================

