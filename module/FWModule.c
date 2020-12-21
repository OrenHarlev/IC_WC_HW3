
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
#include "FWConnectionManager.h"
#include "FWLogger.h"
#include "FWProxyHelper.h"


//================== GLOBALS AND MACROS ===========================

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oren Harlev");

//------------------------netfilter--------------------------------

static struct nf_hook_ops *preRoutHookOps = NULL;
static struct nf_hook_ops *localOutHookOps = NULL;

//---------------------------sysfs-device---------------------------------

static int major;
static struct class* sysfsClass = NULL;
static struct device* sysfsRulesDevice = NULL;
static struct device* sysfsLogResetDevice = NULL;
static struct device* sysfsConnectionsDevice = NULL;

//---------------------------logic---------------------------------

static RuleManager ruleManager;
static ConnectionManager connectionManager;
static Logger logger;

//==================== FUNCTIONS ===========================

//---------------------------device---------------------------------

static ssize_t LogRead(struct file *filp, char *buff, size_t length, loff_t *offp)
{
    char *logBuff = kmalloc(length, GFP_KERNEL);
    ssize_t result = 0;

    ssize_t logLength = ReadLogs(logBuff, length, logger);

    if (logLength < 0)
    {
        result = -EFAULT;
    }
    else if (logLength == 0)
    {
        result = 0;
    }
    else
    {
        result = copy_to_user(buff, logBuff, logLength) ? -EFAULT : logLength;
    }

    kfree(logBuff);
    return result;
}

static int LogOpen(struct inode *_inode, struct file *_file)
{
    return ResetLogReader(logger);
}

static int LogClose(struct inode *_inode, struct file *_file)
{
    return ResetLogReader(logger);
}

static struct file_operations LogReadFops =
{
    .owner = THIS_MODULE,
    .read = LogRead,
    .open = LogOpen,
    .release = LogClose,
};

//------------------------netfilter hooks--------------------------------

static unsigned int FWPreRoutHook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return MatchRawPacket(skb, state, ruleManager, connectionManager, logger);
}

static unsigned int FWLocalOutHook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // todo handle error and print if redirected
    return RedirectLocalOutPacket(skb, connectionManager);
}

//------------------------sysfs api--------------------------------

ssize_t RulesDisplay(struct device *dev, struct device_attribute *attr, char *buf)
{
    return GetRawRules(ruleManager, buf);
}

ssize_t RulesModify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    char rawRules[count];
    memcpy(rawRules, buf, count);
    return UpdateRules(rawRules, count, ruleManager);
}

ssize_t LogModify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    ResetLogs(logger);
    return count;
}

ssize_t ConnectionDisplay(struct device *dev, struct device_attribute *attr, char *buf)
{
    return ReadConnections(connectionManager, buf);
}

ssize_t ConnectionModify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return AddRawConnection(buf, count, connectionManager);
}

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, RulesDisplay, RulesModify);
static DEVICE_ATTR(conns, S_IWUSR | S_IRUGO, ConnectionDisplay, ConnectionModify);
static DEVICE_ATTR(reset, S_IWUSR, NULL, LogModify);

//==================== MODULE SETUP =============================

static int __init init(void)
{
    ruleManager = CreateRuleManager();
    connectionManager = CreateConnectionManager();
    logger = CreateLogger();
    if (ruleManager == NULL || connectionManager == NULL || logger == NULL)
    {
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        printk(KERN_ERR "Failed to init module: Memory allocation failed.");
        return -1;
    }

    preRoutHookOps = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (preRoutHookOps == NULL)
    {
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        printk(KERN_ERR "Failed to init module: Memory allocation failed.");
        return -1;
    }

    preRoutHookOps->hook = (nf_hookfn*)FWPreRoutHook;
    preRoutHookOps->hooknum = NF_INET_PRE_ROUTING;
    preRoutHookOps->pf = PF_INET;
    preRoutHookOps->priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, preRoutHookOps) != 0)
    {
        printk(KERN_ERR "Failed to init module: forward hook_ops init failed.");
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    localOutHookOps = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (localOutHookOps == NULL)
    {
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        printk(KERN_ERR "Failed to init module: Memory allocation failed.");
        return -1;
    }

    localOutHookOps->hook = (nf_hookfn*)FWLocalOutHook;
    localOutHookOps->hooknum = NF_INET_LOCAL_OUT;
    localOutHookOps->pf = PF_INET;
    localOutHookOps->priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, localOutHookOps) != 0)
    {
        printk(KERN_ERR "Failed to init module: forward hook_ops init failed.");
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    //create char devices
    major = register_chrdev(0, DEVICE_NAME_LOG_READ, &LogReadFops);
    if (major < 0)
    {
        printk(KERN_ERR "Failed to init module: register_chrdev failed.");
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    //create sysfs class
    sysfsClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(sysfsClass))
    {
        printk(KERN_ERR "Failed to init module: class_create failed.");
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    //create sysfs device
    sysfsRulesDevice = device_create(sysfsClass, NULL, MKDEV(major, MINOR_LOG_READ), NULL, DEVICE_NAME_LOG_READ);
    if (IS_ERR(sysfsRulesDevice))
    {
        printk(KERN_ERR "Failed to init module: device_create failed.");
        class_destroy(sysfsClass);
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    sysfsRulesDevice = device_create(sysfsClass, NULL, MKDEV(major, MINOR_RULES), NULL, DEVICE_NAME_RULES);
    if (IS_ERR(sysfsRulesDevice))
    {
        printk(KERN_ERR "Failed to init module: device_create failed.");
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG_READ));
        class_destroy(sysfsClass);
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    sysfsLogResetDevice = device_create(sysfsClass, NULL, MKDEV(major, MINOR_LOG), NULL, DEVICE_NAME_LOG_RESET);
    if (IS_ERR(sysfsLogResetDevice))
    {
        printk(KERN_ERR "Failed to init module: device_create failed.");
        device_destroy(sysfsClass, MKDEV(major, MINOR_RULES));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG_READ));
        class_destroy(sysfsClass);
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    sysfsConnectionsDevice = device_create(sysfsClass, NULL, MKDEV(major, MINOR_CONNS), NULL, "conns");
    if (IS_ERR(sysfsConnectionsDevice))
    {
        printk(KERN_ERR "Failed to init module: device_create failed.");
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG));
        device_destroy(sysfsClass, MKDEV(major, MINOR_RULES));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG_READ));
        class_destroy(sysfsClass);
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    //create sysfs file attributes
    if (device_create_file(sysfsRulesDevice, (const struct device_attribute *)&dev_attr_rules.attr))
    {
        printk(KERN_ERR "Failed to init module: device_create_file failed.");
        device_destroy(sysfsClass, MKDEV(major, MINOR_CONNS));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG));
        device_destroy(sysfsClass, MKDEV(major, MINOR_RULES));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG_READ));
        class_destroy(sysfsClass);
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    //create sysfs file attributes
    if (device_create_file(sysfsLogResetDevice, (const struct device_attribute *)&dev_attr_reset.attr))
    {
        printk(KERN_ERR "Failed to init module: device_create_file failed.");
        device_remove_file(sysfsRulesDevice, (const struct device_attribute *)&dev_attr_rules.attr);
        device_destroy(sysfsClass, MKDEV(major, MINOR_CONNS));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG));
        device_destroy(sysfsClass, MKDEV(major, MINOR_RULES));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG_READ));
        class_destroy(sysfsClass);
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    //create sysfs file attributes
    if (device_create_file(sysfsConnectionsDevice, (const struct device_attribute *)&dev_attr_conns.attr))
    {
        printk(KERN_ERR "Failed to init module: device_create_file failed.");
        device_remove_file(sysfsRulesDevice, (const struct device_attribute *)&dev_attr_rules.attr);
        device_destroy(sysfsClass, MKDEV(major, MINOR_CONNS));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG));
        device_destroy(sysfsClass, MKDEV(major, MINOR_RULES));
        device_destroy(sysfsClass, MKDEV(major, MINOR_LOG_READ));
        class_destroy(sysfsClass);
        unregister_chrdev(major, DEVICE_NAME_LOG_READ);
        nf_unregister_net_hook(&init_net, localOutHookOps);
        kfree(localOutHookOps);
        nf_unregister_net_hook(&init_net, preRoutHookOps);
        kfree(preRoutHookOps);
        FreeLogger(logger);
        FreeConnectionManager(connectionManager);
        FreeRuleManager(ruleManager);
        return -1;
    }

    return 0;
}

static void __exit cleanup(void)
{
    device_remove_file(sysfsConnectionsDevice, (const struct device_attribute *)&dev_attr_conns.attr);
    device_remove_file(sysfsLogResetDevice, (const struct device_attribute *)&dev_attr_reset.attr);
    device_remove_file(sysfsRulesDevice, (const struct device_attribute *)&dev_attr_rules.attr);
    device_destroy(sysfsClass, MKDEV(major, MINOR_CONNS));
    device_destroy(sysfsClass, MKDEV(major, MINOR_LOG));
    device_destroy(sysfsClass, MKDEV(major, MINOR_RULES));
    device_destroy(sysfsClass, MKDEV(major, MINOR_LOG_READ));
    class_destroy(sysfsClass);
    unregister_chrdev(major, DEVICE_NAME_LOG_READ);
    nf_unregister_net_hook(&init_net, localOutHookOps);
    kfree(localOutHookOps);
    nf_unregister_net_hook(&init_net, preRoutHookOps);
    kfree(preRoutHookOps);
    FreeLogger(logger);
    FreeConnectionManager(connectionManager);
    FreeRuleManager(ruleManager);
}

//---------------------------------------------------------------

module_init(init);
module_exit(cleanup);

//========================= END OF FILE =========================

