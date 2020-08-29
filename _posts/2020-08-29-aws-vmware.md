---
layout: post
title:  "Converting AWS AMI to OVF"
date:   2020-08-29 01:00:00 +0100
categories: [vmware]
description: ""
image:
  feature: aws.png
  credit:
---

This is a short post covering the steps to convert an AWS AMI to a VMDK.

Step 1
------
Follow the instructions at [https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport_image.html](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport_image.html) in order to export a vmdk to an S3 bucket

Step 2
-----
Run the following command over the exported and downloaded vmdk:
```
C:\Program Files (x86)\VMware\VMware Workstation>vmware-vdiskmanager.exe -r C:/Users/booj/Downloads/export-ami-abcdef.vmdk -t 0 C:/Users/booj/Downloads/out.vmdk
```

Step 3
-----
Mount the outputted vmdk as the primary boot volume of a VMWare Workstation VM.  Ensure BIOS (not UEFI) is selected during the VM creation.
