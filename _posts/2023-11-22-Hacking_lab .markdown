---
title: "How to create secured Hacking lab with Docker Container+ Linode Cloud"
date: 2023-11-22 00:00:00 +0800
categories: [Penetration Testing]
tags: [RedTeam,Linux,container,Docker,Linux Hacking,Linode Cloud]
---


Getting really good and geeky is a breeze with Kasm. It's a tool that
lets you stay completely anonymous online. If you need to do some
hacking and want to keep it on the down-low, Kasm is the way to go ---
the ultimate hacking tool.

![](/assets/linode/media/image1.jpeg){: width="900" height="500" }

Requirements:

1.  Any cloud provider account - I choose Linode with 100\$ Free Credit
    \[<https://cloud.linode.com/>\]

2.  A Server with 2 VCPS, 4GB Ram and 50GB Storage (SSD).

3.  Setup Kasm --- [Kasm Workspaces \| The Container Streaming Platform
    (kasmweb.com)](https://kasmweb.com/)

Kasm Workspaces platform provides enterprise-class orchestration, data
loss prevention, and web streaming technology to enable the delivery of
containerized workloads to your browser. First we install Kasm in the
server and then it will open up the secure web browser and stream the
docker container through the web browser. It is using kasmVnc to stream
the docker containers. Streaming containerized apps and desktops to
end-users.

![](/assets/linode/media/image2.png)

# Kasm Workspaces Single Server

1.  Setup Linode Cloud with 100\$ free Credit. Will have to wait for 10
    Minitues to Activate the account.

![](/assets/linode/media/image3.png)

After Activate the Linode Account, you need to create the VM. For that
Click Create in the Top of the page and select Create Linode.

![](/assets/linode/media/image4.png)

Now you need to select the Linux Distribution with the minimum
requirement. So First need to select the Images, I used Ubuntu 20.04 LTS
here.

![](/assets/linode/media/image5.png)

Select the Region as Chennai since it is near to me.

![](/assets/linode/media/image6.png)

Now you need to select the Linode plan. I choose "Shared CPU with Linode
4GB" and Give any Label name and the root password.

![](/assets/linode/media/image7.png)

![](/assets/linode/media/image8.png)

Finally Provisioned the VM and the stats is running.

![](/assets/linode/media/image9.png)

 2\. Connect to Linode Server from CMD

Open CMD and type ssh root@\<IP Address\> and then accept the ssh
connection by giving "yes" and provide the root password. Now the server
is connected.

![](/assets/linode/media/image10.png)

3\. Install Kasm in the Linode server from CMD.

**Step 01 --- Setup a SWAP Partition** --- For stability and it will
allows users to run more applications simultaneously without
experiencing slowdowns or crashes caused by low memory conditions.

```bash
sudo dd if=/dev/zero bs=1M count=1024 of=/mnt/1GiB.swap\
sudo chmod 600 /mnt/1GiB.swap \[To upgrade the permision\]\
sudo mkswap /mnt/1GiB.swap \[Make Swap\]\
sudo swapon /mnt/1GiB.swap \[Turn on Swap partition.\]
```
![](/assets/linode/media/image11.png)
Verify the created Swap by running "cat /proc/swaps"

![](/assets/linode/media/image12.png)

Add the following command to get the swap whenever there is a reboot.

``` echo \'mnt/1GiB.swap swap swap defaults 00\' \| sudo tee -a /etc/fstab ```

![](/assets/linode/media/image13.png)

-   **Step 02 --- Install KASM\
    **Get the Kasm package from S3 AWS bucket with Wget command.

``` wget https://kasm-static-content.s3.amazonaws.com/kasm_release_1.14.0.3a7abb.tar.gz\ ```
To unzip the package - ``` tar -xf kasm_release_1.14.0.3a7abb.tar.gz\ ```
Navigate inside the \"Kasm_release folder and run ``` sudo bash install.sh ```

![](/assets/linode/media/image14.png)

After the installation you will the success message and the user
credentials for the kasm database. Save it in the secure location.

**Step 03 --- Test the Kasm UI from out Linode's Public IP.\
**Kasm is working on our Linode's server.

![](/assets/linode/media/image15.png)

Now login with the Kasm Administrator credential that you got from the installation part. And this is the kasm dashboard.

![](/assets/linode/media/image16.png)

**Step 04 --- Kasm Workplaces --- Navigate to Workplaces in the top of
the dashboard. And can see the pre build containers are there.**

![](/assets/linode/media/image17.png)

For example lets see how we can browse the internet securely with kasm.
For that we need to add a chrome extension called kasm --- open in
isolation. After added go the extension and click options. Now need to
change the Kasm default URL to our server URL.

![](/assets/linode/media/image18.png)

![](/assets/linode/media/image19.png)

Now we need to select the default browser image. For the Navigate to
kasm profile and select settings. There change "Default Workspace Image
as Brave" So each time user open any link from internet, it will bootup
the vm and open the brave browser inside.

**Step 05 --- Bootup Kali Container in Kasm**

Kali is already enabled in the workplace. Just need to click install.

![](/assets/linode/media/image20.png)

After installed it will be come under our workplace and we need to
change some settings.

![](/assets/linode/media/image21.png)

Now click Edit the kali and go to "Docker Run Config Override (JSON)"
and put this line {"user":"root"}, so whenever the kali machine boot, we
will get the root user.

Now go to Workspaces and Start the session for Kali Linux.

![](/assets/linode/media/image22.png)

Fixing Black Screen issue while starting the session.

![](/assets/linode/media/image23.png)

Delete the session and go back to Admin -\> Workspaces -\> and Edit the
"Docker Run Config Override (JSON)" and add the following line\
\
``` { "user":"root","security_opt": \[ "seccomp=unconfined" \] } ```

Now we started the Kali Linux Session.

![](/assets/linode/media/image24.png)

After we delete the session all the footprint will be gone, when we start the new session, we will get it as a new Operating system. It's good to hide ourselves anonymously.


```Happy Hacking :) ```