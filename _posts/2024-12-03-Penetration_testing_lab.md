---
title: "Penetration Testing Lab Setup on Digital Ocean Cloud"
date: 2024-12-03 00:00:00 +0800
categories: [Penetration Testing]
tags: [RedTeam,Linux,Docker,OWASPtop10,DVWA Cloud DiitalOcean,Penetration Testing, Free_cybersecurity,Pentester]
---


Hello Hackers! Welcome to this new Penetration Testing series. In this first post of the series, we will create our own Penetration testing lab on DigitalOcean for free.

# Introduction

"DigitalOcean offers free credits worth $200, making it an excellent option for setting up Penetration testing labs. Sign up and create your DigitalOcean account using the URL  <a href="https://m.do.co/c/20b67c04f041">  https://m.do.co/c/20b67c04f041.</a> to claim your $200 free credits."

Below is a basic flow of what must be done to create your Pentest lab.

1. Please create a user on the Digital Ocean platform and configure it to work over SSH.
2. Install essential services such as docker.
3. Install and set up the needed vulnerable services such as DVWA etc.

# Setup

Create a user account on digital ocean platform using the link: <a href="https://m.do.co/c/20b67c04f041">  https://m.do.co/c/20b67c04f041.</a>

# Signup

Sign into the newly created account using the login page.

![Desktop View](/assets/Pen1/signup.png){: width="900" height="500" }

# Create a New Project 

Create a new 'Droplet' under your newly created project. In the submenu, select the Ubuntu version you wish to use and configure the required options according to your needs.

![Desktop View](/assets/Pen1/setup.png){: width="900" height="500" }

Droplet Configurations:

```shell
-	Region: Bangalore (Choose the closest region)
-	VPC Network: default-blr1
-	Image: Ubuntu 24.10x64
-	Droplet Type: Basic (Shared CPU)
-	CPU options: Premium Intel disk NVMe SSD
	    $16/mo, 2GB 1 Intel CPU
	    70GB NVMs SSDs
	    2TB Transfer

```
![Desktop View](/assets/Pen1/drop1.png){: width="900" height="500" }
![Desktop View](/assets/Pen1/drop2.png){: width="900" height="500" }

# Configure SSH Key for the connection

Navigate to the SSH Key Section and click "Add SSH Key", Then you will have to go to your Kali Machine and run ``` ssh-keygen -t rsa ``` command and copy the Public key and paste it in the digital ocean panel.

![Desktop View](/assets/Pen1/ssh1.png){: width="900" height="500" }
![Desktop View](/assets/Pen1/ssh2.png){: width="900" height="500" }
![Desktop View](/assets/Pen1/ssh3.png){: width="900" height="500" }
![Desktop View](/assets/Pen1/ssh4.png){: width="900" height="500" }
![Desktop View](/assets/Pen1/ssh5.png){: width="900" height="500" }

Once you finished configuring the SSH, Click create droplet and wait for sometime to complete the process. Now that we have created our Droplet

![Desktop View](/assets/Pen1/droplet.png){: width="900" height="500" }

# Login to the server using Public IP

Copy the Public IP address and go to the kali machine, then login to the machine using SSH. 

``` ssh -i <Private SSH Key> root@<Public IP> ```

![Desktop View](/assets/Pen1/connect.png){: width="900" height="500" }

# Install Docker in the Droplet

```shell
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl enable docker 
sudo systemctl start docker
```

# Installing the Vulnerable applications

1. DVWA container from https://hub.docker.com/r/vulnerables/web-dvwa
   ``` sudo docker pull vulnerables/web-dvwa ```
   ``` sudo docker run --name web-dvwa -d -p 8080:80 --restart always vulnerables/web-dvwa ```
   ![Desktop View](/assets/Pen1/dvwa.png){: width="900" height="500" }

2. Install OWASP Juice-shop: https://hub.docker.com/r/bkimminich/juice-shop
    ``` sudo docker pull bkimminich/juice-shop ```
    ``` sudo docker run --name juice-shop -d -p 8081:3000 --restart always bkimminich/juice-shop ```

# Connecting to the Application

On your Kali terminal, run the below ssh port forwarding commands. Make sure to replace the <sshprivatekey> with your private key and <yourdropletip> with your droplet public IP.

```
ssh -L 80:127.0.0.1:8080 -i <sshprivatekey> user@<yourdropletip> -fN
ssh -L 81:127.0.0.1:8081 -i <sshprivatekey> user@<yourdropletip> -fN
```
![Desktop View](/assets/Pen1/connect2.png){: width="900" height="500" }

# Securing the Vulnerable Application with Firewall

By default, a firewall is not enabled. If we do not restrict access, these vulnerable applications will be exposed to everyone, which is not secure. Therefore, it is essential to configure a firewall.

Click the Droplet name and Navigate to "Networking", Then select firewall.

![Desktop View](/assets/Pen1/fire1.png){: width="900" height="500" }

Keep the SSH connections as it is and create inbound rules for ALL TCP, All UDP where we only accept the source from our public IP not everyone. Get your public IP details from  <a href="https://whatismyipaddress.com/">  Here.</a> And add the public IP in the source and remove All IPv4 and IPv6.

![Desktop View](/assets/Pen1/fire2.png){: width="900" height="500" }

After completing the steps, click on 'Create Firewall.' In the firewall settings, navigate to the 'Droplets' tab and select the droplet by its name. Your droplet is now secured with a firewall.

# DVWA 

https://<PublicIP>:8080 OR http://127.0.0.1:80

![Desktop View](/assets/Pen1/dvwa_1.png){: width="900" height="500" }

# OWASP Juice Shop

https://<PublicIP>:8081 OR http://127.0.0.1:81

![Desktop View](/assets/Pen1/owasp_1.png){: width="900" height="500" }

So thats it, Now we have successfully hosted our vulnerable application on the cloud in a secure with Docker, SSH access and the firewall rules. Im planing to make a Penetration testing series with the help of this vulerable applications and at the end i will share the Final Penetration Testing report which is align to industry standards. So Stay Tuned Guys!!!s

[![DigitalOcean Referral Badge](https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg)](https://www.digitalocean.com/?refcode=20b67c04f041&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)

```Happy Hacking :) ```
