---
title: "Setting Up Metasploitable 2 with OpenVPN on AWS"
date: 2025-02-24 00:00:00 +0800
categories: [Penetration Testing]
tags: [RedTeam,Linux Hacking,Openvpn,ssh,AWS]
---

# Introduction

Metasploitable 2 is a vulnerable virtual machine designed for penetration testing practice. This guide walks you through setting it up on AWS while ensuring secure access via OpenVPN. We'll create a Virtual Private Cloud (VPC), configure networking, set up an OpenVPN server, and deploy Metasploitable 2.

# Step 1: Create a Virtual Network (VPC)

2. Go to the VPC Dashboard 
(`https://console.aws.amazon.com/vpc/`)
3. **Click on "Create VPC"** → Choose **VPC only**.
    - **Name:** `MetasploitableVPN-VPC`
    - **IPv4 CIDR:** `192.168.1.0/24`
    - Click **Create VPC**.

**Create Two Subnets**
1. **Public Subnet (For OpenVPN Server)**:
    - Click **Subnets** → **Create Subnet**.
    - **VPC ID:** `MetasploitableVPN-VPC`
    - **Subnet Name:** `Public-Subnet`
    - **CIDR Block:** `192.168.1.0/25`
    - **Auto-assign Public IPv4:** **Enabled**
    - Click **Create Subnet**.

2. **Private Subnet (For Metasploitable 2 VM)**:
    - **Subnet Name:** `Private-Subnet`
    - **CIDR Block:** `192.168.1.128/25`
    - **Auto-assign Public IPv4:** **Disabled**
    - Click **Create Subnet**.

>  
We are using a /25 CIDR block to divide the network into two subnets:
**`192.168.1.0/25`** (Public Subnet) → Used for OpenVPN Server
**`192.168.1.128/25`** (Private Subnet) → Used for Metasploitable 2
We chose /25 instead of /24 because each /25 subnet supports 126 usable IPs (2^7 - 2). By splitting the /24 into two /25 subnets, we create **one subnet for public resources** (OpenVPN) and **one for private resources** (Metasploitable 2). This prevents direct internet access to **Metasploitable 2**, improving security.
{: .prompt-danger }

# Step 2: Configure Internet Gateway and Routing

1. **Go to "Internet Gateways"** → **Create Internet Gateway**.
    1. **Name:** `VPN-IGW`
    - Click **Create Internet Gateway.**
    - Select `VPN-IGW`, click **Actions** → **Attach to VPC** → Select `MetasploitableVPN-VPC`.

2. **Go to "Route Tables"** → **Create Route Table**.
    - **Name:** `Public-Route-Table`
    - **VPC:** `MetasploitableVPN-VPC`
    - Click **Create Route Table**.

3. Edit the Public Route-Table:
    -  Select `Public-Route-Table` → Click **Routes** → **Edit routes**.
    - Add a route:
        -  **Destination:** `0.0.0.0/0`
        -  **Target:** `VPN-IGW`
    -  Click Save changes.

4. **Associate Public Subnet with Public Route Table**:
    -  Click **Subnet Associations** → **Edit**.
    -  Select **Public-Subnet** → **Save changes**.

# Step 4: Create Security Groups

1. OpenVPN Server Security Group
    -  Go to **EC2 Dashboard** → **Security Groups** → **Create Security Group**.
    -  **Name:** `OpenVPN-SG`
    -  **VPC:** `MetasploitableVPN-VPC`
    -  Inbound Rules:
   
| Rule    | Protocol | Port  | Source      |
|---------|----------|-------|-------------|
| OpenVPN | UDP      | 1194  | 0.0.0.0/0   |
| SSH     | TCP      | 22    | YOUR_IP/32  |

2. Internal Access Security Group (For Metasploitable 2)
    -  **Name:** `Internal-Access-SG`
    -  **VPC:** `MetasploitableVPN-VPC`
    -  Inbound Rules:
    
| Rule     | Protocol | Port  | Source          |
|----------|----------|-------|-----------------|
| Internal | All      | All   | 192.168.1.0/24  |


# Step 5: Launch an OpenVPN Server (Public-Subnet)- EC2 Instance  

1. Go to **EC2 Dashboard** → **Launch Instance**.
2. **Select AMI:** Choose **Ubuntu 22.04**.
3. **Instance Type:** `t2.micro` (Free Tier)
4. Network Settings:
    -  **VPC:** `MetasploitableVPN-VPC`
    -  **Subnet:** `Public-Subnet`
    -  **Security Group:** `OpenVPN-SG`
    -  **Key Pair:** Select or **create a new PEM key**.
    -  **Launch Instance**.
    -  Connect to the Instance:
          ```ssh -i your-key.pem ubuntu@<your-public-ip>```

# Step 6: Install and Configure OpenVPN

1.  Install OpenVPN:

    ```shell 
        sudo apt update && sudo apt install -y openvpn easy-rsa 
    ```

2.  Download and run the OpenVPN install script:

    ```shell
        curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
        chmod +x openvpn-install.sh
        sudo ./openvpn-install.sh
    ```
    **Public IPv4 Address or Hostname?** → Use your **public IP**
    **DNS Server?** → Select **Google (8.8.8.8, 8.8.4.4)**
    **Client Name?** → `pentest-client`

3.  Copy the `.ovpn` file to your local machine:

    ```shell 
     scp -i your-key.pem ubuntu@<your-public-ip>:/root/pentest-client.ovpn .
    ```

#  Step 7: Create Metasploitable 2 VM on EC2

**Why Create a Separate EC2 Instance?**
- **Isolation & Security:** Metasploitable 2 is intentionally vulnerable, so it should not be exposed directly to the internet.
- **Private Access:** Since it is in a private subnet, it can only be accessed via OpenVPN.
- **Network Segmentation:** The OpenVPN server in the public subnet acts as a gateway for secure access.

# Launch Metasploitable 2 on a Private EC2 Instance

1. Create an EC2 Instance in Private Subnet
2. Navigate to **AWS EC2 Dashboard** > **Launch Instance**.
3. Choose **Ubuntu (or any minimal Linux OS)** as the base image.
4. **Network settings**:
    -  **VPC:** Select your `PenTest-VPC`.
    -  **Subnet:** Choose `Private-Subnet (192.168.1.128/25)`.
    -  **Auto-assign Public IP:** **Disable** (since it's private).
    -  **Security Group:** Use the **internal access group** (allowing only 192.168.1.0/24 traffic).
5. Storage: 20GB recommended.
6. **Key Pair:** Use the same key pair as your OpenVPN server.

>  
Note:  Anyway we will remove this VM, Since AWS Dont have the Metasploitable 2 VM, We need to upload the vmdk file to the S3 bucket and then replace this VM. 

# Step 8: Configure Firewall & Routing

1. Enable IP Forwarding

    ```shell 
    sudo nano /etc/sysctl.conf

    ```
    Uncomment this line:

    ```shell 
        net.ipv4.ip_forward=1
    ```
    Save and apply changes:

    ```shell 
       sudo sysctl -p
    ```
2. Adjust Firewall Rules

    ```shell
        sudo ufw allow 1194/udp
        sudo ufw allow OpenSSH
        sudo ufw enable
    ```
3.  Configure NAT for VPN Clients

    ```shell
        sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    ```

4. Save the rule:

    ```shell
        sudo apt install iptables-persistent -y
        sudo netfilter-persistent save
        sudo netfilter-persistent reload
    ```

5. Connect to OpenVPN
    -  Open **OpenVPN Client**.
    -  Import `pentest-client.ovpn`.
    -  Click **Connect**.
    -  If you are in Linux Client then run:

    ```shell
        sudo openvpn pentest-client.ovpn
    ```
    - verify Connection:

    ``` ip a ```

    Now you should be on the 192.168.1.0/24 network!

Once you connected to the VPN, You can see 10.8.0.2 Ip address, that means our connection is established. Then we can try to ping the 2nd VM’s Private IP4 address and try to SSH to the VM. We should be able to make the connection securely.

```Happy Hacking :) ```