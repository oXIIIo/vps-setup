#!/bin/bash

if [ "$(id -u)" != "0" ]; then
    echo "Requires administrator privileges, please run this script with sudo."
    exit 1
fi

check_dialog_installation() {
    if command -v dialog &>/dev/null; then
        return 0
    else
        return 1
    fi
}

get_os_info() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        if [[ $ID == "debian" || $ID == "ubuntu" ]]; then
            echo "Debian/Ubuntu"
        elif [ $ID == "centos" ]; then
            echo "CentOS"
        elif [ $ID == "fedora" ]; then
            echo "Fedora"
        elif [ $ID == "arch" ]; then
            echo "Arch"
        else
            echo "Unknown"
        fi
    elif [ -f /etc/centos-release ]; then
        echo "CentOS"
    elif [ -f /etc/fedora-release ]; then
        echo "Fedora"
    elif [ -f /etc/arch-release ]; then
        echo "Arch"
    else
        echo "Unknown"
    fi
}

check_firewall() {
    if command -v ufw &>/dev/null; then
        echo "ufw"  
    elif command -v firewalld &>/dev/null; then
        echo "firewalld"
    elif command -v iptables &>/dev/null; then
        echo "iptables"
    elif command -v nft &>/dev/null; then
        echo "nftables"
    else
        echo "unknown"
    fi
}

display_open_ports() {
    firewall=$(check_firewall)
    case $firewall in
        "ufw")
            echo "The following TCP ports are currently open on the firewall:"
            ufw status | grep "ALLOW" | grep -oP '\d+/tcp' | sort -u
            echo "The following UDP ports are currently open on the firewall:"
            ufw status | grep "ALLOW" | grep -oP '\d+/udp' | sort -u
            ;;
        "firewalld")
            echo "The following TCP ports are currently open on the firewall:"
            firewall-cmd --list-ports | grep "tcp"
            echo "The following UDP ports are currently open on the firewall:"
            firewall-cmd --list-ports | grep "udp"
            ;;
        "iptables")
            echo "The following TCP ports are currently open on the firewall:"
            iptables-legacy -L INPUT -n --line-numbers | grep "tcp" | grep -oP '\d+' | sort -u
            echo "The following UDP ports are currently open on the firewall:"
            iptables-legacy -L INPUT -n --line-numbers | grep "udp" | grep -oP '\d+' | sort -u
            ;;
        "nftables")
            echo "The following TCP ports are currently open on the firewall:"
            nft list ruleset | grep "tcp" | grep -oP '\d+' | sort -u
            echo "The following UDP ports are currently open on the firewall:"
            nft list ruleset | grep "udp" | grep -oP '\d+' | sort -u
            ;;
        *)
            echo "No supported firewall was found."
            return 1
            ;;
    esac
}

install_components() {
    echo "Would you like to install the necessary components? (y/n)"
    echo "docker.io docker-compose fail2ban vim curl"
    read choice
    if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
        echo "Installation canceled."
        return 1
    fi
    echo "Installing..."
    os_type=$(get_os_info)
    case $os_type in
        Debian/Ubuntu)
            apt -y update || { echo "Failed to update package lists"; return 1; }
            apt -y install docker.io docker-compose fail2ban vim curl || { echo "Failed to install components"; return 1; }
            ;;
        CentOS)
            yum -y update || { echo "Failed to update package lists"; return 1; }
            yum -y install docker docker-compose fail2ban vim curl || { echo "Failed to install components"; return 1; }
            ;;
        Fedora)
            dnf -y update || { echo "Failed to update package lists"; return 1; }
            dnf -y install docker docker-compose fail2ban vim curl || { echo "Failed to install components"; return 1; }
            ;;
        Arch)
            pacman -Syu --noconfirm || { echo "Failed to update package lists"; return 1; }
            pacman -S --noconfirm docker docker-compose fail2ban vim curl || { echo "Failed to install components"; return 1; }
            ;;
        *)
            echo "Unable to determine the operating system type, cannot install components."
            return 1
            ;;
    esac
    echo "components installed successfully."
}

add_public_key() {
    echo "Please enter the public key:"
    read public_key
    if [ -z "$public_key" ]; then
        echo "Invalid public key."
        return 1
    fi
    if [[ ! "$public_key" =~ ^ssh-rsa[[:space:]]+[A-Za-z0-9+/]+[=]{0,3}(\s*.+)? ]]; then
        echo "Invalid public key format."
        return 1
    fi
    cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak
    echo "$public_key" >> ~/.ssh/authorized_keys
    if [ $? -eq 0 ]; then
        echo "Public key added successfully."
    else
        echo "Failed to add public key."
        mv ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys
        return 1
    fi
}

disable_ssh_password_login() {
    echo "Disabling SSH password login..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    if [ -f /etc/ssh/sshd_config ]; then
        chmod 600 ~/.ssh/authorized_keys
        sed -i 's/#\?PasswordAuthentication\s\+yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
        systemctl restart sshd
        if [ $? -eq 0 ]; then
            echo "SSH password login has been disabled."
        else
            echo "Failed to disable SSH password login."
            mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
            return 1
        fi
    else
        echo "sshd_config file does not exist"
        return 1
    fi
}

add_docker_tools() {
    echo "Do you want to install the docker toolbox? (includes common docker commands and custom scripts)"
    echo "-----------------------------------"
    echo "The Docker toolbox provides handy aliases for common tasks:"
    echo "Feature 1: nginx command = docker nginx" 
    echo "Feature 2: dlogs command = view docker container logs"
    echo "Feature 3: dc command = docker-compose"
    echo "Feature 4: dcs command = view docker-compose container status (needs to be executed in the compose.yml folder)"
    echo "Feature 5: dcps command = view docker-compose containers (needs to be executed in the compose.yml folder)"
    echo "Feature 6: dcip command = view container IP and add it to the host's hosts file"
    echo "The tool scripts are located in the /root/docker_tools directory - please do not delete this directory."
    echo "-----------------------------------"
    read -p "Ready to install? Press 'y' to begin or 'n' to cancel." install_choice
    case $install_choice in
        y|Y)
            if [ -e "/root/.bashrc" ]; then
                cp /root/.bashrc /root/.bashrc.bak
            fi
            tools_folder="/root/docker_tools"
            mkdir -p "$tools_folder"
            wget -qO "$tools_folder/dlogs.sh" "https://raw.githubusercontent.com/oXIIIo/vps-setup/main/dlogs.sh"
            if [ $? -eq 0 ]; then
                chmod +x "$tools_folder/dlogs.sh"
                echo "The dlogs.sh script has been downloaded and added to the $tools_folder directory."
            else
                echo "Failed to download the dlogs.sh script."
            fi
            wget -qO "$tools_folder/dcip.sh" "https://raw.githubusercontent.com/oXIIIo/vps-setup/main/dcip.sh"
            if [ $? -eq 0 ]; then
                chmod +x "$tools_folder/dcip.sh"
                echo "The dcip.sh script has been downloaded and added to the $tools_folder directory."
            else
                echo "Failed to download the dcip.sh script."
            fi
            if grep -q "alias nginx=" /root/.bashrc; then
                echo "The aliases already exist, no need to add them again."
            else
                echo 'alias nginx="docker exec -i docker_nginx nginx"' >> /root/.bashrc
                echo 'alias dc="docker-compose"' >> /root/.bashrc
                echo 'alias dcs="docker-compose ps -q | xargs docker stats"' >> /root/.bashrc
                echo 'alias dcps="docker ps $((docker-compose ps -q  || echo "#") | while read line; do echo "--filter id=$line"; done)"' >> /root/.bashrc
                echo 'alias dcip="bash /root/docker_tools/dcip.sh"' >> /root/.bashrc
                echo 'alias dlogs="bash /root/docker_tools/dlogs.sh"' >> /root/.bashrc
            fi
            echo "The Docker toolbox has been installed successfully."
            ;;
        n|N)
            echo "Docker toolbox installation is being cancelled."
            ;;
        *)
            echo "That wasn't a valid option. Cancelling the Docker toolbox installation."
            ;;
    esac
}

remove_all_swap() {
    swap_files=$(swapon -s | awk '{if($1!~"^Filename"){print $1}}')
    swap_partitions=$(grep -E '^\S+\s+\S+\sswap\s+' /proc/swaps | awk '{print $1}')
    for item in $swap_files $swap_partitions; do
        echo "Disabling and removing swap: $item"
        swapoff "$item"
        rm -f "$item"
        echo "Swap removed: $item"
    done
    echo "All swap files and partitions have been deleted."
}

cleanup_swap() {
    echo "Checking current swap space..."
    echo "=========================================="
    swap_files=$(swapon -s | awk '{if($1!~"^Filename"){print $1}}')
    swap_partitions=$(grep -E '^\S+\s+\S+\sswap\s+' /proc/swaps | awk '{print $1}')
    total_memory=$(free -m | awk 'NR==2{print $2}')
    used_memory=$(free -m | awk 'NR==2{print $3}')
    used_swap=$(free -m | awk 'NR==3{print $3}')
    used_memory_percent=$(( (used_memory) * 100 / total_memory ))
    total_used_percent=$(( (used_memory + used_swap) * 100 / total_memory ))
    if [ -n "$swap_files" ]; then
        echo "Current swap space size:"
        swapon --show
        echo "=========================================="
        echo "Physical memory usage: $used_memory_percent% ( $used_memory MB/ $total_memory MB )"
        echo "Percentage of physical memory occupied by used physical and virtual memory: $total_used_percent% ( $((used_memory + used_swap)) MB / $total_memory MB )"
        if [ $total_used_percent -gt 80 ]; then
            echo "It is not recommended to clear the swap cache because the total of physical memory usage and swap usage exceeds 80% of physical memory."
            echo "Clearing the swap cache may lead to insufficient system memory, impacting performance and stability."
        else
            echo "Should I clear the swap cache?"
            read -p "Press 'y' to begin or 'n' to cancel." cleanup_choice
            case $cleanup_choice in
                y|Y)
                    for item in $swap_files $swap_partitions; do
                        echo "Cleaning swap cache: $item"
                        swapoff "$item"
                        echo "Swap cache cleaned: $item"
                        swapon "$item"
                    done

                    echo "All swap caches have been cleaned."
                    ;;
                n|N)
                    echo "It is not necessary to clean the swap cache."
                    ;;
                *)
                    echo "Invalid option, keeping existing swap space."
                    ;;
            esac
        fi
    fi
}

set_virtual_memory() {
    echo "Checking existing swap..."
    swap_files=$(swapon -s | awk '{if($1!~"^Filename"){print $1}}')
    if [ -n "$swap_files" ]; then
        echo "Existing swap size(s):"
        swapon --show
        echo "Do you want to remove existing swap?"
        read -p "Enter y or n: " remove_choice
        case $remove_choice in
            y|Y)
                remove_all_swap
                ;;
            n|N)
                echo "Keeping existing swap."
                ;;
            *)
                echo "Invalid choice. Keeping existing swap."
                ;;
        esac
    fi
    echo "Choose a virtual memory size or enter manually:"
    echo "1. 256M"
    echo "2. 512M"
    echo "3. 1GB"
    echo "4. 2GB"
    echo "5. 4GB"
    echo "6. Enter size manually"
    read -p "Enter choice number (q to quit): " choice
    case $choice in
        1)
            swap_size="256M"
            ;;
        2)
            swap_size="512M"
            ;;
        3)
            swap_size="1G"
            ;;
        4)
            swap_size="2G"
            ;;
        5)
            swap_size="4G"
            ;;
        6)
            read -p "Enter virtual memory size (e.g., 256M, 1G, 2G): " swap_size_input
            swap_size="$swap_size_input"
            ;;
        q|Q)
            echo "Returning to main menu..."
            return 1
            ;;
        *)
            echo "Invalid choice."
            return 1
            ;;
    esac
    echo "Setting virtual memory..."
    if [ -n "$swap_files" ]; then
        echo "Existing swap files found. Removing existing swap files..."
        remove_all_swap
    fi
    case $swap_size in
        *M)
            swap_size_kb=$(( ${swap_size//[^0-9]/} * 1024 ))
            ;;
        *G)
            swap_size_kb=$(( ${swap_size//[^0-9]/} * 1024 * 1024 ))
            ;;
        *)
            echo "Invalid virtual memory size unit."
            return 1
            ;;
    esac
    dd if=/dev/zero of=/swap bs=1k count=$swap_size_kb
    if [ $? -eq 0 ]; then
        chmod 600 /swap
        mkswap /swap
        swapon /swap
        if [ $? -eq 0 ]; then
            echo "/swap swap swap defaults 0 0" >> /etc/fstab
            echo "Virtual memory set up successfully."
            echo "Current swap size:"
            swapon -s | grep '/swap'
        else
            echo "Swap file created successfully, but failed to enable swap. Please check commands for errors."
            return 1
        fi
    else
        echo "Failed to create swap file. Please check commands for errors."
        return 1
    fi
}

modify_swap_usage_threshold() {
    echo "Current vm.swappiness value is: $(cat /proc/sys/vm/swappiness)"
    echo "Modifying swap usage threshold..."
    read -p "Enter new vm.swappiness value (0-100): " swap_value
    if ! [[ "$swap_value" =~ ^[0-9]+$ ]] || [ "$swap_value" -lt 0 ] || [ "$swap_value" -gt 100 ]; then
        echo "Invalid input. Please enter a number between 0 and 100."
        return 1
    fi
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    if grep -q "^vm.swappiness" /etc/sysctl.conf; then
        sed -i "s/^vm.swappiness=.*/vm.swappiness=$swap_value/" /etc/sysctl.conf
    else
        echo "vm.swappiness=$swap_value" >> /etc/sysctl.conf
    fi
    sysctl -p
    if grep -q "^vm.swappiness=$swap_value" /etc/sysctl.conf; then
        echo "Swap usage threshold modified successfully."
        echo "vm.swappiness value set to $swap_value"
    else
        echo "Failed to modify swap usage threshold. Please check configuration file."
        mv /etc/sysctl.conf.bak /etc/sysctl.conf
        return 1
    fi
}

optimize_kernel_parameters() {
    read -p "Sure to tweak kernel settings? (y/n): " optimize_choice

    case $optimize_choice in
        y|Y)
            echo "Backing up original kernel configuration..."
            cp /etc/sysctl.conf /etc/sysctl.conf.bak
            echo "Optimizing kernel parameters..."
            if grep -q "^net.ipv4.tcp_fastopen=3" /etc/sysctl.conf; then
                sed -i 's/^net.ipv4.tcp_fastopen=3/#net.ipv4.tcp_fastopen=3/' /etc/sysctl.conf
            fi
            if ! grep -q "^net.ipv4.tcp_slow_start_after_idle" /etc/sysctl.conf; then
                echo "net.ipv4.tcp_slow_start_after_idle=0" >> /etc/sysctl.conf
            else
                sed -i 's/^net.ipv4.tcp_slow_start_after_idle=.*/net.ipv4.tcp_slow_start_after_idle=0/' /etc/sysctl.conf
            fi
            if ! grep -q "^net.ipv4.tcp_notsent_lowat" /etc/sysctl.conf; then
                echo "net.ipv4.tcp_notsent_lowat=16384" >> /etc/sysctl.conf
            else
                sed -i 's/^net.ipv4.tcp_notsent_lowat=.*/net.ipv4.tcp_notsent_lowat=16384/' /etc/sysctl.conf
            fi
            if ! grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf; then
                echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
            fi
            if ! grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
                echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
            fi
            sysctl -p
            if grep -q "^net.ipv4.tcp_slow_start_after_idle=0" /etc/sysctl.conf &&
            grep -q "^net.ipv4.tcp_notsent_lowat=16384" /etc/sysctl.conf &&
            grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf &&
            grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
            echo "Kernel parameters optimized successfully."
            else
                echo "Failed to optimize kernel parameters. Please check configuration file."
                mv /etc/sysctl.conf.bak /etc/sysctl.conf
                return 1
            fi
            ;;
        n|N)
            echo "Kernel parameter optimization canceled."
            ;;
        *)
            echo "Invalid option."
            return 1
            ;;
    esac
}

install_xanmod_kernel() {
    echo "Current kernel version:$(uname -r)"
    cpu_support_info=$(/usr/bin/awk -f <(wget -qO - https://raw.githubusercontent.com/oXIIIo/vps-setup/main/check_x86-64_psabi.sh))
    if [[ $cpu_support_info == "CPU supports x86-64-v"* ]]; then
        cpu_support_level=${cpu_support_info#CPU supports x86-64-v}
        echo "Your CPU supports XanMod kernel x86-64-v$cpu_support_level"
    else
        echo "Your CPU is not supported by XanMod kernel, installation failed."
        return 1
    fi
    read -p "Continue to download and install XanMod kernel? (y/n): " continue_choice
    case $continue_choice in
        y|Y)
            echo "Downloading XanMod kernel from GitHub..."
            echo "XanMod kernel website https://xanmod.org"
            echo "Kernel from https://sourceforge.net/projects/xanmod/files/releases/lts/"
            curl -fSsL https://dl.xanmod.org/archive.key | gpg --dearmor | sudo tee /usr/share/keyrings/xanmod-archive-keyring.gpg > /dev/null
            echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list
            sudo apt-get update
            sudo apt-get install linux-xanmod-x64v${cpu_support_info#CPU supports x86-64-v} -y
            if [ $? -eq 0 ]; then
                echo "The XanMod kernel has been installed successfully."
                read -p "Do you want to update the grub configuration? (y/n):" update_grub_choice
                case $update_grub_choice in
                    y|Y)
                        update-grub
                        echo "Grub updated. Reboot to use the new kernel."
                        echo "if you want to use BBRv3, run 'kernel optimization options' after reboot."
                        ;;
                    n|N)
                        echo "Continue with the current Grub configuration."
                        ;;
                    *)
                        echo "The chosen option is invalid. Grub boot configuration update will be skipped."
                        ;;
                esac
            else
                echo "The XanMod kernel installation was unsuccessful."
            fi
            ;;
        n|N)
            echo "XanMod kernel installation cancelled."
            ;;
        *)
            echo "Invalid option. XanMod kernel installation cancelled."
            ;;
    esac
}

uninstall_xanmod_kernel() {
    echo "Checking the current kernel...$(uname -r)"
    current_kernel_version=$(uname -r)
    if [[ $current_kernel_version == *-xanmod* ]]; then
        echo "The current kernel is a XanMod kernel: $current_kernel_version"
        read -p "Are you sure you want to uninstall the XanMod kernel and restore the original kernel? (y/n): " confirm
        if [[ $confirm == [yY] ]]; then
            echo "Uninstalling the XanMod kernel and restoring the original kernel..."
            apt-get purge linux-image-*xanmod* linux-headers-*xanmod* -y
            apt-get autoremove -y
            update-grub
            echo "The XanMod kernel has been uninstalled and the original kernel restored. Grub boot configuration has been updated and will take effect after a reboot."
        else
            echo "Uninstall operation cancelled."
        fi
    else
        echo "The current kernel is not a XanMod kernel and cannot be uninstalled."
    fi
}

modify_ssh_port() {
    current_port=$(grep -oP '^Port \K\d+' /etc/ssh/sshd_config)
    if [ -z "$current_port" ]; then
        echo "The current SSH port number is not set (commented out), please enter the new SSH port number:"
    else
        echo "The current SSH port number is: $current_port, please enter the new SSH port number:"
    fi
    read -p "New SSH port number: " new_port
    if ! [[ "$new_port" =~ ^[0-9]+$ ]]; then
        echo "Invalid input, please enter a valid port number."
        return 1
    fi
    if [ -z "$current_port" ]; then
        sed -i "/^#Port/a Port $new_port" /etc/ssh/sshd_config
    else
        sed -i "s/^Port .*/Port $new_port/" /etc/ssh/sshd_config
    fi
    chmod 644 /etc/ssh/sshd_config
    systemctl restart sshd
    echo "The SSH port number has been modified to: $new_port"
    firewall=$(check_firewall)
    case $firewall in
        "ufw")
            ufw allow $new_port/tcp
            echo "Opened SSH port $new_port in ufw"
            ;;
        "firewalld")
            firewall-cmd --add-port=$new_port/tcp --permanent
            firewall-cmd --reload
            echo "Opened SSH port $new_port in firewalld"
            ;;
        "iptables")
            iptables -A INPUT -p tcp --dport $new_port -j ACCEPT
            service iptables save
            service iptables restart
            echo "Opened SSH port $new_port in iptables"
            ;;
        "nftables")
            nft add rule ip filter input tcp dport $new_port accept
            echo "Opened SSH port $new_port in nftables"
            ;;
        *)
            echo "Unsupported firewall or unable to find firewall."
            ;;
    esac
}

set_firewall_ports() {
    firewall=$(check_firewall)
    case $firewall in
        "ufw")
            firewall_cmd="ufw"
            ;;
        "firewalld")
            firewall_cmd="firewall-cmd"
            ;;
        "iptables")
            firewall_cmd="iptables-legacy"
            ;;
        "nftables")
            firewall_cmd="nft"
            ;;
        *)
            echo "Unsupported firewall"
            return 1
            ;;
    esac
    echo "The current system-installed firewall is: $(check_firewall)"
    echo "=========================================="
    display_open_ports
    echo -e "============================================="
    echo "Please select an operation:"
    echo -e "============================================="
    echo "1. Open firewall ports"
    echo "2. Close firewall ports"
    echo "q. Return to main menu"
    read -p "Enter operation option (1/2): " action
    case $action in
        1)
            echo -e "============================================="
            read -p "Enter new firewall ports to open, separated by commas, like 80t,443t,53u (t for TCP, u for UDP): " new_ports_input
            IFS=',' read -ra new_ports <<< "$new_ports_input"
            for port_input in "${new_ports[@]}"; do
                if [[ ! "$port_input" =~ ^[0-9]+[tu]$ ]]; then
                    echo "Invalid input, please follow the format: port number and protocol abbreviation (e.g., 80t or 443u)."
                    return 1
                fi
                port="${port_input%[tu]}"
                case "${port_input: -1}" in
                    t)
                        protocol="tcp"
                        ;;
                    u)
                        protocol="udp"
                        ;;
                    *)
                        echo "Invalid protocol"
                        return 1
                        ;;
                esac
                $firewall_cmd allow $port/$protocol
                echo "Open $protocol port $port successfully."
            done
            ;;
        2)
            echo -e "============================================="
            read -p "Enter firewall ports to close, separated by commas, like 80t,53u (t for TCP, u for UDP): " ports_to_close_input
            IFS=',' read -ra ports_to_close <<< "$ports_to_close_input"
            for port_input in "${ports_to_close[@]}"; do
                if [[ ! "$port_input" =~ ^[0-9]+[tu]$ ]]; then
                    echo "Invalid input, please follow the format: port number and protocol abbreviation (e.g., 80t or 443u)."
                    return 1
                fi
                port="${port_input%[tu]}"
                case "${port_input: -1}" in
                    t)
                        protocol="tcp"
                        ;;
                    u)
                        protocol="udp"
                        ;;
                    *)
                        echo "Invalid protocol."
                        return 1
                        ;;
                esac
                $firewall_cmd deny $port/$protocol
                echo "Close $protocol port $port successfully."
            done
            ;;
        q|Q)
            return 1
            ;;
        *)
            echo "Invalid operation."
            return 1
            ;;
    esac
}

display_menu() {
    linux_version=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release)
    kernel_version=$(uname -r)
    memory_usage=$(free | awk '/Mem/{printf("%.2f", $3/$2 * 100)}')
    GREEN='\033[0;32m'
    BOLD='\033[1m'
    RESET='\033[0m'
    clear
    echo -e "${BOLD}Welcome to oXIIIo's Linux configuration tool${RESET}"
    echo -e "${BOLD}GitHub: https://github.com/oXIIIo/vps-setup${RESET}"
    echo -e "${BOLD}-----------------------------------"
    echo -e "Current Linux distribution version: ${GREEN}${BOLD}${linux_version}${RESET}"
    echo -e "Current kernel version: ${GREEN}${BOLD}${kernel_version}${RESET}"
    echo -e "Current memory usage: ${GREEN}${BOLD}${memory_usage}%${RESET}"
    echo -e "${BOLD}-----------------------------------"
    echo -e "Please select an option: \n"
    echo -e "${BOLD}选项${RESET}     ${BOLD}描述${RESET}"
    echo "-----------------------------------"
    echo -e "${GREEN} 1${RESET}       Install necessary components"
    echo -e "${GREEN} 2${RESET}       Add public key for device registration"
    echo -e "${GREEN} 3${RESET}       Disable SSH password login"
    echo -e "${GREEN} 4${RESET}       Change SSH port number"
    echo -e "${GREEN} 5${RESET}       Add Docker tool script"
    echo -e "${GREEN} 6${RESET}       Set Swap size"
    echo -e "${GREEN} 7${RESET}       Modify Swap usage threshold"
    echo -e "${GREEN} 8${RESET}       Clear Swap cache"
    echo -e "${GREEN} 9${RESET}       Optimize kernel parameters"
    os_type=$(get_os_info)
    case $os_type in
        "Debian/Ubuntu")
            echo -e "${GREEN} 10${RESET}      Download and install XanMod kernel (BBRv3)"
            echo -e "${GREEN} 11${RESET}      Uninstall XanMod kernel and restore original kerne"
            ;;
    esac
    echo -e "${GREEN} 12${RESET}      Set firewall port"
    echo "-----------------------------------"
    echo -e "${BOLD}Enter${RESET} 'q' ${BOLD}to exit${RESET}"
}

display_dialog_menu() {
    os_type=$(get_os_info)
    linux_version=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release)
    kernel_version=$(uname -r)
    memory_usage=$(free | awk '/Mem/{printf("%.2f", $3/$2 * 100)}')
    backtitle="GitHub: https://github.com/oXIIIo/vps-setup \
    Current Linux distribution version: ${linux_version} \
    Current kernel version: ${kernel_version} \
    Current memory usage: ${memory_usage}%"
    dialog_cmd="dialog --clear --title \"oXIIIo's Linux Configuration Tool\" \
        --backtitle \"$backtitle\" \
        --menu \"Please select an option:\" 15 60 10 \
        1 \"Install necessary components\" \
        2 \"Add public key for device registration\" \
        3 \"Disable SSH password login\" \
        4 \"Change SSH port number\" \
        5 \"Add Docker tool script\" \
        6 \"Set Swap size\" \
        7 \"Modify Swap usage threshold\" \
        8 \"Clear Swap cache\" \
        9 \"Optimize kernel parameters\""
    if [[ $os_type == "Debian/Ubuntu" ]]; then
        dialog_cmd="${dialog_cmd} \
        10 \"Download and install XanMod kernel (BBRv3)\" \
        11 \"Uninstall XanMod kernel and restore original kernel\""
    fi
    dialog_cmd="${dialog_cmd} \
        12 \"Set firewall port\" \
        q \"Exit\" 2> menu_choice.txt"

    eval "$dialog_cmd"
}

handle_choice() {
    clear
    case $1 in
        1) install_components ;;
        2) add_public_key ;;
        3) disable_ssh_password_login ;;
        4) modify_ssh_port ;;
        5) add_docker_tools ;;
        6) set_virtual_memory ;;
        7) modify_swap_usage_threshold ;;
        8) cleanup_swap ;;
        9) optimize_kernel_parameters ;;
        10) install_xanmod_kernel ;;
        11) uninstall_xanmod_kernel ;;
        12) set_firewall_ports ;;
        q|Q) return 1 ;;
        *) echo "Invalid option, please enter a valid option number." ;;
    esac
    read -p "Press Enter to return to the main menu..."
}

main() {
    trap cleanup EXIT
    while true; do
        if check_dialog_installation; then
            display_dialog_menu
            choice=$(cat menu_choice.txt)
            if [ -z "$choice" ]; then
                break
            fi
            handle_choice "$choice" || break
        else
            display_menu
            read -p "Enter the option number: " choice
            handle_choice "$choice" || break
        fi
    done
    echo "Welcome back to the script!"
    sleep 0.5s
}

cleanup() {
    rm -f menu_choice.txt
    echo "Exiting the script. Thank you for using it!"
    sleep 1s
    tput reset
}

main "$@"