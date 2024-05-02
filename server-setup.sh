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
    if [[ "$ID" == "debian" || "$ID" == "ubuntu" ]]; then
      echo "Debian/Ubuntu"
    elif [ "$ID" == "centos" ]; then
      echo "CentOS"
    elif [ "$ID" == "fedora" ]; then
      echo "Fedora"
    elif [ "$ID" == "arch" ]; then
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
    echo "Currently open TCP ports on the firewall:"
    ufw status | grep "ALLOW" | grep -oP '\d+/tcp' | sort -u
    echo "Currently open UDP ports on the firewall:"
    ufw status | grep "ALLOW" | grep -oP '\d+/udp' | sort -u
    ;;

  "firewalld")
    echo "Currently open TCP ports on the firewall:"
    firewall-cmd --list-ports | grep "tcp"
    echo "Currently open UDP ports on the firewall:"
    firewall-cmd --list-ports | grep "udp"
    ;;

  "iptables")
    echo "Currently open TCP ports on the firewall:"
    iptables-legacy -L INPUT -n --line-numbers | grep "tcp" | grep -oP '\d+' | sort -u
    echo "Currently open UDP ports on the firewall:"
    iptables-legacy -L INPUT -n --line-numbers | grep "udp" | grep -oP '\d+' | sort -u
    ;;

  "nftables")
    echo "Currently open TCP ports on the firewall:"
    nft list ruleset | grep "tcp" | grep -oP '\d+' | sort -u
    echo "Currently open UDP ports on the firewall:"
    nft list ruleset | grep "udp" | grep -oP '\d+' | sort -u
    ;;

  *)
    echo "No supported firewall was detected."
    return 1
    ;;

  esac
}

install_components() {
  read -p "Would you like to install the necessary components? (y/n) " choice

  case $choice in
  y | Y) ;;

  *)
    echo "Installation canceled."
    return 1
    ;;

  esac

  echo "Installing..."
  os_type=$(get_os_info)

  case $os_type in
  Debian/Ubuntu)
    apt -y update || {
      echo "Failed to update package lists"
      return 1
    }
    apt -y install docker.io docker-compose fail2ban vim curl || {
      echo "Failed to install components"
      return 1
    }
    ;;

  CentOS)
    yum -y update || {
      echo "Failed to update package lists"
      return 1
    }
    yum -y install docker docker-compose fail2ban vim curl || {
      echo "Failed to install components"
      return 1
    }
    ;;

  Fedora)
    dnf -y update || {
      echo "Failed to update package lists"
      return 1
    }
    dnf -y install docker docker-compose fail2ban vim curl || {
      echo "Failed to install components"
      return 1
    }
    ;;

  Arch)
    pacman -Syu --noconfirm || {
      echo "Failed to update package lists"
      return 1
    }
    pacman -S --noconfirm docker docker-compose fail2ban vim curl || {
      echo "Failed to install components"
      return 1
    }
    ;;

  *)
    echo "Unable to determine the operating system type, cannot install components."
    return 1
    ;;

  esac

  echo "components installed successfully."
}

add_public_key() {
  read -p "Please enter the public key: " public_key

  if [ -z "$public_key" ]; then
    echo "The public key cannot be empty. Please try again."
    return 1
  fi

  if [[ ! "$public_key" =~ ^ssh-rsa[[:space:]]+[A-Za-z0-9+/]+[=]{0,3}(\s*.+)? ]]; then
    echo "The public key format is invalid. It should be in the format: ssh-rsa <key>"
    return 1
  fi

  cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak
  echo "$public_key" >>~/.ssh/authorized_keys

  if [ $? -eq 0 ]; then
    echo "The public key has been added successfully."
  else
    echo "Failed to add the public key. Please try again."
    mv ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys
    return 1
  fi
}

disable_ssh_password_login() {
  echo "Disabling SSH password login..."

  if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    chmod 600 ~/.ssh/authorized_keys
    sed -i 's/#\?PasswordAuthentication\s\+yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    if systemctl restart sshd; then
      echo "SSH password login has been successfully disabled."
    else
      echo "Failed to disable SSH password login."
      mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
      return 1
    fi
  else
    echo "The sshd_config file does not exist. Cannot disable SSH password login."
    return 1
  fi
}

add_docker_tools() {
  echo "Do you want to install the Docker toolbox?"
  echo "-----------------------------------"
  echo "The Docker toolbox provides handy aliases for common tasks:"
  echo "  • nginx command: docker nginx"
  echo "  • dlogs command: view docker container logs"
  echo "  • dc command: docker-compose"
  echo "  • dcs command: view docker-compose container status (needs to be executed in the compose.yml folder)"
  echo "  • dcps command: view docker-compose containers (needs to be executed in the compose.yml folder)"
  echo "  • dcip command: view container IP and add it to the host's hosts file"
  echo "The tool scripts will be located in the /root/docker_tools directory. Please do not delete this directory."
  echo "-----------------------------------"
  read -p "Ready to install? (y/n) " install_choice

  case $install_choice in
  y | Y)
    if [ -e "/root/.bashrc" ]; then
      cp /root/.bashrc /root/.bashrc.bak
    fi
    tools_folder="/root/docker_tools"
    mkdir -p "$tools_folder"

    echo "Downloading scripts..."
    wget -qO "$tools_folder/dlogs.sh" "https://raw.githubusercontent.com/oXIIIo/vps-setup/main/dlogs.sh"
    if [ $? -eq 0 ]; then
      chmod +x "$tools_folder/dlogs.sh"
      echo "The dlogs.sh script has been downloaded and added to the $tools_folder directory."
    else
      echo "Failed to download the dlogs.sh script."
      return 1
    fi

    wget -qO "$tools_folder/dcip.sh" "https://raw.githubusercontent.com/oXIIIo/vps-setup/main/dcip.sh"
    if [ $? -eq 0 ]; then
      chmod +x "$tools_folder/dcip.sh"
      echo "The dcip.sh script has been downloaded and added to the $tools_folder directory."
    else
      echo "Failed to download the dcip.sh script."
      return 1
    fi

    echo "Adding aliases to ~/.bashrc..."
    if grep -q "alias nginx=" /root/.bashrc; then
      echo "The aliases already exist, no need to add them again."
    else
      echo 'alias nginx="docker exec -i docker_nginx nginx"' >>/root/.bashrc
      echo 'alias dc="docker-compose"' >>/root/.bashrc
      echo 'alias dcs="docker-compose ps -q | xargs docker stats"' >>/root/.bashrc
      echo 'alias dcps="docker ps $((docker-compose ps -q  || echo "#") | while read line; do echo "--filter id=$line"; done)"' >>/root/.bashrc
      echo 'alias dcip="bash /root/docker_tools/dcip.sh"' >>/root/.bashrc
      echo 'alias dlogs="bash /root/docker_tools/dlogs.sh"' >>/root/.bashrc
    fi

    echo "The Docker toolbox has been installed successfully."
    ;;
  n | N)
    echo "Docker toolbox installation cancelled."
    ;;
  *)
    echo "Invalid option. Cancelling the Docker toolbox installation."
    ;;
  esac
}

remove_all_swap() {
  swap_files=$(swapon -s | awk '{if($1!~"^Filename"){print $1}}')
  swap_partitions=$(grep -E '^\S+\s+\S+\sswap\s+' /proc/swaps | awk '{print $1}')

  for item in $swap_files $swap_partitions; do
    echo "Disabling and removing swap: $item"
    if swapoff "$item"; then
      rm -f "$item"
      echo "Swap removed: $item"
    else
      echo "Failed to disable swap: $item"
    fi
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
  used_memory_percent=$(((used_memory) * 100 / total_memory))
  total_used_percent=$(((used_memory + used_swap) * 100 / total_memory))

  if [ -n "$swap_files" ]; then
    echo "Current swap space size:"
    swapon --show
    echo "=========================================="
    echo "Physical memory usage: ${used_memory_percent}% ( ${used_memory} MB / ${total_memory} MB )"
    echo "Percentage of physical memory occupied by used physical and virtual memory: ${total_used_percent}% ( $((used_memory + used_swap)) MB / ${total_memory} MB )"

    if [ $total_used_percent -gt 80 ]; then
      echo "Clearing the swap cache is not recommended when the total of physical memory usage and swap usage exceeds 80% of physical memory."
      echo "This may lead to insufficient system memory, impacting performance and stability."
    else
      read -p "Do you want to clear the swap cache? (y/n) " cleanup_choice

      case $cleanup_choice in
      y | Y)
        for item in $swap_files $swap_partitions; do
          echo "Cleaning swap cache: $item"
          swapoff "$item"
          echo "Swap cache cleaned: $item"
          swapon "$item"
        done

        echo "All swap caches have been cleaned."
        ;;
      n | N)
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
  echo "Checking existing swap files..."
  swap_files=$(swapon -s | awk '{if($1!~"^Filename"){print $1}}')
  if [ -n "$swap_files" ]; then
    echo "Existing swap file(s):"
    swapon --show
    read -p "Do you want to remove existing swap? (y/n) " remove_choice
    case $remove_choice in
    y | Y)
      remove_all_swap
      ;;
    n | N)
      echo "Keeping existing swap."
      ;;
    *)
      echo "Invalid choice. Keeping existing swap."
      ;;
    esac
  fi
  echo "Select a pre-defined virtual memory size or enter a custom value:"
  echo "1. 256M"
  echo "2. 512M"
  echo "3. 1G"
  echo "4. 2G"
  echo "5. 4G"
  echo "6. Enter size manually"
  read -p "Enter choice (q to quit): " choice
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
  q | Q)
    echo "Exiting..."
    return 1
    ;;
  *)
    echo "Invalid choice."
    return 1
    ;;
  esac
  echo "Creating swap file..."
  if [ -n "$swap_files" ]; then
    echo "Existing swap files found. Removing existing swap..."
    remove_all_swap
  fi
  case $swap_size in
  *M)
    swap_size_kb=$((${swap_size//[^0-9]/} * 1024))
    ;;
  *G)
    swap_size_kb=$((${swap_size//[^0-9]/} * 1024 * 1024))
    ;;
  *)
    echo "Invalid size unit. Please use M or G for Megabytes or Gigabytes."
    return 1
    ;;
  esac
  dd if=/dev/zero of=/swap bs=1k count=$swap_size_kb
  if [ $? -eq 0 ]; then
    chmod 600 /swap
    mkswap /swap
    swapon /swap
    if [ $? -eq 0 ]; then
      echo "/swap swap swap defaults 0 0" >>/etc/fstab
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
  # Show current swap usage threshold
  echo "Current swap usage threshold is: $(cat /proc/sys/vm/swappiness)"

  # Set new swap usage threshold
  echo "Setting new swap usage threshold..."
  read -p "Enter a new swap usage threshold (0-100): " swap_value

  # Input validation
  if ! [[ "$swap_value" =~ ^[0-9]+$ ]] || [ "$swap_value" -lt 0 ] || [ "$swap_value" -gt 100 ]; then
    echo "Invalid input. Please enter a number between 0 and 100."
    return 1
  fi

  # Modify /etc/sysctl.conf
  cp /etc/sysctl.conf /etc/sysctl.conf.bak
  if grep -q "^vm.swappiness" /etc/sysctl.conf; then
    sed -i "s/^vm.swappiness=.*/vm.swappiness=$swap_value/" /etc/sysctl.conf
  else
    echo "vm.swappiness=$swap_value" >>/etc/sysctl.conf
  fi

  # Apply changes and verify
  sysctl -p
  if grep -q "^vm.swappiness=$swap_value" /etc/sysctl.conf; then
    echo "Swap usage threshold set to $swap_value successfully."
  else
    echo "Failed to set swap usage threshold. Please check configuration file."
    mv /etc/sysctl.conf.bak /etc/sysctl.conf
    return 1
  fi
}

optimize_kernel_parameters() {
  read -p "Confirm kernel optimization to improve network performance? (y/n): " optimize_choice

  case $optimize_choice in
  y | Y)
    echo "Creating backup of kernel settings..."
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    echo "Improving network performance..."

    # Disable TCP Fast Open (may not be beneficial for all workloads)
    if grep -q "^net.ipv4.tcp_fastopen=3" /etc/sysctl.conf; then
      sed -i 's/^net.ipv4.tcp_fastopen=3/#net.ipv4.tcp_fastopen=3/' /etc/sysctl.conf
    fi

    # Improve TCP slow start after idle (reduce connection latency)
    if ! grep -q "^net.ipv4.tcp_slow_start_after_idle" /etc/sysctl.conf; then
      echo "net.ipv4.tcp_slow_start_after_idle=0" >>/etc/sysctl.conf
    else
      sed -i 's/^net.ipv4.tcp_slow_start_after_idle=.*/net.ipv4.tcp_slow_start_after_idle=0/' /etc/sysctl.conf
    fi

    # Increase TCP receive and write buffers
    ! grep -q "^net.core.rmem_max=" /etc/sysctl.conf && echo "net.core.rmem_max=16777216" >> /etc/sysctl.conf
    ! grep -q "^net.core.wmem_max=" /etc/sysctl.conf && echo "net.core.wmem_max=16777216" >> /etc/sysctl.conf
    grep -q "^net.core.rmem_max=" /etc/sysctl.conf && sed -i 's/^net.core.rmem_max=.*$/net.core.rmem_max=16777216/' /etc/sysctl.conf
    grep -q "^net.core.wmem_max=" /etc/sysctl.conf && sed -i 's/^net.core.wmem_max=.*$/net.core.wmem_max=16777216/' /etc/sysctl.conf

    # Increase TCP buffer for unsent data (improve performance for large transfers)
    if ! grep -q "^net.ipv4.tcp_notsent_lowat" /etc/sysctl.conf; then
      echo "net.ipv4.tcp_notsent_lowat=16384" >>/etc/sysctl.conf
    else
      sed -i 's/^net.ipv4.tcp_notsent_lowat=.*/net.ipv4.tcp_notsent_lowat=16384/' /etc/sysctl.conf
    fi

    # Set queuing discipline (improve traffic management)
    if ! grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf; then
      echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    fi

    # Set TCP congestion control algorithm (improve bulk transfers)
    if ! grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
      echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
    fi

    sysctl -p
    if grep -q "^net.ipv4.tcp_slow_start_after_idle=0" /etc/sysctl.conf &&
      grep -q "^net.ipv4.tcp_notsent_lowat=16384" /etc/sysctl.conf &&
      grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf &&
      grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf &&
      grep -q "^net.core.rmem_max=16777216" /etc/sysctl.conf &&
      grep -q "^net.core.wmem_max=16777216" /etc/sysctl.conf; then
      echo "Network performance optimized successfully."
    else
      echo "Failed to optimize network performance. Please check configuration file."
      mv /etc/sysctl.conf.bak /etc/sysctl.conf
      return 1
    fi
    ;;
  n | N)
    echo "Kernel parameter optimization canceled."
    ;;
  *)
    echo "Invalid option."
    return 1
    ;;
  esac
}

install_xanmod_kernel() {
  # Check current kernel version
  echo "Currently running kernel version: $(uname -r)"

  # Check CPU compatibility with XanMod kernel
  cpu_support_info=$(/usr/bin/awk -f <(wget -qO - https://raw.githubusercontent.com/oXIIIo/vps-setup/main/check_x86-64_psabi.sh))
  if [[ $cpu_support_info == "CPU supports x86-64-v"* ]]; then
    cpu_support_level=${cpu_support_info#CPU supports x86-64-v}
    echo "Your CPU supports XanMod kernel x86-64-v$cpu_support_level"
  else
    echo "Your CPU is not supported by XanMod kernel, installation failed."
    return 1
  fi

  # User confirmation before download and install
  read -p "Continue to download and install XanMod kernel? (y/n): " continue_choice
  case $continue_choice in
  y | Y)
    echo "Downloading and installing XanMod kernel..."
    echo "XanMod website https://xanmod.org"
    echo "Kernel download source https://sourceforge.net/projects/xanmod/files/releases/lts/"
    curl -fSsL https://dl.xanmod.org/archive.key | gpg --dearmor | sudo tee /usr/share/keyrings/xanmod-archive-keyring.gpg >/dev/null
    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list
    sudo apt-get update
    sudo apt-get install linux-xanmod-x64v${cpu_support_info#CPU supports x86-64-v} -y
    if [ $? -eq 0 ]; then
      echo "XanMod kernel installed successfully."
      read -p "Do you want to update the grub configuration to use the new kernel (y/n)? " update_grub_choice
      case $update_grub_choice in
      y | Y)
        update-grub
        echo "Grub updated. Reboot to use the new kernel."
        echo "For BBRv3 network optimization, run 'kernel optimization options' after reboot."
        ;;
      n | N)
        echo "Continue with the current Grub configuration."
        ;;
      *)
        echo "Invalid choice. Skipping Grub update."
        ;;
      esac
    else
      echo "XanMod kernel installation failed."
    fi
    ;;
  n | N)
    echo "XanMod kernel installation cancelled."
    ;;
  *)
    echo "Invalid choice. XanMod kernel installation cancelled."
    ;;
  esac
}

uninstall_xanmod_kernel() {
  current_kernel_version=$(uname -r)
  echo "Current kernel: $current_kernel_version"

  if [[ $current_kernel_version =~ xanmod ]]; then
    echo "The current kernel is a XanMod kernel."
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
    echo "Current SSH port is not set (commented out)."
  else
    echo "Current SSH port: $current_port."
  fi
  read -p "Enter new SSH port number: " new_port
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
  echo "SSH port number changed to: $new_port"

  # Open port in firewall (if detected)
  firewall=$(check_firewall)
  case $firewall in
  "ufw")
    ufw allow $new_port/tcp
    echo "Opened SSH port in ufw"
    ;;
  "firewalld")
    firewall-cmd --add-port=$new_port/tcp --permanent
    firewall-cmd --reload
    echo "Opened SSH port in firewalld"
    ;;
  "iptables")
    iptables -A INPUT -p tcp --dport $new_port -j ACCEPT
    service iptables save
    service iptables restart
    echo "Opened SSH port in iptables"
    ;;
  "nftables")
    nft add rule ip filter input tcp dport $new_port accept
    echo "Opened SSH port in nftables"
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
    read -p "Enter new firewall ports to open, separated by commas, e.g. 80t,443t,53u (t for TCP, u for UDP): " new_ports_input
    IFS=',' read -ra new_ports <<<"$new_ports_input"
    for port_input in "${new_ports[@]}"; do
      if [[ ! "$port_input" =~ ^[0-9]+[tu]$ ]]; then
        echo "Invalid input, please follow the format: port number and protocol abbreviation (e.g. 80t or 443u)."
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
    read -p "Enter firewall ports to close, separated by commas, e.g. 80t,53u (t for TCP, u for UDP): " ports_to_close_input
    IFS=',' read -ra ports_to_close <<<"$ports_to_close_input"
    for port_input in "${ports_to_close[@]}"; do
      if [[ ! "$port_input" =~ ^[0-9]+[tu]$ ]]; then
        echo "Invalid input, please follow the format: port number and protocol abbreviation (e.g. 80t or 443u)."
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
  q | Q)
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

  echo -e "${BOLD}Welcome to the oXIIIo Linux configuration tool.${RESET}"
  echo -e "${BOLD}GitHub: https://github.com/oXIIIo/vps-setup${RESET}"
  echo -e "${BOLD}-----------------------------------"
  echo -e "Current Linux distribution version: ${GREEN}${BOLD}${linux_version}${RESET}"
  echo -e "Current kernel version: ${GREEN}${BOLD}${kernel_version}${RESET}"
  echo -e "Current memory usage: ${GREEN}${BOLD}${memory_usage}%${RESET}"
  echo -e "${BOLD}-----------------------------------"
  echo -e "Please select an option: \n"
  echo -e "${BOLD}Option${RESET}   ${BOLD}Description${RESET}"
  echo "-----------------------------------"
  echo -e "${GREEN}  1${RESET}      Install necessary components"
  echo -e "${GREEN}  2${RESET}      Add public key for device registration"
  echo -e "${GREEN}  3${RESET}      Disable SSH password login"
  echo -e "${GREEN}  4${RESET}      Change SSH port number"
  echo -e "${GREEN}  5${RESET}      Add Docker tool script"
  echo -e "${GREEN}  6${RESET}      Set Swap size"
  echo -e "${GREEN}  7${RESET}      Modify Swap usage threshold"
  echo -e "${GREEN}  8${RESET}      Clear Swap cache"
  echo -e "${GREEN}  9${RESET}      Optimize kernel parameters"

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
  q | Q) return 1 ;;
  *) echo "Invalid option, please enter a valid option number:" ;;
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
  echo "Glad you're using the script!"
  sleep 0.5s
}

cleanup() {
  rm -f menu_choice.txt
  echo "Exiting the script. We hope it was helpful!"
  sleep 1s
  tput reset
}

main "$@"
