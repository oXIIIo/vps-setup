# Automated Linux Server Configuration Script

## Introduction

This script automates various setup and configuration tasks for Linux systems, including installing essential components, managing SSH settings, configuring virtual memory, optimizing kernel parameters, and installing or uninstalling the XanMod kernel.

## Features

### 1. Install Necessary Components

Installs Docker, Docker Compose, Fail2Ban, Vim, and Curl.

### 2. Add Public Key for Registered Device

Adds an SSH public key to the authorized keys file for secure remote access.

### 3. Disable SSH Password Login

Enhances security by disabling SSH password authentication and enforcing key-based authentication.

### 4. Modify SSH Port Number

Allows changing the default SSH port for added security.

### 5. Add Docker Tool Scripts

Adds handy aliases for Docker, Docker Compose, and other common commands to the Bash environment.

### 6. Set Virtual Memory

Configures the system's virtual memory (swap space) with predefined or custom sizes.

### 7. Modify Swap Usage Threshold

Adjusts the `vm.swappiness` value to control swap usage behavior.

### 8. Clear Swap Cache

Clears the swap cache, setting the swap usage to zero (with a usage check).

### 9. Optimize Kernel Parameters

Modifies kernel parameters in `/etc/sysctl.conf` for improved performance, including TCP settings and queue discipline.

### 10. Download and Install XanMod Kernel

Downloads and installs the XanMod kernel and optionally updating the GRUB boot configuration.

### 11. Uninstall XanMod Kernel and Restore Original Kernel

Removes the XanMod kernel and restores the original kernel.

### 12. Set Firewall Ports

Allows setting firewall ports, which may be required by some VPS providers.

## Usage

1. Access the Linux system via terminal.
2. Run the script using one of the following methods:
   ```bash
   /bin/bash <(wget -qO - https://raw.githubusercontent.com/oXIIIo/vps-setup/main/server-setup.sh)
   ```

   Alternatively, clone the repository and run the script:

   ```bash
   git clone https://github.com/oXIIIo/vps-setup.git
   cd vps-setup
   chmod +x server-setup.sh
   ./server-setup.sh
   ```

3. Follow the menu prompts to select and execute the desired operations.

## Notes

- Ensure you have administrative privileges before running the script (use `sudo` if needed).
- The script may modify system configurations. Use it with caution and understanding.
- Check the terminal output for any issues or additional information during execution.
- Submit issues or feedback in the project repository if you encounter problems or have suggestions.

## Compatibility

- Supported on Debian 10, 11, and 12
- Ubuntu users, please self-test as compatibility is expected but not guaranteed
- For CentOS, Fedora, and Arch Linux, compatibility has been implemented but not extensively tested. Users are advised to self-test before use. Please note that XanMod kernel is not supported.

## Credits

This script is based on the original work by [SuperNG6](https://github.com/SuperNG6/linux-setup.sh).

# Buy me a coffee ☕
If you find this project helpful, you can buy me a coffee using the donation button below:

<a href="https://nowpayments.io/donation?api_key=MG750CX-D7AMMH9-QWARQ7V-9ZKH9XQ&source=lk_donation&medium=referral" target="_blank">
  <img src="https://nowpayments.io/images/embeds/donation-button-black.svg" alt="Crypto donation button by NOWPayments">
</a>
