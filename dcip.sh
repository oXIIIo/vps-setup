#!/bin/bash

# Check if the script is being executed as root user
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root user"
  exit
fi

# Check if Docker is running
if ! systemctl is-active --quiet docker; then
  echo "Docker service is not running, please start Docker"
  exit
fi

# Define the path to the hosts file
HOSTS_FILE="/etc/hosts"

# Define comment start and end markers
COMMENT_START="# BEGIN Docker container IPs"
COMMENT_END="# END Docker container IPs"

# Create a temporary file using mktemp and check for success
TMP_FILE=$(mktemp)
if [ ! -f "$TMP_FILE" ]; then
  echo "Failed to create temporary file"
  exit
fi

echo "Fetching IP addresses of Docker containers..."

# Iterate over all Docker containers
docker ps -q | while read -r id; do
  # Get container name
  container_name=$(docker inspect -f '{{ .Name }}' "$id" | sed 's/^\///')

  # Get IP addresses of all network interfaces of the container
  container_ips=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$id")

  for ip in $container_ips; do
    # Check if container name and IP address are not empty
    if [[ -n "$container_name" ]] && [[ -n "$ip" ]]; then
      echo "Adding $ip for $container_name"
      # Add container IP address and name to the temporary file
      echo -e "$ip\t$container_name" >>"$TMP_FILE"
    fi
  done
done

# Check if the temporary file is not empty
if [[ -s "$TMP_FILE" ]]; then
  echo "Updating $HOSTS_FILE"
  # Remove existing Docker container IP address information and add new information to the hosts file
  sed -i "/$COMMENT_START/,/$COMMENT_END/d" "$HOSTS_FILE"
  echo -e "\n$COMMENT_START\n$(cat $TMP_FILE)\n$COMMENT_END\n" >>"$HOSTS_FILE"
  echo "Update complete"
else
  echo "No Docker containers found"
fi

# Remove temporary file
rm "$TMP_FILE"
