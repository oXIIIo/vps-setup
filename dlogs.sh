#!/bin/bash

# Get a list of running container names
containers=$(docker ps --format '{{.Names}}')

# Check if there are any containers running
if [ -z "$containers" ]; then
  echo "No running Docker containers found."
  exit 1
fi

# Display container selection menu
PS3="Select a container to view its logs or 'q' to quit: "
select container in $containers q; do
  case $container in
  q)
    echo "Exiting..."
    break
    ;;
  *)
    if [ -n "$container" ]; then
      # User selected a container
      echo "Following the last 10 lines of logs for $container..."
      docker logs -f -n 10 "$container"
    else
      echo "Invalid selection. Please choose a valid option."
    fi
    ;;
  esac
done
