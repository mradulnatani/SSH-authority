#!/bin/bash

# Auto-generated script to create users from roles file
ROLES_FILE="/tmp/user_roles.txt"

while IFS="" read -r user || [ -n "$user" ]; do
    if [ -z "$user" ]; then
        continue
    fi

    if id "$user" &>/dev/null; then
        echo "User $user already exists"
    else
        echo "Creating user: $user"
        sudo useradd "$user"
    fi
done < "$ROLES_FILE"

