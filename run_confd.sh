sudo confd \
  -backend consul \
  -node http://localhost:18500 \
  -confdir ./confd \
  -log-level debug


cp ../user_roles.txt ./user_roles.txt

# Run confd to generate the script
sudo confd -backend env \
      -confdir ./confd

