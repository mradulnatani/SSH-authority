sudo confd \
  -backend consul \
  -node http://consul_lb:8500 \
  -confdir /etc/confd \
  -log-level debug


