MERAKI_API_KEY = "API KEY"
ORG_NAME = "ORG NAME"
NETWORK_NAME = "NETWORK NAME"

# Insert comma separated lists of acl names, where 'nat_set' are the acls which require nat translation (outside ->
# in), and outbound set is a normal MX outbound list (inside -> inside, or inside -> outside)
ACL_TYPES = {
  "nat_set": ["nat acl 1", "nat acl 2"],
  "outbound_set": ["outbound acl 1", "outbound acl 2"]
}
