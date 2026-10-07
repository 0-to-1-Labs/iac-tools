# Hardened Three-Tier Web Application (threat-model fixture)

A hardened copy of `tf-01-three-tier-webapp`. Same shape (ALB -> Auto Scaling
group -> RDS MySQL), with every internet-to-data path closed:

- The ALB is `internal = true`, sits in the private subnets, and its security
  group accepts 80/443 only from the VPC CIDR. Nothing accepts `0.0.0.0/0`.
- HTTP redirects to HTTPS; the HTTPS listener is unconditional. Access logs go
  to a private, encrypted, versioned S3 bucket.
- Public subnets do not assign public IPs. Only the NAT gateways live there.
- The launch template requires IMDSv2.
- RDS storage is encrypted with a rotating customer managed key, has deletion
  protection, IAM authentication, and log exports.
- The instance role's wildcard-resource statement is conditioned to one
  CloudWatch namespace.

Expected threat-model result: **zero** internet-to-data attack paths. The stack
still carries lower-severity threats (for example a log group retention under a
year), which is the point: no paths is not the same as no threats.

`certificate_arn` must be set for `terraform validate` to be meaningful; the
fixture is parsed, not applied.
