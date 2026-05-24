resource "alicloud_ram_role" "cert_manager_dns_solver" {
  role_name   = "cert-manager-dns-solver"
  description = "Role for cert-manager to solve DNS challenges"
  assume_role_policy_document = jsonencode({
    Version = "1"
    Statement = [
      {
        Effect = "Allow"
        Condition = {
          StringEquals = {
            "oidc:aud" = "sts.aliyuncs.com",
            "oidc:sub" = "system:serviceaccount:acme-dns-aliyun:acme-dns-aliyun",
            "oidc:iss" = alicloud_cs_managed_kubernetes.default.rrsa_metadata.rrsa_oidc_issuer_url
          }
        }
        Principal = {
          Federated = [
            alicloud_cs_managed_kubernetes.default.rrsa_metadata.ram_oidc_provider_arn
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "alicloud_ram_policy" "cert_manager_dns_solver" {
  policy_name = "cert-manager-dns-solver"

  policy_document = jsonencode({
    Version = "1"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "alidns:DescribeDomainRecords",
          "alidns:AddDomainRecord",
          "alidns:DeleteDomainRecord"
        ]
        Resource = "*"
      }
    ]
  })
  description = "Policy for cert-manager to manage DNS records in Alibaba Cloud DNS"
}

resource "alicloud_ram_role_policy_attachment" "cert_manager_dns_solver_attachment" {
  policy_name = alicloud_ram_policy.cert_manager_dns_solver.policy_name
  policy_type = "Custom"
  role_name   = alicloud_ram_role.cert_manager_dns_solver.role_name
}
