# acme-dns-aliyun

A dead simple **cert-manager ACME DNS01 solver webhook** for **Alibaba Cloud
(Aliyun) DNS**, written in [Zig 0.16](https://ziglang.org/).

No frameworks, no SDKs, no dependencies except OpenSSL for TLS, no bullshit.

---

## Deploying on Kubernetes

### Generate manifests

Run the interactive manifest generator:

```bash
zig build manifest
```

It will prompt for:
- Webhook group name and solver name
- Container image tag
- Let's Encrypt account email
- Credential mode: **AccessKey** (static key/secret) or **RRSA** (RAM Roles for Service Accounts — recommended for ACK clusters)
- Mode-specific credentials

Generated files land in `zig-out/manifests/`:
- `webhook-accesskey.yaml` or `webhook-rrsa.yaml` — Namespace, ServiceAccount, Deployment, Service, TLS cert
- `apiservice.yaml` — APIService + RBAC
- `clusterissuer.yaml` — example ClusterIssuer

**For RRSA:** see the [Terraform example](./example/rrsa-role.tf) for creating the necessary RAM Role and OIDC trust relationship.
