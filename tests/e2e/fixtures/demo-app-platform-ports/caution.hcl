enclave "default" {
  build {
    app_sources = ["git@codeberg.org:caution/demo-hello-world-enclave.git"]
  }
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8083
      ip_protocol = "tcp"
    }
    http {
      domain = "app.example.com"
      port = 8083
      e2e_encryption {
        enabled = true
        key_exchange = "xwing-draft10"
        cors_origins = ["http://127.0.0.1:3000", "http://localhost:3000"]
      }
    }
  }
  unit "default" {
    command = "/usr/local/bin/hello"
  }
}
