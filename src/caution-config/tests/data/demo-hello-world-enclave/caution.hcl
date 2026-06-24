enclave "default" {
  build {
    binary = "/usr/local/bin/hello"
    app_sources = ["git@codeberg.org:caution/demo-hello-world-enclave.git"]
  }
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8083
      ip_protocol = "tcp"
    }
  }
  unit "default" {
    command = "/usr/local/bin/hello"
  }
}
