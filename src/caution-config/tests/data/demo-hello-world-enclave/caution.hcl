enclave "default" {
  build {
    app_sources = ["git@git.caution.co:public/demo-hello-world-enclave.git"]
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
