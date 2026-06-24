enclave "default" {
  build {
    app_sources = ["https://codeberg.org/caution/demo-ai-inference.git"]
    cache = false
  }
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 80
      ip_protocol = "tcp"
    }
    http {
      domain = "chat.caution.dev"
      port = 80
      e2e_encryption {
        enabled = true
      }
    }
  }
  resources {
    cpu = 14
    memory_mb = 55000
  }
  unit "default" {
    command = "/usr/bin/llama-server"
    args = ["--host", "0.0.0.0", "--port", "8083", "-m", "/workdir/models/model.gguf", "--path", "/workdir/public", "--ctx-size", "2048", "-t", "8"]
  }
}
