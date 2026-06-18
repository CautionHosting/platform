caution {
  managed_credentials = "credentials.pgp"
  machine_type = "c5.xlarge"
  build_machine_type = "c5.xlarge"
}

enclave "main" {
  build {
    containerfile = "Containerfile.example"
    binary = "static-binary"
    app_sources = [
      "git@codeberg.org:caution/demo-hello-world-enclave",
      "https://codeberg.org/caution/demo-hello-world-enclave",
    ]
    cache = false
  }

  debug {
    enabled = true
    ssh_keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGiqWyt0v5RpZqVK9EUeTWdCBGQo6+GN6jbUe0mPSEfV ryan@left"
    ]
  }

  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      start_port = 40000
      end_port = 40005
      ip_protocol = "tcp"
    }
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }
    egress {
      cidr_ipv4 = "0.0.0.0/0"
    }

    http {
      domain = "chat.caution.dev"
      port = "8000"
      e2e_encryption {
        enabled = true
        cors_origins = ["*"]
      }
    }
  }

  resources {
    cpu = 2
    memory_mb = 2000
  }

  unit "main" {
    command = "/usr/bin/hello"
    args = ["hello", "world"]
    env {
      FOO = "bar"
      HELLO = "world"
    }
  }
}
