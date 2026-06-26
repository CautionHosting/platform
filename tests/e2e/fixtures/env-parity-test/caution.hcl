enclave "main" {
  build {
    containerfile = "Containerfile"
  }
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
  unit "main" {
    command = "/usr/local/bin/env-parity-test"
    env {
      TEST_ENV_FOO = "bar"
      TEST_ENV_HELLO = "$(world)"
      TEST_ENV_PARITY = "`\"ch\\eck\"`"
    }
  }
}
