ui = true
disable_mlock = true
api_addr = "http://openbao:8200"

storage "file" {
  path = "/openbao/data"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_disable     = true
  cluster_address = "0.0.0.0:8201"
}
