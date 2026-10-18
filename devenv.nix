{ pkgs, ... }:
{
  packages = [
    pkgs.git
    pkgs.bitwarden-cli
  ];

  languages.go.enable = true;

  scripts = {
    build.exec = "CGO_ENABLED=0 go build -mod=vendor -trimpath -o vaultbroker ./cmd/vaultbroker";
    check.exec = ''
      go vet -mod=vendor ./...
      go build -mod=vendor ./...
      python3 -m py_compile mcp/vault_mcp.py
    '';
  };
}
