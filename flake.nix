{
  description = "Bitwarden secret broker for AI agents";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.default = pkgs.buildGoModule {
        pname = "vaultbroker";
        version = "0.2.0";
        src = self;
        vendorHash = null;
        subPackages = [ "cmd/vaultbroker" ];
        env.CGO_ENABLED = 0;
      };
    };
}
