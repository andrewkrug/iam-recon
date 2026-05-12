class IamRecon < Formula
  desc "AWS IAM privilege escalation and attack path mapper"
  homepage "https://github.com/andrewkrug/iam-recon"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/andrewkrug/iam-recon/releases/download/v0.1.0-ac0e1d1/iam-recon-macos-aarch64"
      sha256 "a9814a5e822ebf5208688c48480fe271a0835c53ce64337f42429ac40ff390dd"
    else
      url "https://github.com/andrewkrug/iam-recon/releases/download/v0.1.0-ac0e1d1/iam-recon-macos-x86_64"
      sha256 "95077b56304161cbf004512ff1c9cfb35b0f8b6cfb8357d97871c54ce163f91c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/andrewkrug/iam-recon/releases/download/v0.1.0-ac0e1d1/iam-recon-linux-aarch64"
      sha256 "b0cafaec57f81ce1970984dfc115a9256b5c964f5594d25145265e594aec5ebf"
    else
      url "https://github.com/andrewkrug/iam-recon/releases/download/v0.1.0-ac0e1d1/iam-recon-linux-x86_64"
      sha256 "f6b91091ad058d6434e8ae69366dbeb455a25f83165034aa1a5997979ef0e53d"
    end
  end

  def install
    bin.install Dir["*"].first => "iam-recon"
  end

  test do
    system "#{bin}/iam-recon", "--version"
  end
end
