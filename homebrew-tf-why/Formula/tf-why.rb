class TfWhy < Formula
  desc "Explain Terraform plan changes in human language with risk scoring"
  homepage "https://github.com/djeeteg007/tf-why"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/djeeteg007/tf-why/releases/download/v#{version}/tf-why_#{version}_darwin_arm64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    end
    on_intel do
      url "https://github.com/djeeteg007/tf-why/releases/download/v#{version}/tf-why_#{version}_darwin_amd64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/djeeteg007/tf-why/releases/download/v#{version}/tf-why_#{version}_linux_arm64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    end
    on_intel do
      url "https://github.com/djeeteg007/tf-why/releases/download/v#{version}/tf-why_#{version}_linux_amd64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
    end
  end

  def install
    bin.install "tf-why"
  end

  test do
    # Verify the binary runs
    assert_match "tf-why", shell_output("#{bin}/tf-why --version")
  end
end

# ──────────────────────────────────────────────────
# HOW TO UPDATE THIS FORMULA AFTER A RELEASE
# ──────────────────────────────────────────────────
#
# 1. Create a GitHub release (e.g., v0.2.0):
#      git tag v0.2.0 && git push origin v0.2.0
#      goreleaser release --clean
#
# 2. Download the checksums.txt from the release assets.
#
# 3. Replace the version string above.
#
# 4. Replace each PLACEHOLDER_SHA256_* with the corresponding
#    SHA256 from checksums.txt. For example:
#      sha256sum tf-why_0.2.0_darwin_arm64.tar.gz
#
# 5. Commit and push the formula to the homebrew-tf-why tap repo.
#
# Users install with:
#   brew tap djeeteg007/tf-why https://github.com/djeeteg007/homebrew-tf-why
#   brew install tf-why
# ──────────────────────────────────────────────────
