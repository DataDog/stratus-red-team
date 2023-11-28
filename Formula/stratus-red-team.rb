# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class StratusRedTeam < Formula
  desc ""
  homepage "https://stratus-red-team.cloud"
  version "2.11.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/DataDog/stratus-red-team/releases/download/v2.11.2/stratus-red-team_Darwin_arm64.tar.gz"
      sha256 "654a3c1fe18891e7050703a024d6ee717ec95b518ffc4b4a7683e0f4fe4c413a"

      def install
        bin.install "stratus"

        # Install shell completions
        generate_completions_from_executable(bin/"stratus", "completion", shells: [:bash, :fish, :zsh], base_name: "stratus")
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DataDog/stratus-red-team/releases/download/v2.11.2/stratus-red-team_Darwin_x86_64.tar.gz"
      sha256 "6c01c0c2d26ea8a46d894c49d1c4d33a9af192277518bb35bd0ea56aae3ecaf2"

      def install
        bin.install "stratus"

        # Install shell completions
        generate_completions_from_executable(bin/"stratus", "completion", shells: [:bash, :fish, :zsh], base_name: "stratus")
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DataDog/stratus-red-team/releases/download/v2.11.2/stratus-red-team_Linux_arm64.tar.gz"
      sha256 "cbf9357538fee3913015a9b4999c36169e7b2f8c417379fcb4f79c87e5a0d7d9"

      def install
        bin.install "stratus"

        # Install shell completions
        generate_completions_from_executable(bin/"stratus", "completion", shells: [:bash, :fish, :zsh], base_name: "stratus")
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DataDog/stratus-red-team/releases/download/v2.11.2/stratus-red-team_Linux_x86_64.tar.gz"
      sha256 "d85c7ac5e2bfaf59863b57ba143ceb8a6ccf7a6eb1551e7825841e95e1eb3738"

      def install
        bin.install "stratus"

        # Install shell completions
        generate_completions_from_executable(bin/"stratus", "completion", shells: [:bash, :fish, :zsh], base_name: "stratus")
      end
    end
  end
end
