class WifiJammer < Formula
  include Language::Python::Virtualenv

  desc "Advanced WiFi security testing tool with 10 attack types, CLI/TUI/GUI"
  homepage "https://github.com/oyi77/wifi-jammer"
  url "https://files.pythonhosted.org/packages/source/w/wifi-jammer/wifi_jammer-2.0.0.tar.gz"
  sha256 "f9ace5cf81777302c8f60ca881bd377166837b9dd42044c613beef61080feea4"
  license "MIT"

  depends_on "python@3.12"
  depends_on "wireless-tools"
  depends_on "aircrack-ng"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/wifi-jammer --version")
  end
end
