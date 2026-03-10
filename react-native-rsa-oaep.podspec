require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-rsa-oaep"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = package["description"]
  s.license      = "MIT"
  s.homepage     = package["homepage"]
  s.authors      = package["author"] || "Author"
  s.source       = { :git => package["repository"]["url"], :tag => "v#{s.version}" }
  s.platforms    = { :ios => "11.0" }
  s.source_files = "ios/**/*.{h,m,mm,swift}"
  s.requires_arc = true
  s.swift_version = "5.0"

  s.dependency "React-Core"
end
