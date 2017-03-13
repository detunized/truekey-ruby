require "yaml"
require "httparty"

#
# main
#

config = ap YAML::load_file "config.yaml"
