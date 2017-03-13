require "yaml"
require "httparty"

class Http
    include HTTParty

    def get url, headers = {}
        self.class.get url, {
            headers: headers
        }
    end

    def post url, args, headers = {}
        self.class.post url, {
            body: args,
            headers: headers
        }
    end
end

#
# main
#

config = ap YAML::load_file "config.yaml"
