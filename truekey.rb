#!/usr/bin/env ruby

require "json"
require "yaml"
require "httparty"

FORCE_ONLINE = false

class Http
    include HTTParty

    def get url, headers = {}, mock_response = nil
        return make_response mock_response if should_return_mock? mock_response

        self.class.get url, {
            headers: headers
        }
    end

    def post url, args, headers = {}, mock_response = nil
        return make_response mock_response if should_return_mock? mock_response

        self.class.post url, {
            body: args,
            headers: headers
        }
    end

    def post_json url, args, headers = {}, mock_response = nil
        post url,
             args.to_json,
             headers.merge({"Content-Type" => "application/json"}),
             mock_response
    end

    def should_return_mock? mock_response
        mock_response && !FORCE_ONLINE
    end

    def make_response mock_response
        @response_class ||= Struct.new :parsed_response
        @response_class.new mock_response
    end
end

# This is the first step in authentication process for a new device.
# This requests the client token with is used in OCRA (RFC 6287) exchange
# later on. There's also a server assigned id for the new device.
#
# `device_name` is the name of the device registered with the True Key service.
# For example 'Chrome' or 'Nexus 5'.
def register_new_device device_name, http
    mock_response = {
         "responseResult" => {
                   "isSuccess" => true,
                   "errorCode" => "",
            "errorDescription" => nil,
               "transactionId" => "e36c90af-9f73-4354-af78-902dfa80bd87"
        },
            "clientToken" => "AQCmAwEAAh4AAAAAWMajHQAAGU9DUkEtMTpIT1RQLVNIQ" +
                             "TI1Ni0wOlFBMDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIOiR" +
                             "fItpCTOkvq0ZfV2+GgvP83aF9SrTBfOuabZfcQr9AAAAA" +
                             "AgAIBwWTZpUTIn493Us/JwczrK6O0+LH8FRidFaZkJ2Al" +
                             "Tu",
             "tkDeviceId" => "d871347bd0a3e7af61f60f511bc7de5e944c5c7787056" +
                             "49d4aa8dc77bcd21489412894",
          "tkDeviceNonce" => "1489412894",
        "tkReEnrollToken" => "bd23b315af167d81ea216a1c26a1a836657583e84fece" +
                             "a2fb3281920a33aec84"
    }

    response = http.post_json "https://truekeyapi.intelsecurity.com/sp/pabe/v2/so", {
              clientUDID: "truekey-ruby", # The official client generates random client
                                          # UDID every time. It doesn't seem to be needed,
                                          # so it's just hardcoded here.
              deviceName: device_name,
        devicePlatformID: 7,              # MacOS (see DevicePlatformType)
              deviceType: 5,              # Mac (see DeviceType)
                  oSName: "Unknown",
           oathTokenType: 1
    }, {}, mock_response

    parsed = response.parsed_response
    raise "Request failed" if !parsed["responseResult"]["isSuccess"]

    result = {
        token: parsed["clientToken"],
        name: device_name,
        id: parsed["tkDeviceId"]
    }
    raise "Invalid response" if result.values.include? nil

    result
end

# Returns OAuth transaction id that is used in the next step
def auth_step1 username, device_info, http
    mock_response = {
        "oAuthTransId"    => "6cdfcd43-065c-43a1-aa7a-017de98eefd0",
        "responseResult"  => {
                   "isSuccess" => true,
                   "errorCode" => nil,
            "errorDescription" => nil,
               "transactionId" => nil
        },
        "riskAnalysisInfo" => nil
    }

    response = http.post_json "https://truekeyapi.intelsecurity.com/session/auth", {
        data: {
            contextData: {
                deviceInfo: {
                          deviceName: device_info[:name],
                    devicePlatformID: 7, # MacOS (see DevicePlatformType)
                          deviceType: 5, # Mac (see DeviceType)
                },
            },
            rpData: {
                     clientId: "42a01655e65147c3b03721df36b45195",
                response_type: "session_id_token",
                      culture: "en-US",
            },
            userData: {
                email: username,
            },
            ysvcData: {
                deviceId: device_info[:id],
            }
        }
    }, {}, mock_response

    parsed = response.parsed_response
    raise "Request failed" if !parsed["responseResult"]["isSuccess"]

    transaction_id = parsed["oAuthTransId"]
    raise "Request failed" if transaction_id == nil

    transaction_id
end

#
# main
#

config = YAML::load_file "config.yaml"

http = Http.new
device_info = register_new_device "truekey-ruby", http
transaction_id = auth_step1 config["username"], device_info, http
