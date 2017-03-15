#!/usr/bin/env ruby

require "json"
require "yaml"
require "httparty"
require "securerandom"

#
# Network
#

class Http
    include HTTParty

    # Network modes:
    #  - :default: return mock response if one is provided
    #  - :force_online: always go online
    #  - :force_offline: never go online and return mock even if it's nil
    def initialize network_mode = :default
        @network_mode = network_mode
    end

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
        case @network_mode
        when :default
            mock_response
        when :force_online
            false
        when :force_offline
            true
        else
            raise "Invalid network_mode '#{@network_mode}'"
        end
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
# OCRA/OTP/RFC 6287
#

# TODO: Make sure these don't leak outside
class String
    def d64
        Base64.decode64 self
    end

    def e64
        Base64.strict_encode64 self
    end
end

# TODO: Make sure these don't leak outside
class StringIO
    def ru size, format
        read(size).unpack(format)[0]
    end
end

# Parses clientToken field returned by the server. It contains encoded
# OCRA/OPT/RFC 6287 infofmation. This is used later on to sign messages.
def parse_client_token encoded
    StringIO.open encoded.d64 do |io|
        token_type = io.ru 1, "C"
        token_length = io.ru 2, "n"
        token = io.read token_length
        iptmk_tag = io.ru 1, "C"
        iptmk_length = io.ru 2, "n"
        iptmk = io.read iptmk_length

        ocra = StringIO.open token do |io|
            version = io.ru 1, "C"
            otp_algo = io.ru 1, "C"
            otp_length = io.ru 1, "C"
            hash_algo = io.ru 1, "C"
            time_step = io.ru 1, "C"
            start_time = io.ru 4, "N"
            server_time = io.ru 4, "N"
            wys_option = io.ru 1, "C"
            suite_length = io.ru 2, "n"
            suite = io.read suite_length

            io.pos = 128
            hmac_seed_length = io.ru 2, "n"
            hmac_seed = io.read hmac_seed_length

            {
                version: version,
                otp_algo: otp_algo,
                otp_length: otp_length,
                hash_algo: hash_algo,
                time_step: time_step,
                start_time: start_time,
                server_time: server_time,
                wys_option: wys_option,
                suite: suite,
                hmac_seed: hmac_seed
            }
        end

        {
            ocra: ocra,
            iptmk: iptmk
        }
    end
end

def validate_otp_info otp
    check = lambda { |name, index, expected|
        actual = otp[:ocra][index]
        raise "Unsupported OTP #{name} (got #{actual}, expected #{expected})" if actual != expected
    }

    check.call "version", :version, 3
    check.call "method", :otp_algo, 1
    check.call "length", :otp_length, 0
    check.call "hash", :hash_algo, 2
    check.call "suite", :suite, "OCRA-1:HOTP-SHA256-0:QA08"
end

# Generates the OTP signature of type "time". This is deterministic version, both
# time and random challenge must be provided.
def generate_otp otp_info, challenge, timestamp_sec
    raise "challenge must be 128 bytes long (was #{challenge.size})" if challenge.size != 128

    ocra = otp_info[:ocra]

    message = ""
    message += ocra[:suite]
    message += "\0"
    message += challenge
    message += [0, ((timestamp_sec - ocra[:start_time]) / ocra[:time_step]) & 0xffff_ffff].pack "NN"

    signature = hmac ocra[:hmac_seed], message

    {
        qn: challenge.e64,
        otpType: "time",
        otp: signature.e64
    }
end

# Generates the OTP signature of type "time" with a random challnge and current time.
def generate_random_otp otp_info
    generate_otp otp_info, SecureRandom.random_bytes(128), Time.now.to_i
end

# Default HMAC for True Key (HMAC-SHA256).
def hmac seed, message
    OpenSSL::HMAC.digest "sha256", seed, message
end

#
# main
#

config = YAML::load_file "config.yaml"

http = Http.new
device_info = register_new_device "truekey-ruby", http
device_info[:otp_info] = parse_client_token device_info[:token]
validate_otp_info device_info[:otp_info]

transaction_id = auth_step1 config["username"], device_info, http
ap generate_random_otp device_info[:otp_info]
