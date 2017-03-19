#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "json"
require "yaml"
require "httparty"
require "securerandom"

# TODO: Remove mock responses and put in the tests

# Case insensitive hash map with read-only access. It's very very simple.
# It's made to convert from a parsed JSON hash map. The conversion takes
# care of the nested data. Only hashes and vectors are supported. Normal
# JSON shouldn't have anything else anyway.
#
# This is needed since Intel cannot get their engineering together and
# figure out how they want to name their identifiers. In the original code
# they often check multiple versions, like OOBDevices vs oobDevices or
# NextStep vs nextStep and so on.
class CaseInsensitiveHash
    def initialize hash = nil
        @storage = {}
        (hash || {}).each do |k, v|
            @storage[k.downcase] = convert v
        end
    end

    def [] path
        path.downcase.split("/").reduce @storage do |h, i|
            (h || {})[i]
        end
    end

    def to_hash
        @storage
    end

    private

    def convert value
        case value
        when Array
            value.map { |e| convert e }
        when Hash
            CaseInsensitiveHash.new value
        else
            value
        end
    end
end

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
        @log = true
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

    # Expects JSON in response. Parses and converts it to CaseInsensitiveHash.
    # Also checks for operation result and throws on failure. Also throws on
    # HTTP error.
    def post_json url, args, headers = {}, mock_response = nil
        if @log
            puts "=" * 80
            puts "Request to #{url}"
            ap args
        end

        response = post url,
             args.to_json,
             headers.merge({"Content-Type" => "application/json"}),
             mock_response

        if @log
            puts "-" * 40
            puts "HTTP: #{response.code}"
            ap response.parsed_response
        end

        raise "Request failed with code #{response.code}" if !response.success?

        json = CaseInsensitiveHash.new response.parsed_response
        raise "Request failed" if !json["responseResult/isSuccess"]

        json
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
        @response_class ||= Struct.new :parsed_response, :code, :success?
        @response_class.new mock_response, 200, true
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

    result = {
        token: response["clientToken"],
        id: response["tkDeviceId"]
    }
    raise "Invalid response" if result.values.include? nil

    result
end

def make_common_request client_info, response_type, transaction_id = ""
    {
        data: {
            contextData: {
                deviceInfo: {
                          deviceName: client_info[:name],
                    devicePlatformID: 7, # MacOS (see DevicePlatformType)
                          deviceType: 5, # Mac (see DeviceType)
                },
            },
            rpData: {
                     clientId: "42a01655e65147c3b03721df36b45195",
                response_type: response_type,
                      culture: "en-US",
            },
            userData: {
                email: client_info[:username],
                oTransId: transaction_id,
            },
            ysvcData: {
                deviceId: client_info[:id],
            },
        }
    }
end

# Returns OAuth transaction id that is used in the next step
def auth_step1 client_info, http
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

    response = http.post_json "https://truekeyapi.intelsecurity.com/session/auth",
                              make_common_request(client_info, "session_id_token"),
                              {},
                              mock_response

    transaction_id = response["oAuthTransId"]
    raise "Request failed" if transaction_id == nil

    transaction_id
end

# Returns instructions on what to do next
def auth_step2 client_info, password, step1_transaction_id, http
    mock_response_with_one_oob = {
        "refreshTokenExpiry" => 0.0,
            "responseResult" => {
                   "isSuccess" => true,
                   "errorCode" => nil,
            "errorDescription" => nil,
               "transactionId" => "296264da-50a5-4d32-b9ab-c086f360093b"
        },
          "riskAnalysisInfo" => {
                   "nextStep" => 12,
                     "flowId" => nil,
               "nextStepData" => {
                       "oobDevices" => [
                    {
                            "deviceId" => "MTU5NjAwMjI3MQP04dNsmSNQ2LOPWrIep" +
                                          "KI6ra8lkjoubkr1B9TMpWSSytkNsFK2n/" +
                                          "utQGl+8giXPuzWxS+p9GSPvBQPE2444eZ" +
                                          "gyDogtwq3vWKX2ayAvmEj1G198GiDmjfj" +
                                          "XpkMq41hQYU=",
                          "deviceName" => "LGE Nexus 5",
                        "oobPreferred" => false
                    }
                ],
                "verificationEmail" => "username@example.com",
                   "bcaResyncToken" => nil
            },
                "altNextStep" => 14,
                "bcaNextStep" => 0,
            "bcaNextStepData" => nil
        },
                  "authCode" => nil,
               "redirectUrl" => nil,
                     "state" => nil,
                  "cloudKey" => nil,
                   "idToken" => nil,
              "uasTokenInfo" => nil,
              "oAuthTransId" => "ae830c59-634b-437c-95b6-58158e85ffae",
             "activeSession" => false,
             "templateCount" => 0,
              "refreshToken" => nil
    }

    mock_response_with_two_oobs = {
        "refreshTokenExpiry" => 0.0,
            "responseResult" => {
                   "isSuccess" => true,
                   "errorCode" => nil,
            "errorDescription" => nil,
               "transactionId" => "5105155e-fbbc-4a7c-bb3d-455f968e147d"
        },
          "riskAnalysisInfo" => {
                   "nextStep" => 13,
                     "flowId" => nil,
               "nextStepData" => {
                       "oobDevices" => [
                    {
                            "deviceId" => "MTU5NjAwMjI3MQA+h3kH+ff/bO2MmXl7d" +
                                          "DMZQwwFnt9jztLUMGHXCWnCNSkhJKI14M" +
                                          "bCduOPZLtWarN6p3g2ZxqSxRNZyjfCTuH" +
                                          "RAAGbPdhu400VYpzU/liw/97TpuVdczqq" +
                                          "uX78IKwLRZ8=",
                          "deviceName" => "OnePlus ONEPLUS A3003",
                        "oobPreferred" => false
                    },
                    {
                            "deviceId" => "MTU5NjAwMjI3MQCRJ1PS9YAIdsEjGormP" +
                                          "lvrxG3d872WvUjVOgLISXKftAD++bFzfV" +
                                          "zSdOCQhPK0iVyw0bTUxxgJH+5puKJZYfe" +
                                          "EortnUXDYmmV6VYwuX0p5+weSuI5Tt4RS" +
                                          "VpRrhueCK6g=",
                          "deviceName" => "LGE Nexus 5",
                        "oobPreferred" => false
                    }
                ],
                "verificationEmail" => "username@example.com",
                   "bcaResyncToken" => nil
            },
                "altNextStep" => 14,
                "bcaNextStep" => 0,
            "bcaNextStepData" => nil
        },
                  "authCode" => nil,
               "redirectUrl" => nil,
                     "state" => nil,
                  "cloudKey" => nil,
                   "idToken" => nil,
              "uasTokenInfo" => nil,
              "oAuthTransId" => "c1a79e3d-6c4d-432c-a85b-17f9c76f9f66",
             "activeSession" => false,
             "templateCount" => 0,
              "refreshToken" => nil
    }

    response = http.post_json "https://truekeyapi.intelsecurity.com/mp/auth", {
        userData: {
                   email: client_info[:username],
            oAuthTransId: step1_transaction_id,
                     pwd: hash_password(client_info[:username], password),
        },
        deviceData: {
                      deviceId: client_info[:id],
                    deviceType: "mac",
            devicePlatformType: "macos",
                       otpData: generate_random_otp(client_info[:otp_info])
        }
    }, {}, mock_response_with_two_oobs

    parse_auth_step_response response
end

#
# Auth FSM
#

def wait_for_email email, transaction_id
    {
        state: :wait_for_email,
        done: false,
        valid_answers: [:check, :resend],
        email: email,
        transaction_id: transaction_id,
    }
end

def wait_for_oob device, email, transaction_id
    {
        state: :wait_for_oob,
        done: false,
        valid_answers: [:check, :resend, :email],
        device: device,
        email: email,
        transaction_id: transaction_id,
    }
end

def choose_oob devices, email, transaction_id
    {
        state: :choose_oob,
        done: false,
        valid_answers: [0...devices.size].to_a + [:email],
        devices: devices,
        email: email,
        transaction_id: transaction_id,
    }
end

def done oauth_token
    {
        state: :done,
        done: true,
        oauth_token: oauth_token,
    }
end

def failure
    {
        state: :failure,
        done: true,
    }
end

def auth_check client_info, transaction_id, http
    mock_response_success = {
              "refreshToken" => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidmV" +
                                "yc2lvbiI6MX0..GUk1Usj-H1kS0cG5.Z5qVcr5BcrpC" +
                                "aMLHyoxeO_k0PBqSS3Xgi05PyjP1EIOSns9B73JgLfP" +
                                "FBHj28F0e0zfct4Kriwh_oUjHvUOw_t2AM8LcVqI3jm" +
                                "hW05In_4KRqNb64AovO2JYoUL4CQNmgqpzz2kuKMFQV" +
                                "46NGagrrEvK7eg27HGMLRRpa4wCL_Bu8dBhCn_MbbMW" +
                                "WNN35hBp3deJ6h41B4XZIw5Saf5iisSNun62zy6QIDb" +
                                "hsFzHpSW8fQmka2E4sZ7ip3aBFUF2vr8Ff4MQOHEo5n" +
                                "LJwF5nMwrqj8vBYxzPN72TwrwBjeKceFmrxsp1CoZB1" +
                                "5SewGTuFMXrlYM7XVDNt6AUSa_uQBAqrCLnyWvfzvI4" +
                                "jon37t0GipdDAcV88qwfnWpcGkFREbiBSu37QOBB6rR" +
                                "aRN3Ao9Yge15WG2RYyP-nkDwiBgJgIYNlkkVSUINOAW" +
                                "uOODsNPqPSOzrVMNoLa6cn-pWcQBORFH0uxLHJZtr40" +
                                "jpfmsBk70hFnKJMA2SONYDzXpqKEqPXNEQRTLPNL_F9" +
                                "9bSnOeW7IXfrn_Nva5lWCwSvwEcB3xCPp1XRbf8nmjB" +
                                "FBemtr5lSNrOTaBcU5nSnXagm8rPaS956VAzupkGNR1" +
                                "SNNqaqAip78crDQG2-OEdaYDB6in0.yKq6sGLfBUr6c" +
                                "Lanaons6g",
        "refreshTokenExpiry" => 0.0,
            "ResponseResult" => {
                   "IsSuccess" => true,
                   "ErrorCode" => nil,
            "ErrorDescription" => nil,
               "TransactionId" => nil
        },
                  "nextStep" => 10,
              "NextStepData" => nil,
                  "authCode" => nil,
               "redirectUri" => nil,
                   "idToken" => "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI" +
                                "6IllBUF9UUlVFS0VZX1BST0RfMDEifQ.eyJzdWIiOiI" +
                                "5ZTQ0ZmViNy1mZTRlLTQzODMtYWQ5Ny0zZWFmZWNiZD" +
                                "Q3MmYiLCJub25jZSI6IiIsImlzX3ByZW1pdW0iOiJmY" +
                                "WxzZSIsImlzcyI6Imh0dHBzOi8vaW50ZWxzZWN1cml0" +
                                "eS5jb20iLCJhdWQiOiI0MmEwMTY1NWU2NTE0N2MzYjA" +
                                "zNzIxZGYzNmI0NTE5NSIsImV4cCI6MTQ4OTc3NTIzMy" +
                                "wibmJmIjoxNDg5NzcxNjMzLCJpYXQiOjE0ODk3NzE2M" +
                                "zQsImF1dGhfdGltZSI6MTQ4OTc3MTYzNCwiZW1haWwi" +
                                "OiJsYXN0cGFzcy5ydWJ5QGdtYWlsLmNvbSIsImVtYWl" +
                                "sX3ZlcmlmaWVkIjoidHJ1ZSIsImRldmljZV9pZCI6Ij" +
                                "YxYWE0M2I5ZWNlMTgwMjVhNjhkNmQxY2Y5ZjdkODI0Z" +
                                "GNjZDY1MGQ0NzBjMjc5NDhlYTQyYzg4ZjVlNzE0ODk0" +
                                "MTA4MDciLCJhY2Nlc3NfdHlwZSI6WyJkZWZhdWx0Il1" +
                                "9.PyuQVBg3GIjaMa12VAC6BxDKPpudeuKxzMYDw19po" +
                                "KjWcE2pM55vl0jBNSYtf88qHC4ZcXKpKX6uWycmVxZx" +
                                "WZdJt4xpgACbA0JjUMkZZHC5m-sARneR90iV8PPN8-M" +
                                "r4zwmr0WR28EU0XAe62AGzAuPYnJwoJ_-55k4ZGR46R" +
                                "SHG4LjYwVeh997eSURoEgsORTki9q3-10j_5m30aOFF" +
                                "1DimX29PRkZS5SOK2ThApJq6vg3GrChcxJ82MCljr7C" +
                                "CK1z7GTDW0gGjiURiICQHyzepW27SRByFacrgTCGRpu" +
                                "xE06gvIzJBMRHTPVNlBk-h-7xeummbWVr8v-InsSWOw",
                     "state" => nil,
                  "cloudKey" => "5b33074068c3be15776b6c4c536a2a848ae4a5a0bc7" +
                                "f6a1c3922b0b984fc6f06",
           "isTrustedDevice" => false,
              "uasTokenInfo" => {
              "authToken" => "11-3-1489771633",
            "attestation" => nil,
                  "nonce" => nil
        }
    }

    mock_response_pending = {
              "refreshToken" => nil,
        "refreshTokenExpiry" => 0.0,
            "ResponseResult" => {
                   "IsSuccess" => false,
                   "ErrorCode" => "E3013",
            "ErrorDescription" => "Authentication Pending",
               "TransactionId" => nil
        },
                  "nextStep" => 0,
              "NextStepData" => nil,
                  "authCode" => nil,
               "redirectUri" => nil,
                   "idToken" => nil,
                     "state" => nil,
                  "cloudKey" => nil,
           "isTrustedDevice" => false,
              "uasTokenInfo" => nil
    }

    args = make_common_request client_info, "code", transaction_id
    http.post_json "https://truekeyapi.intelsecurity.com/sp/profile/v1/gls",
                   args,
                   {},
                   mock_response_success
end

def send_email client_info, email, transaction_id, http
    mock_response = {
        "ResponseResult" => {
                   "IsSuccess" => true,
                   "ErrorCode" => nil,
            "ErrorDescription" => nil,
               "TransactionId" => nil
        }
    }

    args = make_common_request client_info, "code", transaction_id
    args[:notificationData] = {
        NotificationType: 1,
        RecipientId: email,
    }

    http.post_json "https://truekeyapi.intelsecurity.com/sp/oob/v1/son",
                   args,
                   {},
                   mock_response
end

def send_push client_info, device, transaction_id, http
    mock_response = {
        "ResponseResult" => {
                   "IsSuccess" => true,
                   "ErrorCode" => nil,
            "ErrorDescription" => nil,
               "TransactionId" => nil
        }
    }

    args = make_common_request client_info, "code", transaction_id
    args[:notificationData] = {
        NotificationType: 2,
        RecipientId: device[:id],
    }

    http.post_json "https://truekeyapi.intelsecurity.com/sp/oob/v1/son",
                   args,
                   {},
                   mock_response
end

class Gui
    def wait_for_email email
        [:check, :resend][0]
    end

    def wait_for_oob device, email
        [:check, :resend, :email][0]
    end

    def choose_oob devices, email
        [0, 1, :email][0]
    end
end

def parse_auth_step_response response
    ra = response["riskAnalysisInfo"]
    next_step = ra["nextStep"]

    case next_step
    when 10
        done response["idToken"]
    when 12
        wait_for_oob parse_devices(ra["nextStepData/oobDevices"])[0], ra["verificationEmail"], response["oAuthTransId"]
    when 13
        choose_oob parse_devices(ra["nextStepData/oobDevices"]), ra["verificationEmail"], response["oAuthTransId"]
    when 14
        wait_for_email ra["verificationEmail"], response["oAuthTransId"]
    else
        raise "Next two factor step #{next_step} is not supported"
    end
end

def parse_devices device_info
    device_info.map { |i| {id: i["deviceId"], name: i["deviceName"]} }
end

# TODO: This is probably better done with some classes rather then a giant switch
def auth_fsm client_info, step, gui, http
    while !step[:done]
        case step[:state]
        when :wait_for_email
            answer = gui.wait_for_email step[:email]
            step = case answer
            when :check
                auth_check client_info, step[:transaction_id], http
            when :resend
                send_email client_info,
                           step[:email] || client_info[:username],
                           step[:transaction_id],
                           http
                wait_for_email step[:email], step[:transaction_id]
            else
                raise "Invalid answer"
            end
        when :wait_for_oob
            answer = gui.wait_for_oob step[:device], step[:email]
            step = case answer
            when :check
                auth_check client_info, step[:transaction_id], http
            when :resend
                send_push client_info, step[:device], step[:transaction_id], http
                wait_for_oob step[:device], step[:email], step[:transaction_id]
            when :email
                send_email client_info,
                           step[:email] || client_info[:username],
                           step[:transaction_id],
                           http
                wait_for_email step[:email], step[:transaction_id]
            else
                raise "Invalid answer"
            end
        when :choose_oob
            answer = gui.choose_oob step[:devices], step[:email]
            step = case answer
            when 0...step[:devices].size
                device = step[:devices][answer]
                send_push client_info, device, step[:transaction_id], http
                wait_for_oob device, step[:email], step[:transaction_id]
            when :email
                send_email client_info,
                           step[:email] || client_info[:username],
                           step[:transaction_id],
                           http
                wait_for_email step[:email], step[:transaction_id]
            else
                raise "Invalid answer"
            end
        end
    end

    step
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

# Checks that the OTP info is something we can work with.
# The Chrome extension also supports only this subset. They don't validate as much, just assume
# the values are what they expect.
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

#
# Crypto
#

# Default HMAC for True Key (HMAC-SHA256).
def hmac seed, message
    OpenSSL::HMAC.digest "sha256", seed, message
end

# Creates a password hash that is sent to the server during the auth sequence.
def hash_password username, password
    salt = Digest::SHA256.digest username
    bin = OpenSSL::PKCS5.pbkdf2_hmac password, salt, 10000, 32, "sha512"
    hex = bin.unpack("H*")[0]
    "tk-v1-" + hex
end

#
# Vault
#

def open_vault config, http, gui
    client_info = {
        username: config["username"],
            name: "truekey-ruby",
           token: config["token"],
              id: config["id"],
    }

    # Step 1: register a new device and get a token and an id back
    if client_info[:token].nil? || client_info[:id].nil?
        device_info = register_new_device client_info[:name], http

        client_info[:token] = device_info[:token]
        client_info[:id] = device_info[:id]
    end

    # Step 2: parse the token to decode OTP information
    client_info[:otp_info] = parse_client_token client_info[:token]

    # Step 3: validate the OTP info to make sure it's got only the things we support at the moment
    validate_otp_info client_info[:otp_info]

    # Step 4: auth step 1 gives us a transaction id to pass along to the next step
    transaction_id = auth_step1 client_info, http

    # Step 5: auth step 2 gives us instructions what to do next. For a new client that would
    #         be some form of second factor auth. For a known client that would be a pair of
    #         OAuth tokens.
    whats_next = auth_step2 client_info, config["password"], transaction_id, http

    # Auth FSM
    result = auth_fsm client_info, whats_next, gui, http
end

#
# main
#

# Simple Gui implementation
# TODO: Add resend and email options
class TextGui < Gui
    def wait_for_email email
        puts "Please check your email '#{email}' and confirm"
        gets
        :check
    end

    def wait_for_oob device, email
        puts "Please check #{device[:name]} and confirm"
        gets
        :check
    end

    def choose_oob devices, email
        puts "Please choose second factor device:"
        devices.each_with_index do |d, i|
            puts " - #{i + 1}: #{d[:name]}"
        end
        gets.to_i - 1
    end
end

config = YAML::load_file "config.yaml"
http = Http.new :default
gui = TextGui.new

ap open_vault config, http, gui
