#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "json"
require "yaml"
require "httparty"
require "securerandom"
require "openssl/ccm"

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

    # We have to force JSON since HTTParty fails to automatically recognize
    # 'application/vnd.api+json' as JSON.
    format :json

    # Network modes:
    #  - :default: return mock response if one is provided
    #  - :force_online: always go online
    #  - :force_offline: never go online and return mock even if it's nil
    def initialize network_mode = :default
        @network_mode = network_mode
        @log = false
    end

    def get url, headers = {}, mock_response = nil
        return make_response mock_response if should_return_mock? mock_response

        self.class.get url, {headers: headers}
    end

    # TODO: Remove _json suffix since everything is JSON here.
    def get_json url, headers = {}, mock_response = nil
        if @log
            puts "=" * 80
            puts "GET to #{url}"
        end

        response = get url, headers, mock_response

        if @log
            puts "-" * 40
            puts "HTTP: #{response.code}"
            ap response.parsed_response
        end

        raise "Request failed with code #{response.code}" if !response.success?

        CaseInsensitiveHash.new response.parsed_response
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
    # TODO: Remove _json suffix since everything is JSON here.
    def post_json url, args, headers = {}, mock_response = nil
        response = post_json_no_check url, args, headers, mock_response
        raise "Request failed" if !response["responseResult/isSuccess"]

        response
    end

    # The version of the above function that doesn't check the isSuccess flag
    # in the returned response.
    # TODO: Remove _json suffix since everything is JSON here.
    def post_json_no_check url, args, headers = {}, mock_response = nil
        if @log
            puts "=" * 80
            puts "POST to #{url}"
            ap args
        end

        response = post url,
             args.to_json,
             headers.merge({"Content-Type" => "application/json; charset=UTF-8"}),
             mock_response

        if @log
            puts "-" * 40
            puts "HTTP: #{response.code}"
            ap response.parsed_response
        end

        raise "Request failed with code #{response.code}" if !response.success?

        CaseInsensitiveHash.new response.parsed_response
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

def get_vault oauth_token, http
    mock_response = {
                 "schema" => "tkd0",
               "customer" => {
                            "id" => 11522643,
                        "schema" => "tkp-s3",
                      "fullname" => "LastPass Ruby",
                         "email" => "lastpass.ruby@gmail.com",
                        "cohort" => "{\"distinct_id\":\"TK:9e44feb7-fe4e-438" +
                                    "3-ad97-3eafecbd472f\",\"af_status\":\"O" +
                                    "rganic\",\"signup_date\":\"2016-12-09T1" +
                                    "7:00:08Z\",\"p\":\"public_2\"}",
                          "salt" => "845864cf3692189757f5f276b37c2981bdceefe" +
                                    "a04905699685ad0541c4f9092",
                         "k_kek" => "AARZxaQ5EeiK9GlqAkz+BzTwb1cO+b8yMN+SCt3" +
                                    "bzQJO+Fyf4TnlA83Mbl1KrMI09iOd9VQJJlu4iv" +
                                    "WMwCYhMB6Mw3LOoyS/2UjqmCnxAUqo6MTSnptgj" +
                                    "lWO",
                    "public_key" => "{\"n\":\"ec9c8f40232c32cf5fdd8a1fdc7db9" +
                                    "27387ab7536e22a7c2ca5e610a4fc52f8335616" +
                                    "5f8219877af7262b8466d3937d7115457dc348e" +
                                    "bd4d126a8dd01614926e3cc057cae00e854b317" +
                                    "33f769ea29a630be1f8b8a80e6fd7c08592c508" +
                                    "958c904106fa5527118dc23a470902471898045" +
                                    "e355c4cc73e6c314f38261c7b35b4320634705a" +
                                    "858070368c7e6f5fcac6694f50e3ca7ef0c09be" +
                                    "ccea0141157a4b92e3963a8cde744f010b1e178" +
                                    "4bc1d7c5e6ddde7fa8d78252563e8be16d16847" +
                                    "635e69fa3080c39cdefb904d17d2fc3d6ef4e2e" +
                                    "ee35eb65dc79ec66f62ba9f45c356a06827e289" +
                                    "3b698684a7733658ad175306cd3b14631cb5a5a" +
                                    "d46eb5a0280c49\",\"e\":\"3\"}",
                   "private_key" => "AATubos0zhkDs3+NrxNevyGYs6lIXfg8ncmrxqk" +
                                    "wXQSBJtSk04EhZb23Ql5bYOSQ82SqsRsNW7xGjC" +
                                    "FCybFoAy0cINmxBjUfjiAPdeO6g2Kc0A40b9IfE" +
                                    "rdvHRiE99TS8hP2tgLbA1hodsGN8zbpUJ1Hz0oA" +
                                    "EFNBnq2jqmC++CbLynY2vphc+RNScasczziQcse" +
                                    "/JsXkQ2NIBr9lDjnyelPALc6MHDE8rQt3rBLs/8" +
                                    "dwYClHLhsitNdRLYqJgWNFqU6JghGbPnAVbmpZX" +
                                    "+NqUOFzKqGZcVqev6k9d4vx/iEeoeg2PeHWAc7X" +
                                    "iBKdt2ej2/KmlWceSP8akJ9t2nzDjP7xpMIhKed" +
                                    "MZKAgC30f2ZznyH/4iZtVim2p50zpFXglfRvFA4" +
                                    "acZbg6cSzr0JCn8ueATwYE1yo8pHHJ5F7x6SA6R" +
                                    "wqZMq0hoK6xy1AS9DfVZV+UNR/kSmzXw2ExNbjc" +
                                    "BVTos/8KaRma5iuLMqgjkGKIXov6yY6TD0XyFIU" +
                                    "DGXTlUigfxgL7iHOEwkag2yfqNRTTpQOzniPv2Y" +
                                    "mU1BBKk/6ewMm6LsER2pX269s4v1XdHLZ19whNn" +
                                    "CS7j1EY9JJlH0TtPBPNsh/i+Zazt3i2DxZ/jI6N" +
                                    "oUMB1jPjUdBSwS5QZn/XnWP/UcNqGgztQJFRNM3" +
                                    "c8YhSHK6wicoIHTS4eSqVMKkPXIbRql9i9P7LDZ" +
                                    "pi7rGFAow8aISRsVag/4o6+gtQrRLN6+3FvrH0n" +
                                    "yamNeR8JKqWI0JOXsoTVEdjrKV3X3NBsZtQWAa2" +
                                    "HMKE/2jqPKM5n2fM15IeTDbNEYBcZjRcs98rvfB" +
                                    "eUhxJFPzLI/inw5ekaOHmthATopbao+/lOO5yFX" +
                                    "1xE4rS8MlATiE5yCgTy7H4ftwcgtkjCFczKx0u0" +
                                    "q8seVHjTaNG0zVotWp5xzBuY5cqzSd5xjtdsO4V" +
                                    "Y9D5k91OC6O/x+5hjKlbdFekScXX8AeqOqE5/0M" +
                                    "ThCSHgCDb2ob0xjLMT+Mt1DgaPFIBbTCDEcQkSE" +
                                    "5s4orpF9KT8Eo5JLw7RtcAayIcvzeCf6gm3LqTQ" +
                                    "ZmakDQrjx+s5I6rw/Bgawso/iA72OgQSQHqEiwu" +
                                    "F/wTuO/eUkxcLNxisvT+lTDtZ07UFbKRz2eXnx/" +
                                    "gWAvpzbHWA0nui9hMzaH9yRbM0AA1BD2TanHnUs" +
                                    "EEhMd+SejKtXD1RT+05VAZNsxEC5QwFN2qo95pC" +
                                    "t3T3AyM70iTkYlP2pZtbyquyuL5paDV2Bx84xfN" +
                                    "3h1zlrKsdqO8UevDOD5CHKOpXuTLt1IjJRHOfvJ" +
                                    "XxN82V995Yvj79mmcWaeyIxN4Hh6Sygy7d1gw2n" +
                                    "gxPWtJMz7u4gUJfrfSFmv3dDD2oMGI62HKmRmJ0" +
                                    "somCPTNCWHaDmEF/w48AsDKAOaJTfNBVml+oSQx" +
                                    "UfByWYBe1xDF8TNAw/7xCt2Z/zQvW4GrdCCJhRf" +
                                    "OW4vukkK9KGLKd5u1EPRp2nVAfYjQXCdOrCiEh9" +
                                    "cuhH+WeAzrxxZzkMtVxO+iKtvxhquFJ+JT2S2dd" +
                                    "FtMYTt71xozUw0iqFV8jmmCY0EKzcqDaosgKTvI" +
                                    "I8BdF0ColXhgPCFqIhVUekvvpMcNAE+JC6bcVEO" +
                                    "VYZRWhI9/u8CFzlu3bNa7JzT0zaJcXrQll/Fq3F" +
                                    "YI+PH60FubJWAZK8Cj5MLDWgIMtzVN64Anm/rnX" +
                                    "l1m8qan1paQGJ3MmZQWs1074RbONF/y4SmQit7q" +
                                    "DZ96BhZKYRTAncd5bPYvU4dOsbKQjFdLiWBV7Ul" +
                                    "mR71eDuuVcLRsX5E0Km8xHVXnvrLbkBAHvCAbqx" +
                                    "G9f3gCiA1ohjZZmu8MZNz80aVRA5NJL9pHAHDhY" +
                                    "t5LFELkL+/9Ao3OL/Oi8YlH6r2gR+ogwyhh5zxS" +
                                    "vaHkEMs1V5vx3dN4bOSrT0n29FGUuJ8HTEZt2zr" +
                                    "0iwZWElII0HEQntoszAPWPMqrAz+sCRMkRnIbs6" +
                                    "ymiLlYekUkTh/Ct7THxCELZ2eUN2YAQrxtLje9O" +
                                    "39k4wn23RNyX7aDXMDbjM3W8HcX2dbfXqsKj7rY" +
                                    "IJLQY27V8dzHVTqtmhHucFWhANjYxxor2ArwLwV" +
                                    "S6bpYjcfFVg/X96PeNGIPlY0Uo9ZHCUoqE8dHF3" +
                                    "nrIVwYOCW+tm4zPmnKPGKlacXtOAl0tjngmPcxp" +
                                    "BBOBbHVRmNE3KBKChoTQ/vUg/EGocBqyTlNzWBm" +
                                    "mcWFUFb3HV/PsGoCc/wRrJX2iGkz0+XRjoiPAbx" +
                                    "ZBXYEZfmGLkeLBFmElK0aO+F+FvjYhr2cnwJHt7" +
                                    "CRin9OFV+q873vwLMOfW7L9L+dVS3t+9gas5LGv" +
                                    "rd39KTlWjeB4CoML4waVasrAMlw5gj/VQhsLxOU" +
                                    "lrHYE/w8faMTPu09GIccvfrlgaII2ygJXLSy6MG" +
                                    "gSyYTYteX0OaxZlH7qy5mHFSy4XS9apIiP+A1fW" +
                                    "UBFqOyJ0eo9U7ryBEkKKa+UTX80XE8AzxUO4JBp" +
                                    "P8PubqdVogmvOd9JMn6Xv8RyIQ6V+W0T3IO+FVO" +
                                    "RXpPKzhfisaT11SKXOFKPhJBEFIWVuOrveSnd+Q" +
                                    "tiJ/rJaorRgql7EwOXvuf2ENF5yZAREvrbklow+" +
                                    "Q8ca4nhrBvwM5yV2QOxAxC37pfoKgJ3lAwuC11R" +
                                    "J2LgqO1w0ofjOXXuGK5ZTI5YUJiJLy6EZFN52dC" +
                                    "NJQsvX/wbSiS5WeR/s8CgdmlU7JP1xUlrSN3Udc" +
                                    "uBMKHUTaXHChCodL70vDz0XGwPPtxMgYImgqhRA" +
                                    "NKeuaP7hWswlqJMYKfwc+i6mTwiQ6y2WrO2wpuk" +
                                    "hNmJjM1K8bAHpnIVWZvefR7Z7kCZN1AoMo/SuNq" +
                                    "uveUV6zTr2gRzivq0rL4V0NtqZuMhCSJ8aVWup5" +
                                    "TxhH76wAbXFULc78Amh5KbaOAo3PPwUbJJ+iTAG" +
                                    "/hHlcA7tQD1WWKjKA/BnDyXK2dl4jpocvGJ5UiP" +
                                    "ghrb7Ju/kCf+bp9zDUwnZqvhdIs3OOuWlpNMqWO" +
                                    "8NlifvHAJJHbQZ6iVEbIp9foFcIyoo0Ym0NJkjr" +
                                    "D9VrZNHduKR4r80n5kcNQFyxb1LyxzH00+dIFpK" +
                                    "+Aodp6VG02s+vAOxsuG+nNVsZNdETXTzJ396rFC" +
                                    "WP94DSGBMgmN+YYgfAQp5nTBGdv+a0McbHE7I9b" +
                                    "2iDOgEmT7gD0OUmePqJAdpaSw74Up2HOD20/Auw" +
                                    "5sNlkiXTForfF7pEmo1L1RucJNuzYdykahnsY",
                            "dr" => "{\"algo\":\"tk-v1_pbkdf2-hmac-sha512\"," +
                                    "\"iterations\":10000}",
               "profile_version" => 2,
             "enrollment_ticket" => "b96c116d-3572-458f-af30-47ec49e1349a",
                   "profile_uid" => "9e44feb7-fe4e-4383-ad97-3eafecbd472f",
                   "distinct_id" => "TK:9e44feb7-fe4e-4383-ad97-3eafecbd472f",
                         "trial" => true,
                  "assets_limit" => 15,
            "email_verification" => {
                         "verified_at" => "2016-12-09T17:00:08Z",
                "verification_sent_at" => nil
            },
                      "settings" => nil,
               "data_updated_at" => "2017-03-20T11:41:44-04:00"
        },
        "data_updated_at" => "2017-03-20T15:41:44Z",
                 "assets" => [
            {
                        "id" => 50934080,
                 "member_id" => 11522643,
                      "name" => "Google",
                     "login" => "dude@gmail.com",
                       "url" => "https://accounts.google.com/ServiceLogin",
                    "domain" => "google.com",
                    "memo_k" => "AAS2l1XcabgdPTM3CuUZDbT5txJu1ou0gOQ=",
                "password_k" => "AAR24UbLgkHUhsSXB2mndMISE7U5qn+WA3znhgdXex0br6y5",
                "created_at" => "2016-12-09T12:07:53-05:00",
                "updated_at" => "2016-12-09T12:07:53-05:00",
                  "settings" => "{\"autologin\":1,\"password_reprompt\":" +
                                "0,\"subdomain_only\":0,\"protectedWithP" +
                                "assword\":0,\"protectedWithFace\":0,\"c" +
                                "ustom_partner_asset\":0,\"android_packa" +
                                "ge_name\":null,\"allow_deletion\":1,\"a" +
                                "lways_on_top\":0}"
            },
            {
                        "id" => 60789074,
                 "member_id" => 11522643,
                      "name" => "facebook",
                     "login" => "mark",
                       "url" => "http://facebook.com",
                    "domain" => "facebook.com",
                    "memo_k" => nil,
                "password_k" => "AAShzvG+qXE7bT8MhAbbXelu/huVjuUMDC8IsLw4Lw==",
                "created_at" => "2017-03-10T05:28:13-05:00",
                "updated_at" => "2017-03-10T05:28:13-05:00",
                  "settings" => "{\"autologin\":\"1\",\"password_repromp" +
                                "t\":\"0\",\"subdomain_only\":\"0\",\"cu" +
                                "stom_partner_asset\":false}"
            }
        ],
              "documents" => [],
          "blocked_items" => []
    }

    http.get_json "https://pm-api.truekey.com/data", {
               "Authorization" => "Bearer #{oauth_token}",
                      "Accept" => "application/vnd.tk-pm-api.v1+json",
             "X-TK-Client-API" => "TK-API-1.1",
         "X-TK-Client-Version" => "2.6.3820",
        "X-TK-Client-Language" => "en-US",
         "X-TK-Client-Context" => "crx-mac",
    }, mock_response
end

#
# Auth FSM
#

def wait_for_email email, transaction_id
    {
        state: :wait_for_email,
        valid_answers: [:check, :resend],
        email: email,
        transaction_id: transaction_id,
    }
end

def wait_for_oob device, email, transaction_id
    {
        state: :wait_for_oob,
        valid_answers: [:check, :resend, :email],
        device: device,
        email: email,
        transaction_id: transaction_id,
    }
end

def choose_oob devices, email, transaction_id
    {
        state: :choose_oob,
        valid_answers: (0...devices.size).to_a + [:email],
        devices: devices,
        email: email,
        transaction_id: transaction_id,
    }
end

def done oauth_token
    {
        state: :done,
        oauth_token: oauth_token,
    }
end

def failure
    {
        state: :failure,
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

    response = http.post_json_no_check "https://truekeyapi.intelsecurity.com/sp/profile/v1/gls",
                                       make_common_request(client_info, "code", transaction_id),
                                       {},
                                       mock_response_success

    if response["responseResult/isSuccess"] && response["nextStep"] == 10
        done response["idToken"]
    else
        failure
    end
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
    args[:data][:notificationData] = {
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
    args[:data][:notificationData] = {
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

# TODO: Handle 12 and 13 differently. It looks like the server can return
# 8 (face) or possible 15 (fingerprint) though they are not supported by
# the Chrome extension. Check how many oob devices there are and pick "wait"
# or "choose".
def parse_auth_step_response response
    next_step = response["riskAnalysisInfo/nextStep"]
    data = response["riskAnalysisInfo/nextStepData"]

    case next_step
    when 10
        done response["idToken"]
    when 12
        wait_for_oob parse_devices(data["oobDevices"])[0],
                     data["verificationEmail"],
                     response["oAuthTransId"]
    when 13
        choose_oob parse_devices(data["oobDevices"]),
                   data["verificationEmail"],
                   response["oAuthTransId"]
    when 14
        wait_for_email data["verificationEmail"],
                       response["oAuthTransId"]
    else
        raise "Next two factor step #{next_step} is not supported"
    end
end

def parse_devices device_info
    device_info.map { |i| {id: i["deviceId"], name: i["deviceName"]} }
end

# TODO: This is probably better done with some classes rather then a giant switch
# TODO: Refactor this and DRY up
def auth_fsm client_info, step, gui, http
    loop do
        case step[:state]
        when :wait_for_email
            answer = gui.wait_for_email step[:email]
            raise "Invalid answer" if !step[:valid_answers].include? answer

            step = case answer
            when :check
                auth_check client_info,
                           step[:transaction_id],
                           http
            when :resend
                send_email client_info,
                           step[:email] || client_info[:username],
                           step[:transaction_id],
                           http

                wait_for_email step[:email],
                               step[:transaction_id]
            else
                raise "Invalid answer"
            end
        when :wait_for_oob
            answer = gui.wait_for_oob step[:device], step[:email]
            raise "Invalid answer" if !step[:valid_answers].include? answer

            step = case answer
            when :check
                auth_check client_info,
                           step[:transaction_id],
                           http
            when :resend
                send_push client_info,
                          step[:device],
                          step[:transaction_id],
                          http

                wait_for_oob step[:device],
                             step[:email],
                             step[:transaction_id]
            when :email
                send_email client_info,
                           step[:email] || client_info[:username],
                           step[:transaction_id],
                           http

                wait_for_email step[:email],
                               step[:transaction_id]
            else
                raise "Invalid answer"
            end
        when :choose_oob
            answer = gui.choose_oob step[:devices], step[:email]
            raise "Invalid answer" if !step[:valid_answers].include? answer

            step = case answer
            when 0...step[:devices].size
                device = step[:devices][answer]

                send_push client_info,
                          device,
                          step[:transaction_id],
                          http

                wait_for_oob device,
                             step[:email],
                             step[:transaction_id]
            when :email
                send_email client_info,
                           step[:email] || client_info[:username],
                           step[:transaction_id],
                           http

                wait_for_email step[:email],
                               step[:transaction_id]
            else
                raise "Invalid answer"
            end
        when :failure
            raise "Authentication failed"
        when :done
            return step[:oauth_token]
        end
    end
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

    def decode_hex
        [self].pack "H*"
    end
end

# TODO: Make sure these don't leak outside
class StringIO
    def ru size, format
        read(size).unpack(format)[0]
    end
end

# Parses clientToken field returned by the server. It contains encoded
# OCRA/OPT/RFC 6287 information. This is used later on to sign messages.
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

def decrypt_sjcl_aes encrypted, key
    version = encrypted[1].bytes[0]
    raise "Unsupported version #{version}" if version != 4

    # TODO: The size of IV is 15 - LOL, where LOL is the length of length,
    #       the number of bytes required to store the length. Min of 2.
    #       Check on a large blob bigger than 64k.
    iv = encrypted[2, 13]
    ciphertext = encrypted[18..-1]

    # Nothing to decrypt, it's just the tag
    return "" if ciphertext.size == 8

    # openssl-ccm doesn't return an error when the tag doesn't match. It
    # just returns "". So we assume when we get "" it's an error.
    ccm = OpenSSL::CCM.new "AES", key, 8
    plaintext = ccm.decrypt ciphertext, iv
    raise "Decrypt failed" if plaintext == ""

    plaintext
end

def compute_master_key password, salt, encrypted_key
    key = OpenSSL::PKCS5.pbkdf2_hmac password, salt, 10000, 32, "sha512"
    master_key_hex = decrypt_sjcl_aes encrypted_key, key
    [master_key_hex].pack "H*"
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

    # Step 6: Auth FSM -- walk through all the auth steps until we're done
    oauth_token = auth_fsm client_info, whats_next, gui, http

    # Step 7: Get the vault from the server
    vault = get_vault oauth_token, http

    # Step 8: Compute the master key
    master_key = compute_master_key config["password"],
                                    vault["customer/salt"].decode_hex,
                                    vault["customer/k_kek"].d64

    # Step 9: Parse the vault
    decrypt_accounts vault["assets"], master_key
end

def decrypt_accounts accounts, master_key
    accounts.map { |account|
        decrypted = {
                name: account["name"] || "",
            username: account["login"] || "",
            password: "",
                 url: account["url"] || "",
               notes: "",
        }

        encrypted_password = account["password_k"]
        if encrypted_password
            decrypted[:password] = decrypt_sjcl_aes encrypted_password.d64, master_key
        end

        encrypted_notes = account["memo_k"]
        if encrypted_notes
            decrypted[:notes] = decrypt_sjcl_aes encrypted_notes.d64, master_key
        end

        decrypted
    }
end

#
# main
#

# Simple Gui implementation
class TextGui < Gui
    def wait_for_email email
        puts "A verification email is sent to '#{email}'."
        puts "Please check the inbox, confirm and then press enter."
        puts "Enter 'r' to resend the email to '#{email}'."

        case gets.strip
        when "r"
            :resend
        else
            :check
        end
    end

    def wait_for_oob device, email
        puts "A push message is sent to '#{device[:name]}'."
        puts "Please check, confirm and then press enter."
        puts "Enter 'r' to resend the push message to '#{device[:name]}'."
        puts "Enter 'e' to send a verification email to '#{email}' instead."

        case gets.strip
        when "r"
            :resend
        when "e"
            :email
        else
            :check
        end
    end

    def choose_oob devices, email
        loop do
            puts "Please choose the second factor method:"
            devices.each_with_index do |d, i|
                puts " - #{i + 1}: push message to '#{d[:name]}'"
            end
            puts " - e: verification email to '#{email}'"

            case input = gets.strip
            when /\d+/
                index = input.to_i - 1
                return index if index >= 0 && index < devices.size
            when "e"
                return :email
            end

            puts "Invalid input '#{input}'"
        end
    end
end

config = YAML::load_file "config.yaml"
http = Http.new :force_offline
gui = TextGui.new

ap open_vault config, http, gui
