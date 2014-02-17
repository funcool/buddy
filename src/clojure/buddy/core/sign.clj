;; Copyright 2013 Andrey Antukh <niwi@niwi.be>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.core.sign
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.hash :refer [make-sha512]]
            [buddy.core.keys :as keys])
  (:import (org.apache.commons.codec.binary Base64 Hex)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)
           (java.security MessageDigest SecureRandom)))

(defn hmac
  "Generic function that implement salted variant
of keyed-hash message authentication code (hmac)."
  [algorithm value pkey & [{:keys [salt] :or {salt ""}}]]
  (let [salt  (->byte-array salt)
        sks   (SecretKeySpec. (make-sha512 (keys/key->bytes pkey) salt) "HmacSHA512")
        mac   (doto (Mac/getInstance "HmacSHA256")
                (.init sks))]
    (.doFinal mac (str->bytes value))))

(def ^{:doc "Function that implements the HMAC algorithm with SHA256 digest mode."}
  hmac-sha256 (partial hmac "HmacSHA256"))

(def ^{:doc "Function that implements the HMAC algorithm with SHA384 digest mode."}
  hmac-sha384 (partial hmac "HmacSHA384"))

(def ^{:doc "Function that implements the HMAC algorithm with SHA512 digest mode."}
  hmac-sha512 (partial hmac "HmacSHA512"))

