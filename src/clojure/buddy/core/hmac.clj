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

(ns buddy.core.hmac
  "Hash-based Message Authentication Codes (HMACs)"
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.hash :refer [make-sha512]]
            [buddy.core.keys :as keys])
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)
           (java.security MessageDigest)))

(defn hmac
  "Generic function that implement salted variant
of keyed-hash message authentication code (hmac)."
  [^String algorithm, ^bytes value, pkey & [{:keys [salt] :or {salt ""}}]]
  (let [sks   (SecretKeySpec. (make-sha512 (keys/key->bytes pkey) salt) algorithm)
        mac   (doto (Mac/getInstance algorithm)
                (.init sks))]
    (.doFinal mac (->byte-array value))))

;; Alias for hmac + sha-2 hash algorithms
(def hmac-sha256 (partial hmac "HmacSHA256"))
(def hmac-sha384 (partial hmac "HmacSHA384"))
(def hmac-sha512 (partial hmac "HmacSHA512"))
