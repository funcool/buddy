;; Copyright 2014 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.sign.generic
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.hmac :refer [hmac-sha256]]
            [buddy.core.hmac :as hmac]
            [buddy.core.sign :as sign]
            [clojure.string :as str]
            [taoensso.nippy :as nippy]))

(def ^{:doc "List of supported signing algorithms"
       :static true}
  signers-map {:hs256 {:signer (comp bytes->safebase64 hmac/hmac-sha256)
                       :verifier #(hmac/hmac-sha256-verify %1 (safebase64->bytes %2) %3)}
               :hs512 {:signer (comp bytes->safebase64 hmac/hmac-sha512)
                       :verifier #(hmac/hmac-sha512-verify %1 (safebase64->bytes %2) %3)}
               :rs256 {:signer (comp bytes->safebase64 sign/rsassa-pkcs-sha256)
                       :verifier #(sign/rsassa-pkcs-sha256-verify %1 (safebase64->bytes %2) %3)}
               :rs512 {:signer (comp bytes->safebase64 sign/rsassa-pkcs-sha512)
                       :verifier #(sign/rsassa-pkcs-sha512-verify %1 (safebase64->bytes %2) %3)}
               :ps256 {:signer (comp bytes->safebase64 sign/rsassa-pss-sha256)
                       :verifier #(sign/rsassa-pss-sha256-verify %1 (safebase64->bytes %2) %3)}
               :ps512 {:signer (comp bytes->safebase64 sign/rsassa-pss-sha512)
                       :verifier #(sign/rsassa-pss-sha512-verify %1 (safebase64->bytes %2) %3)}
               :es256 {:signer (comp bytes->safebase64 sign/ecdsa-sha256)
                       :verifier #(sign/ecdsa-sha256-verify %1 (safebase64->bytes %2) %3)}
               :es512 {:signer (comp bytes->safebase64 sign/ecdsa-sha512)
                       :verifier #(sign/ecdsa-sha512-verify %1 (safebase64->bytes %2) %3)}})

(defn timestamp-millis
  "Get current timestamp in millis."
  []
  (System/currentTimeMillis))

(defn- make-signature
  [s pkey alg]
  (let [signer (get-in signers-map [alg :signer])]
    (when-not signer
      (throw (RuntimeException. (str "No signer found for algorithm: " (name alg)))))
    (signer s pkey)))

(defn- verify-signature
  [s signature pkey alg]
  (let [verifier (get-in signers-map [alg :verifier])]
    (when-not verifier
      (throw (RuntimeException. (str "No verifier found for algorithm: " (name alg)))))
    (verifier s signature pkey)))

(defn- make-stamped-signature
  [s pkey alg sep stamp]
  (let [candidate (str s sep stamp)
        signature (make-signature candidate pkey alg)]
    (str/join sep [signature stamp])))

(defn sign
  "Given a string and secret key,
  return a signed and prefixed string."
  ([s, pkey & [{:keys [sep alg]
                :or {sep ":" alg :hs256}
                :as opts}]]
   (let [stamp     (str->safebase64 (str (timestamp-millis)))
         signature (make-stamped-signature s pkey alg sep stamp)]
     (str/join sep [s signature (name alg)]))))

(defn unsign
  "Given a signed string and private key with string
  was preoviously signed and return unsigned value
  if the signature is valed else nil."
  [s pkey & [{:keys [sep max-age alg]
               :or {sep ":" max-age nil alg :hs256}}]]
  (let [[value sig stamp] (str/split s (re-pattern sep))
        candidate (str value sep stamp)]
    (when (verify-signature candidate sig pkey alg)
      (if-not (nil? max-age)
        (let [old-stamp-value (Long/parseLong (safebase64->str stamp))
              age             (- (timestamp-millis) old-stamp-value)]
          (if (> age (* max-age 1000)) nil value))
        value))))

(defn dumps
  "Sign a complex data strucutres using
  serialization as intermediate step."
  [data & args]
  (let [encoded (bytes->base64 (nippy/freeze data))]
    (apply sign encoded (vec args))))

(defn loads
  "Unsign data signed with dumps."
  [s & args]
  (let [unsigned (apply unsign s (vec args))]
    (when-not (nil? unsigned)
      (nippy/thaw (base64->bytes unsigned)))))
