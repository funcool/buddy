;; Copyright (c) 2014 Andrey Antukh <niwi@niwi.be>
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
            [buddy.core.keys :refer :all]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.sign.rsapss :as rsapss]
            [buddy.core.sign.rsapkcs15 :as rsapkcs]
            [buddy.core.sign.ecdsa :as ecdsa]
            [buddy.util :refer [maybe-let]]
            [clojure.string :as str]
            [taoensso.nippy :as nippy])
  (:import clojure.lang.Keyword))

(def ^{:doc "List of supported signing algorithms"
       :dynamic true}
  *signers-map* {:hs256 {:signer   #(hmac/hmac %1 %2 :sha256)
                         :verifier #(hmac/verify %1 %2 %3 :sha256)}
                 :hs512 {:signer   #(hmac/hmac %1 %2 :sha512)
                         :verifier #(hmac/verify %1 %2 %3 :sha512)}
                 :rs256 {:signer   #(rsapkcs/rsapkcs15 %1 %2 :sha256)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha256)}
                 :rs512 {:signer   #(rsapkcs/rsapkcs15 %1 %2 :sha512)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha512)}
                 :ps256 {:signer   #(rsapss/rsapss %1 %2 :sha256)
                         :verifier #(rsapss/verify %1 %2 %3 :sha256)}
                 :ps512 {:signer   #(rsapss/rsapss %1 %2 :sha512)
                         :verifier #(rsapss/verify %1 %2 %3 :sha512)}
                 :es256 {:signer   #(ecdsa/ecdsa %1 %2 :sha256)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha256)}
                 :es512 {:signer   #(ecdsa/ecdsa %1 %2 :sha512)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha512)}})

(defn timestamp-millis
  "Get current timestamp in millis."
  []
  (System/currentTimeMillis))

(defn- make-signature
  "Make timestamped signature"
  [^bytes input ^bytes pkey ^bytes salt ^bytes stamp ^Keyword alg]
  (maybe-let [signer (get-in *signers-map* [alg :signer])
              input  (concat-byte-arrays input salt stamp)]
    (signer input pkey)))

(defn- verify-signature
  [^bytes input ^bytes signature ^bytes pkey ^bytes salt ^bytes stamp ^Keyword alg]
  (maybe-let [verifier (get-in *signers-map* [alg :verifier])
              input    (concat-byte-arrays input salt stamp)]
    (verifier input signature pkey)))

(defn sign
  "Sign arbitrary length string/byte array."
  [^String input pkey & [{:keys [sep alg]
                                  :or {sep ":" alg :hs256}}]]
  {:pre [(alg *signers-map*)]}
  (maybe-let [input (->byte-array input)
              salt  (make-random-bytes 8)
              stamp (long->bytes (timestamp-millis))
              s     (make-signature input pkey salt stamp alg)]
    (str/join sep [(bytes->safebase64 input)
                   (bytes->safebase64 s)
                   (bytes->safebase64 salt)
                   (bytes->safebase64 stamp)])))

(defn unsign
  [^String input, pkey & [{:keys [sep alg max-age]
                           :or {sep ":" alg :hs256}}]]
  {:pre [(alg *signers-map*)]}
  (let [[input signature salt stamp] (str/split input (re-pattern sep))]
    (maybe-let [input     (when input (safebase64->bytes input))
                signature (when signature (safebase64->bytes signature))
                stamp     (when stamp (safebase64->bytes stamp))
                salt      (when salt (safebase64->bytes salt))]
      (when (verify-signature input signature pkey salt stamp alg)
        (if (nil? max-age)
          (bytes->str input)
          (let [oldstamp (bytes->long stamp)
                newstamp (timestamp-millis)
                age      (- newstamp oldstamp)]
            (if (> age (* max-age 1000)) nil (bytes->str input))))))))

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
