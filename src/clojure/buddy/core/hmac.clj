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
            [buddy.core.util :refer [concat-byte-arrays]]
            [buddy.core.hash :refer [make-sha512]]
            [clojure.java.io :as io])
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)
           (java.security MessageDigest)))

(defprotocol HMac
  "Defined unified protocol for calculate a
keyed-hash message for a concrete type. It comes
with default implementations for bytes, String,
InputStream, File, URL and URI."
  (make-hmac [data key algorithm] "Low level interface for make HMAC"))

(extend-protocol HMac
  (Class/forName "[B")
  (make-hmac [data key algorithm]
    (let [bkey (->byte-array key)
          sks  (SecretKeySpec. bkey algorithm)
          mac  (Mac/getInstance algorithm)]
      (.init mac sks)
      (.doFinal mac data)))

  String
  (make-hmac [data key algorithm]
    (make-hmac (->byte-array data) key algorithm))

  java.io.InputStream
  (make-hmac [data key algorithm]
    (let [bkey (->byte-array key)
          sks  (SecretKeySpec. bkey algorithm)
          bfr  (byte-array 5120)
          mac  (Mac/getInstance algorithm)]
      (.init mac sks)
      (loop []
        (let [readed (.read data bfr 0 5120)]
          (when-not (= readed -1)
            (.update mac bfr 0 readed)
            (recur))))
      (.doFinal mac)))

  java.io.File
  (make-hmac [data key algorithm]
    (make-hmac (io/input-stream data) key algorithm))

  java.net.URL
  (make-hmac [data key algorithm]
    (make-hmac (io/input-stream data) key algorithm))

  java.net.URI
  (make-hmac [data key algorithm]
    (make-hmac (io/input-stream data) key algorithm)))

(defn make-salted-hmac
  "Generic function that implement salted variant
of keyed-hash message authentication code (hmac).
This is a low level function and always return bytes."
  [data key salt algorithm]
  (let [key (concat-byte-arrays (->byte-array key)
                                (->byte-array salt))]
    (make-hmac data (make-sha512 key) algorithm)))

(defn hmac
  "Generic function that exposes a high level
interface for keyed-hash message authentication
code algorithm."
  [data, key, ^String algorithm]
  (-> (make-hmac data key algorithm)
      (bytes->hex)))

(defn salted-hmac
  "Generic function that exposes a high level
interface for salted variant of keyed-hash message
authentication code algorithm."
  [data, key, salt, ^String algorithm]
  (-> (make-salted-hmac data key salt algorithm)
      (bytes->hex)))

;; Alias for hmac + sha-2 hash algorithms
(def hmac-sha256 #(hmac %1 %2 "HmacSHA256"))
(def hmac-sha384 #(hmac %1 %2 "HmacSHA384"))
(def hmac-sha512 #(hmac %1 %2 "HmacSHA512"))

;; Alias for salted hmac + sha-2 hash algorithms
(def salted-hmac-sha256 #(salted-hmac %1 %2 %3 "HmacSHA256"))
(def salted-hmac-sha384 #(salted-hmac %1 %2 %3 "HmacSHA384"))
(def salted-hmac-sha512 #(salted-hmac %1 %2 %3 "HmacSHA512"))
