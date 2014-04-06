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

(ns buddy.core.hmac
  "Hash-based Message Authentication Codes (HMACs)"
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.util :refer [concat-byte-arrays]]
            [buddy.core.hash :refer [make-sha512]]
            [clojure.java.io :as io])
  (:import javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec
           java.security.MessageDigest
           java.util.Arrays))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level private function with all logic for make
;; hmac for distinct types.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- make-hmac-for-plain-data
  [^bytes data, pkey, ^String algorithm]
  (let [bkey (->byte-array pkey)
        sks  (SecretKeySpec. bkey algorithm)
        mac  (Mac/getInstance algorithm)]
    (.init mac sks)
    (.doFinal mac data)))

(defn- verify-hmac-for-plain-data
  [^bytes data, ^bytes signature, pkey, ^String algorithm]
  (let [sig (make-hmac-for-plain-data data pkey algorithm)]
    (Arrays/equals sig signature)))

(defn- make-hmac-for-stream
  [^java.io.InputStream stream, pkey, ^String algorithm]
  (let [bkey (->byte-array pkey)
        sks  (SecretKeySpec. bkey algorithm)
        bfr  (byte-array 5120)
        mac  (Mac/getInstance algorithm)]
    (.init mac sks)
    (loop []
      (let [readed (.read stream bfr 0 5120)]
        (when-not (= readed -1)
          (.update mac bfr 0 readed)
          (recur))))
    (.doFinal mac)))

(defn- verify-hmac-for-stream
  [^java.io.InputStream stream, ^bytes signature, pkey, ^String algorithm]
  (let [sig (make-hmac-for-stream stream pkey algorithm)]
    (Arrays/equals sig signature)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level public interface. Works with bytes.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol HMac
  "Unified protocol for calculate a keyed-hash message.
It comes with default implementations for bytes, String,
InputStream, File, URL and URI."
  (make-hmac [data key algorithm] "Calculate hmac for data using key and algorithm.")
  (verify-hmac [data signature key algorithm] "Verify hmac for data using key and algorithm."))

(extend-protocol HMac
  (Class/forName "[B")
  (make-hmac [^bytes data ^String key ^String algorithm]
    (make-hmac-for-plain-data data key algorithm))
  (verify-hmac [^bytes data ^bytes signature ^String key ^String algorithm]
    (verify-hmac-for-plain-data data signature key algorithm))

  java.lang.String
  (make-hmac [^String data ^String key ^String algorithm]
    (make-hmac-for-plain-data (->byte-array data) key algorithm))
  (verify-hmac [^String data ^bytes signature ^String key ^String algorithm]
    (verify-hmac-for-plain-data (->byte-array data) signature key algorithm))

  java.io.InputStream
  (make-hmac [^java.io.InputStream data ^String key ^String algorithm]
    (make-hmac-for-stream data key algorithm))
  (verify-hmac [^java.io.InputStream data ^bytes signature ^String key ^String algorithm]
    (verify-hmac-for-stream data signature key algorithm))

  java.io.File
  (make-hmac [^java.io.File data ^String key ^String algorithm]
    (make-hmac-for-stream (io/input-stream data) key algorithm))
  (verify-hmac [^java.io.File data ^bytes signature ^String key ^String algorithm]
    (verify-hmac-for-stream data signature key algorithm))

  java.net.URL
  (make-hmac [^java.net.URL data ^String key ^String algorithm]
    (make-hmac-for-stream (io/input-stream data) key algorithm))
  (verify-hmac [^java.net.URL data ^bytes signature ^String key ^String algorithm]
    (verify-hmac-for-stream data signature key algorithm))

  java.net.URI
  (make-hmac [^java.net.URI data ^String key ^String algorithm]
    (make-hmac-for-stream (io/input-stream data) key algorithm))
  (verify-hmac [^java.net.URI data ^bytes signature ^String key ^String algorithm]
    (verify-hmac-for-stream data signature key algorithm)))

(defn make-salted-hmac
  "Generic function that implement salted variant
of keyed-hash message authentication code (hmac).
This is a low level function and always return bytes."
  [data ^String key salt ^String algorithm]
  (let [key (concat-byte-arrays (->byte-array key)
                                (->byte-array salt))]
    (make-hmac data (make-sha512 key) algorithm)))

(defn verify-salted-hmac
  [data ^bytes signature ^String key salt ^String algorithm]
  (let [key (concat-byte-arrays (->byte-array key)
                                (->byte-array salt))]
    (verify-hmac data signature (make-sha512 key) algorithm)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level interface. Works with strings.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hmac
  "Generic function that exposes a high level
interface for keyed-hash message authentication
code algorithm."
  [data ^String key ^String algorithm]
  (-> (make-hmac data key algorithm)
      (bytes->hex)))

(defn hmac-verify
  "Generic function that exposes a high level
interface for keyed-hash message authentication
code verification algorithm."
  [data ^String signature ^String key ^String algorithm]
  (verify-hmac data (hex->bytes signature) key algorithm))

(defn salted-hmac
  "Generic function that exposes a high level
interface for salted variant of keyed-hash message
authentication code algorithm."
  [data, key, salt, ^String algorithm]
  (-> (make-salted-hmac data key salt algorithm)
      (bytes->hex)))

(defn salted-hmac-verify
  "Generic function that exposes a high level
interface for salted variant of keyed-hash message
authentication code verification algorithm."
  [data ^String signature ^String key ^String salt ^String algorithm]
  (verify-salted-hmac data signature (hex->bytes signature) key algorithm))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Most used aliases
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Alias for hmac + sha2 hash algorithms
(def hmac-sha256 #(hmac %1 %2 "HmacSHA256"))
(def hmac-sha384 #(hmac %1 %2 "HmacSHA384"))
(def hmac-sha512 #(hmac %1 %2 "HmacSHA512"))
(def hmac-sha256-verify #(hmac-verify %1 %2 %3 "HmacSHA256"))
(def hmac-sha384-verify #(hmac-verify %1 %2 %3 "HmacSHA384"))
(def hmac-sha512-verify #(hmac-verify %1 %2 %3 "HmacSHA512"))

;; Alias for salted hmac + sha2 hash algorithms
(def salted-hmac-sha256 #(salted-hmac %1 %2 %3 "HmacSHA256"))
(def salted-hmac-sha384 #(salted-hmac %1 %2 %3 "HmacSHA384"))
(def salted-hmac-sha512 #(salted-hmac %1 %2 %3 "HmacSHA512"))
(def salted-hmac-sha256-verify #(salted-hmac-verify %1 %2 %3 %4 "HmacSHA256"))
(def salted-hmac-sha384-verify #(salted-hmac-verify %1 %2 %3 %4 "HmacSHA384"))
(def salted-hmac-sha512-verify #(salted-hmac-verify %1 %2 %3 %4 "HmacSHA512"))
