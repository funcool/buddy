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

(ns buddy.crypto.core
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [clojure.string :refer [trim]])
  (:import (org.apache.commons.codec.binary Base64 Hex)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)
           (java.security MessageDigest SecureRandom)))

(defn bytes?
  "Test if a first parameter is a byte
  array or not."
  [x]
  (= (Class/forName "[B")
    (.getClass x)))

(defn str->bytes
  "Convert string to java bytes array"
  ([^String s]
   (str->bytes s "UTF-8"))
  ([^String s, ^String encoding]
   (.getBytes s encoding)))

(defn bytes->str
  "Convert octets to String."
  ([data]
   (bytes->str data "UTF-8"))
  ([#^bytes data, ^String encoding]
   (String. data encoding)))

(defn bytes->hex
  "Convert a byte array to hex
  encoded string."
  [#^bytes data]
  (Hex/encodeHexString data))

(defn hex->bytes
  "Convert hexadecimal encoded string
  to bytes array."
  [^String data]
  (Hex/decodeHex (.toCharArray data)))

(defn bytes->base64
  "Encode a bytes array to base64."
  [#^bytes data]
  (let [codec (Base64. true)]
    (trim (.encodeToString codec data))))

(defn base64->bytes
  "Decode from base64 to bytes."
  [^String s]
  (let [codec (Base64. true)
        data  (.decode codec s)]
    data))

(defn str->base64
  "Encode to urlsafe base64."
  [^String s]
  (let [codec (Base64. true)
        data  (str->bytes s)]
    (trim (.encodeToString codec data))))

(defn base64->str
  "Decode from base64 to string."
  [^String s]
  (let [codec (Base64. true)
        data  (.decode codec s)]
    (bytes->str data)))

(defn hmac-sha256
  "Returns a salted hmac-sha256."
  [value secret & [{:keys [salt] :or {salt ""}}]]
  (let [salt  (cond
                (bytes? salt) salt
                (string? salt) (str->bytes salt)
                :else (throw (IllegalArgumentException. "invalid salt type")))
        md    (doto (MessageDigest/getInstance "SHA-256")
                (.update (str->bytes secret))
                (.update salt))
        mac   (doto (Mac/getInstance "HmacSHA256")
                (.init (SecretKeySpec. (.digest md) "HmacSHA256")))]
    (->
      (.doFinal mac (str->bytes value))
      (bytes->hex))))

(defn random-bytes
  "Generate a byte array of random bytes using
  secure random generator."
  [s]
  (let [data  (byte-array s)
        sr    (SecureRandom/getInstance "SHA1PRNG")]
    (.nextBytes sr data)
    data))

(defn random-salt
  "Generates a random salt using a secure
  random number generator."
  ([] (random-salt 8))
  ([s]
   (let [rbytes (random-bytes (int (/ s 2)))]
     (bytes->hex rbytes))))

(defn timestamp
  "Get current timestamp."
  []
  (quot (System/currentTimeMillis) 1000))
