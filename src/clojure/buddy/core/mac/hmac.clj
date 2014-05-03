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

(ns buddy.core.mac.hmac
  "Hash-based Message Authentication Codes (HMACs)"
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.hash :as hash]
            [clojure.java.io :as io])
  (:import org.bouncycastle.crypto.macs.HMac
           org.bouncycastle.crypto.Mac
           org.bouncycastle.crypto.params.KeyParameter
           clojure.lang.Keyword
           buddy.Arrays))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level private function with all logic for make
;; hmac for distinct types.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- make-hmac-for-plain-data
  [^bytes input, pkey, ^Keyword alg]
  (let [digest (hash/resolve-digest alg)
        kp     (KeyParameter. (->byte-array pkey))
        mac    (HMac. digest)
        buffer (byte-array (.getMacSize mac))]
    (doto mac
      (.init kp)
      (.update input 0 (count input))
      (.doFinal buffer 0))
    buffer))

(defn- verify-hmac-for-plain-data
  [^bytes input, ^bytes signature, pkey, ^Keyword alg]
  (let [sig (make-hmac-for-plain-data input pkey alg)]
    (Arrays/equals sig signature)))

(defn- make-hmac-for-stream
  [^java.io.InputStream input, pkey, ^Keyword alg]
  (let [digest  (hash/resolve-digest alg)
        kp      (KeyParameter. (->byte-array pkey))
        mac     (HMac. digest)
        buffer1 (byte-array 5120)
        buffer2 (byte-array (.getMacSize mac))]
    (.init mac kp)
    (loop []
      (let [readed (.read input buffer1 0 5120)]
        (when-not (= readed -1)
          (.update mac buffer1 0 readed)
          (recur))))
    (.doFinal mac buffer2 0)
    buffer2))

(defn- verify-hmac-for-stream
  [^java.io.InputStream input, ^bytes signature, pkey, ^Keyword alg]
  (let [sig (make-hmac-for-stream input pkey alg)]
    (Arrays/equals sig signature)))

(defprotocol HMacType
  "Unified protocol for calculate a keyed-hash message.
It comes with default implementations for bytes, String,
InputStream, File, URL and URI."
  (make-hmac [data key alg] "Calculate hmac for input using key and alg.")
  (verify-hmac [data signature key alg] "Verify hmac for input using key and alg."))

(alter-meta! #'make-hmac assoc :no-doc true :private true)
(alter-meta! #'verify-hmac assoc :no-doc true :private true)

(extend-protocol HMacType
  (Class/forName "[B")
  (make-hmac [^bytes input key ^Keyword alg]
    (make-hmac-for-plain-data input key alg))
  (verify-hmac [^bytes input ^bytes signature ^String key ^Keyword alg]
    (verify-hmac-for-plain-data input signature key alg))

  java.lang.String
  (make-hmac [^String input key ^Keyword alg]
    (make-hmac-for-plain-data (->byte-array input) key alg))
  (verify-hmac [^String input ^bytes signature ^String key ^Keyword alg]
    (verify-hmac-for-plain-data (->byte-array input) signature key alg))

  java.io.InputStream
  (make-hmac [^java.io.InputStream input key ^Keyword alg]
    (make-hmac-for-stream input key alg))
  (verify-hmac [^java.io.InputStream input ^bytes signature ^String key ^Keyword alg]
    (verify-hmac-for-stream input signature key alg))

  java.io.File
  (make-hmac [^java.io.File input key ^Keyword alg]
    (make-hmac-for-stream (io/input-stream input) key alg))
  (verify-hmac [^java.io.File input ^bytes signature ^String key ^Keyword alg]
    (verify-hmac-for-stream (io/input-stream input) signature key alg))

  java.net.URL
  (make-hmac [^java.net.URL input key ^Keyword alg]
    (make-hmac-for-stream (io/input-stream input) key alg))
  (verify-hmac [^java.net.URL input ^bytes signature ^String key ^Keyword alg]
    (verify-hmac-for-stream (io/input-stream input) signature key alg))

  java.net.URI
  (make-hmac [^java.net.URI input key ^Keyword alg]
    (make-hmac-for-stream (io/input-stream input) key alg))
  (verify-hmac [^java.net.URI input ^bytes signature ^String key ^Keyword alg]
    (verify-hmac-for-stream (io/input-stream input) signature key alg)))

(defn- make-salted-hmac
  "Generic function that implement salted variant
of keyed-hash message authentication code (hmac).
This is a low level function and always return bytes."
  [input key salt ^Keyword alg]
  (let [key (concat-byte-arrays (->byte-array key)
                                (->byte-array salt))]
    (make-hmac input (hash/sha512 key) alg)))

(defn- verify-salted-hmac
  [input ^bytes signature key salt ^Keyword alg]
  (let [key (concat-byte-arrays (->byte-array key)
                                (->byte-array salt))]
    (verify-hmac input signature (hash/sha512 key) alg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hmac
  [input key ^Keyword alg]
  (make-hmac input key alg))

(defn hmac-verify
  [input ^bytes signature key ^Keyword alg]
  (verify-hmac input signature key alg))

(defn shmac
  "Generic function that exposes a high level
interface for salted variant of keyed-hash message
authentication code algorithm."
  [input key salt ^Keyword alg]
  (make-salted-hmac input key salt alg))

(defn shmac-verify
  "Generic function that exposes a high level
interface for salted variant of keyed-hash message
authentication code verification algorithm."
  [input ^bytes signature key salt ^Keyword alg]
  (verify-salted-hmac input signature key salt alg))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Most used aliases
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Alias for hmac + sha2 hash algorithms
(def hmac-sha256 #(hmac %1 %2 :sha256))
(def hmac-sha384 #(hmac %1 %2 :sha384))
(def hmac-sha512 #(hmac %1 %2 :sha512))
(def hmac-sha256-verify #(hmac-verify %1 %2 %3 :sha256))
(def hmac-sha384-verify #(hmac-verify %1 %2 %3 :sha384))
(def hmac-sha512-verify #(hmac-verify %1 %2 %3 :sha512))

;; Alias for salted hmac + sha2 hash algorithms
(def shmac-sha256 #(shmac %1 %2 %3 :sha256))
(def shmac-sha384 #(shmac %1 %2 %3 :sha384))
(def shmac-sha512 #(shmac %1 %2 %3 :sha512))
(def shmac-sha256-verify #(shmac-verify %1 %2 %3 %4 :sha256))
(def shmac-sha384-verify #(shmac-verify %1 %2 %3 %4 :sha384))
(def shmac-sha512-verify #(shmac-verify %1 %2 %3 %4 :sha512))
