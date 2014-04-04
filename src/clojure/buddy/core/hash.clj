(ns buddy.core.hash
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.core.codecs :refer :all]
            [clojure.java.io :as io])
  (:import (java.security MessageDigest)))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defprotocol Digest
  (make-digest [data algorithm] "Low level interface, always returns bytes"))

(extend-protocol Digest
  (Class/forName "[B")
  (make-digest [data algorithm]
    (let [md (MessageDigest/getInstance algorithm)]
      (.update md data)
      (.digest md)))

  String
  (make-digest [data algorithm]
    (make-digest (->byte-array data) algorithm))

  java.io.InputStream
  (make-digest [data algorithm]
    (let [md (MessageDigest/getInstance algorithm)
          bf (byte-array 5120)]
      (loop []
        (let [readed (.read data bf 0 5120)]
          (when-not (= readed -1)
            (.update md bf 0 readed)
            (recur))))
      (.digest md)))

  java.io.File
  (make-digest [data algorithm]
    (make-digest (io/input-stream data) algorithm))

  java.net.URL
  (make-digest [data algorithm]
    (make-digest (io/input-stream data) algorithm))

  java.net.URI
  (make-digest [data algorithm]
    (make-digest (io/input-stream data) algorithm)))

(defn digest
  "Generic function for create cryptographic hash. Given an algorithm
and any data that implements `Digest` protocol, return hex encoded
hash result."
  [data algorithm]
  (bytes->hex (make-digest data algorithm)))

;; Alias for low level interface for all supported
;; secure hash algorithms. All of them return alway
;; array of bytes.
(def make-sha256 #(make-digest % "SHA-256"))
(def make-sha384 #(make-digest % "SHA-384"))
(def make-sha512 #(make-digest % "SHA-512"))
(def make-sha3-256 #(make-digest % "SHA3-256"))
(def make-sha3-384 #(make-digest % "SHA3-384"))
(def make-sha3-512 #(make-digest % "SHA3-256"))
(def make-sha1 #(make-digest % "SHA-1"))
(def make-md5 #(make-digest % "MD5"))

;; Alias of same secure hash algorithms previously
;; defined but return human readable hex encoded output.
(def sha256 #(digest % "SHA-256"))
(def sha384 #(digest % "SHA-384"))
(def sha512 #(digest % "SHA-512"))
(def sha3-256 #(digest % "SHA3-256"))
(def sha3-384 #(digest % "SHA3-384"))
(def sha3-512 #(digest % "SHA3-256"))
(def sha1 #(digest % "SHA-1"))
(def md5 #(digest % "MD5"))

