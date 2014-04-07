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

(alter-meta! #'make-digest assoc :no-doc true :private true)

(extend-protocol Digest
  (Class/forName "[B")
  (make-digest [^bytes data ^String algorithm]
    (let [md (MessageDigest/getInstance algorithm)]
      (.update md data)
      (.digest md)))

  String
  (make-digest [^String data ^String algorithm]
    (make-digest (->byte-array data) algorithm))

  java.io.InputStream
  (make-digest [^java.io.InputStream data ^String algorithm]
    (let [md (MessageDigest/getInstance algorithm)
          bf (byte-array 5120)]
      (loop []
        (let [readed (.read data bf 0 5120)]
          (when-not (= readed -1)
            (.update md bf 0 readed)
            (recur))))
      (.digest md)))

  java.io.File
  (make-digest [^java.io.File data ^String algorithm]
    (make-digest (io/input-stream data) algorithm))

  java.net.URL
  (make-digest [^java.net.URL data ^String algorithm]
    (make-digest (io/input-stream data) algorithm))

  java.net.URI
  (make-digest [^java.net.URI data ^String algorithm]
    (make-digest (io/input-stream data) algorithm)))

(defn digest
  "Generic function for create cryptographic hash."
  [data ^String algorithm]
  (make-digest data algorithm))

(def sha256 #(digest % "SHA-256"))
(def sha384 #(digest % "SHA-384"))
(def sha512 #(digest % "SHA-512"))
(def sha3-256 #(digest % "SHA3-256"))
(def sha3-384 #(digest % "SHA3-384"))
(def sha3-512 #(digest % "SHA3-256"))
(def sha1 #(digest % "SHA-1"))
(def md5 #(digest % "MD5"))

