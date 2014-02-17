(ns buddy.core.hash
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.core.codecs :refer :all])
  (:import (java.security MessageDigest)))

(defn digest
  "Generic function for create cryptographic hash. Given an algorithm
name and many parts of any type that implements ByteArray protocol,
return a computed hash as byte array. This function hides java api
to `java.security.MessageDigest`"
  [algorithm & parts]
  (let [md (MessageDigest/getInstance algorithm)]
    (doseq [part parts]
      (.update md (->byte-array part)))
    (.digest md)))

;; Alias for low level interface for all supported
;; secure hash algorithms. All of them return alway
;; array of bytes.
(def make-sha256 (partial digest "SHA-256"))
(def make-sha384 (partial digest "SHA-384"))
(def make-sha512 (partial digest "SHA-512"))
(def make-sha1 (partial digest "SHA-1"))
(def make-md5 (partial digest "MD5"))

;; Alias of same secure hash algorithms previously
;; defined but return human readable hexadecimal
;; encoded output.
(def sha256 (comp bytes->hex make-sha256))
(def sha384 (comp bytes->hex make-sha384))
(def sha512 (comp bytes->hex make-sha512))
(def sha1 (comp bytes->hex make-sha1))
(def md5 (comp bytes->hex make-md5))
