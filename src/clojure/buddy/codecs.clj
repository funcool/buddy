(ns buddy.codecs
  "Util functions for make conversion between string, bytes
and encode them to base64 ot hex format."
  (:require [clojure.string :refer [trim]])
  (:import (org.apache.commons.codec.binary Base64 Hex)))

(defn bytes?
  "Test if a first parameter is a byte
  array or not."
  [^Object x]
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
  "Encode a bytes array to base64
and return utf8 string."
  [#^bytes data]
  (Base64/encodeBase64URLSafeString data))

(defn bytes->bbase64
  "Encode a bytes array to base64 and
return bytearray."
  [#^bytes data]
  (Base64/encodeBase64URLSafe data))

(defn base64->bytes
  "Decode from base64 to bytes."
  [s]
  (Base64/decodeBase64 s))

(defn str->base64
  "Encode to urlsafe base64."
  [^String s]
  (-> (str->bytes s)
      (Base64/encodeBase64URLSafeString)
      (trim)))

(defn base64->str
  "Decode from base64 to string."
  [^String s]
  (String. (base64->bytes s) "UTF8"))
