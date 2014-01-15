(ns buddy.crypto.core
  (:import (org.apache.commons.codec.binary Base64 Hex)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)
           (java.security MessageDigest)))

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

(defn bytes->base64
  "Encode a bytes array to base64."
  [#^bytes data]
  (let [codec (Base64. true)]
    (.encodeToString codec data)))

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
    (.encodeToString codec data)))

(defn base64->str
  "Decode from base64 to string."
  [^String s]
  (let [codec (Base64. true)
        data  (.decode codec s)]
    (bytes->str data)))

(defn hmac-sha256
  "Returns a salted hmac-sha256."
  [value secret & [{:keys [salt] :or {salt ""}}]]
  (let [md  (doto (MessageDigest/getInstance "SHA-256")
              (.update (str->bytes secret))
              (.update (str->bytes salt)))
        mac (doto (Mac/getInstance "HmacSHA256")
              (.init (SecretKeySpec. (.digest md) "HmacSHA256")))]
    (->
      (.doFinal mac (str->bytes value))
      (bytes->hex))))

(defn timestamp
  "Get current timestamp."
  []
  (quot (System/currentTimeMillis) 1000))
