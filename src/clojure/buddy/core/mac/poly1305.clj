(ns buddy.core.mac.poly1305
  "Poly1305-AES is a cryptographic message authentication code
(MAC) written by Daniel J. Bernstein. It can be used to verify the
data integrity and the authenticity of a message.

The security of Poly1305-AES is very close to the underlying AES
block cipher algorithm. As a result, the only way for an attacker
to break Poly1305-AES is to break AES.

Poly1305-AES offers also cipher replaceability. If anything does
go wrong with AES, it can be substituted with identical security
guarantee."
  (:import org.bouncycastle.crypto.generators.Poly1305KeyGenerator
           org.bouncycastle.crypto.macs.Poly1305
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.params.ParametersWithIV
           org.bouncycastle.crypto.engines.AESFastEngine
           java.security.SecureRandom
           java.util.Arrays)
  (:require [buddy.core.hash :refer [sha3-256]]
            [buddy.core.codecs :refer :all]
            [clojure.java.io :as io]))

(defprotocol Poly1305KeyType
  "Defines unform access to poly 1305 formatted key."
  (key->bytes [obj] "Get 32 bytes array formated for poly1305.")
  (key->iv [obj] "Get 128bit (16 bytes) iv for encryption engine."))

(defprotocol KeyConstructor
  "Poly1305 key constructor defined as protocol
for easy extensibility for different types."
  (make-key [obj] "Build poly 1305 key instance from type."))

;; Simple data structure for represent the buddy
;; representation of poly 1305 key.
(defrecord Key [key iv])

(alter-meta! #'key->bytes assoc :no-doc true :private true)
(alter-meta! #'key->iv assoc :no-doc true :private true)
(alter-meta! #'->Key assoc :no-doc true :private true)
(alter-meta! #'map->Key assoc :no-doc true :private true)

;; Constructor implementations

(extend-protocol KeyConstructor
  java.lang.String
  (make-key [self]
    (let [bkey (sha3-256 self)
          iv   (byte-array 16)]
      (doto (SecureRandom.)
        (.nextBytes iv))
      (Poly1305KeyGenerator/clamp bkey)
      (->Key bkey iv))))

;; Conversion implementations

(extend-protocol Poly1305KeyType
  ;; Default implementation of type converter for String.
  ;; This generates:
  ;;
  ;; - a poly 1305 formatted key from string
  ;; - a 0 filled iv 16 bytes array.
  ;;
  ;; Mainly used when poly1305 mac is used with
  ;; string as key argument. If you want stronguest security
  ;; build poly 1305 key previously with corresponding
  ;; constructor instead of using string key directly.

  java.lang.String
  (key->bytes [self]
    (let [key (sha3-256 self)]
      (Poly1305KeyGenerator/clamp key)
      key))
  (key->iv [self]
    (byte-array 16))

  ;; Default implementation of type converter for Key.
  ;; This does nothing, simple return Key instance values.

  Key
  (key->bytes [self]
    (:key self))
  (key->iv [self]
    (:iv self)))

;; Algorithm implementation

(defn- make-poly1305-plain-impl
  [data pkey]
  (let [bkey (key->bytes pkey)
        iv   (key->iv pkey)
        mac  (Poly1305. (AESFastEngine.))
        out  (byte-array 16)
        kp   (KeyParameter. bkey)
        pwi  (ParametersWithIV. kp iv)]
    (doto mac
      (.init pwi)
      (.update data 0 (count data))
      (.doFinal out 0))
    out))

(defn- make-poly1305-stream-impl
  [stream pkey]
  (let [bkey (key->bytes pkey)
        iv   (key->iv pkey)
        mac  (Poly1305. (AESFastEngine.))
        out  (byte-array 16)
        kp   (KeyParameter. bkey)
        pwi  (ParametersWithIV. kp iv)
        bfr  (byte-array 5120)]
    (.init mac pwi)
    (loop []
      (let [readed (.read stream bfr 0 5120)]
        (when-not (= readed -1)
          (.update mac bfr 0 readed)
          (recur))))
    (.doFinal mac out 0)
    out))

(declare make-poly1305)

(defn- verify-poly1305-impl
  [data signature pkey]
  (let [sig (make-poly1305 data pkey)]
    (Arrays/equals sig signature)))

(defprotocol Poly1305Mac
  "Protocol that defines a low level interface
to poly 1305 algorithm and allows extend it for
different types.
It comes with default implementation for: string,
bytes, input stream, file, url and uri."
  (make-poly1305 [obj key] "Calculate poly1305 mac for type.")
  (verify-poly1305 [obj key] "Verify poly1305 mac for type."))

(extend-protocol Poly1305Mac
  (Class/forName "[B")
  (make-poly1305 [^bytes data ^String key]
    (make-poly1305-plain-impl data key))
  (verify-poly1305 [^bytes data ^bytes signature ^String key]
    (verify-poly1305-impl data signature key))

  java.lang.String
  (make-poly1305 [^String data ^String key]
    (make-poly1305-plain-impl (->byte-array data) key))
  (verify-poly1305 [^String data ^bytes signature ^String key]
    (verify-poly1305-impl (->byte-array data) signature key))

  java.io.InputStream
  (make-poly1305 [^java.io.InputStream data ^String key]
    (make-poly1305-stream-impl data key))
  (verify-poly1305 [^java.io.InputStream data ^bytes signature ^String key]
    (verify-poly1305-impl data signature key))

  java.io.File
  (make-poly1305 [^java.io.File data ^String key]
    (make-poly1305-stream-impl (io/input-stream data) key))
  (verify-poly1305 [^java.io.File data ^bytes signature ^String key]
    (verify-poly1305-impl (io/input-stream data) signature key))

  java.net.URL
  (make-poly1305 [^java.net.URL data ^String key]
    (make-poly1305-stream-impl (io/input-stream data) key))
  (verify-poly1305 [^java.net.URL data ^bytes signature ^String key]
    (verify-poly1305-impl (io/input-stream data) signature key))

  java.net.URI
  (make-poly1305 [^java.net.URI data ^String key]
    (make-poly1305-stream-impl (io/input-stream data) key))
  (verify-poly1305 [^java.net.URI data ^bytes signature ^String key]
    (verify-poly1305-impl (io/input-stream data) signature key)))
