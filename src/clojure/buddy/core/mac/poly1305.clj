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
           org.bouncycastle.crypto.engines.SerpentEngine
           org.bouncycastle.crypto.engines.TwofishEngine
           org.bouncycastle.crypto.BlockCipher
           clojure.lang.IFn
           clojure.lang.Keyword
           buddy.Arrays)
  (:require [buddy.core.hash :refer [sha3-256]]
            [buddy.core.codecs :refer :all]
            [buddy.core.keys :refer [make-random-bytes]]
            [clojure.java.io :as io]))

(def ^{:doc "Default engine factories."
       :dynamic true}
  *available-engines* {:aes     #(AESFastEngine.)
                       :serpent #(SerpentEngine.)
                       :twofish #(TwofishEngine.)})

(defn resolve-engine
  "Given dynamic type engine, try resolve it to
valid engine instance. By default accepts keywords
and functions."
  [engine]
  (cond
   (instance? Keyword engine) (let [factory (engine *available-engines*)]
                                (factory))
   (instance? IFn engine) (engine)
   (instance? BlockCipher engine) engine))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Internal implementations
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn key->poly1305key
  "Noramalizes any length byte array key to poly1305
formatted byte array key.
It uses sha3 (256 bit) for normalize the size to 32
bytes and poly1305 algorithm for transform it."
  [^bytes key]
  (let [bkey (sha3-256 key)]
    (Poly1305KeyGenerator/clamp bkey)
    bkey))

(defn- make-poly1305-plain-impl
  [^bytes input ^bytes pkey ^bytes iv ^Keyword alg]
  (let [engine (resolve-engine alg)
        mac    (Poly1305. engine)
        out    (byte-array 16)
        kp     (KeyParameter. (key->poly1305key pkey))
        pwi    (ParametersWithIV. kp iv)]
    (doto mac
      (.init pwi)
      (.update input 0 (count input))
      (.doFinal out 0))
    out))

(defn- make-poly1305-stream-impl
  [^java.io.InputStream stream ^bytes pkey ^bytes iv ^Keyword alg]
  (let [engine (resolve-engine alg)
        mac    (Poly1305. engine)
        out    (byte-array 16)
        kp     (KeyParameter. (key->poly1305key pkey))
        pwi    (ParametersWithIV. kp iv)
        bfr    (byte-array 5120)]
    (.init mac pwi)
    (loop []
      (let [readed (.read stream bfr 0 5120)]
        (when-not (= readed -1)
          (.update mac bfr 0 readed)
          (recur))))
    (.doFinal mac out 0)
    out))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(declare make-poly1305)

(defn verify-poly1305-impl
  "Generic implementation of verify."
  [input ^bytes signature ^bytes pkey ^bytes iv ^Keyword alg]
  (let [sig (make-poly1305 input pkey iv alg)]
    (Arrays/equals sig signature)))

(defprotocol Poly1305Mac
  "Protocol that defines a low level interface
to poly 1305 algorithm and allows extend it for
different types.
It comes with default implementation for: string,
bytes, input stream, file, url and uri."
  (make-poly1305 [obj key iv alg] "Calculate poly1305 mac for type."))

(alter-meta! #'make-poly1305 assoc :no-doc true :private true)

(extend-protocol Poly1305Mac
  (Class/forName "[B")
  (make-poly1305 [^bytes input ^bytes key ^bytes iv ^Keyword alg]
    (make-poly1305-plain-impl input key iv alg))

  java.lang.String
  (make-poly1305 [^String input ^bytes key ^bytes iv ^Keyword alg]
    (make-poly1305-plain-impl (->byte-array input) key iv alg))

  java.io.InputStream
  (make-poly1305 [^java.io.InputStream input ^bytes key ^bytes iv ^Keyword alg]
    (make-poly1305-stream-impl input key iv alg))

  java.io.File
  (make-poly1305 [^java.io.File input ^bytes key ^bytes iv ^Keyword alg]
    (make-poly1305-stream-impl (io/input-stream input) key iv alg))

  java.net.URL
  (make-poly1305 [^java.net.URL input ^bytes key ^bytes iv ^Keyword alg]
    (make-poly1305-stream-impl (io/input-stream input) key iv alg))

  java.net.URI
  (make-poly1305 [^java.net.URI input ^bytes key ^bytes iv ^Keyword alg]
    (make-poly1305-stream-impl (io/input-stream input) key iv alg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn poly1305
  "Make poly1305 mac for specified data, using arbitrary
length key and 128 bits iv.
Key can be any type that implements ByteArray protocol."
  [input key ^bytes iv ^Keyword alg]
  {:pre [(= (count iv) 16)]}
  (let [key (->byte-array key)]
    (make-poly1305 input key iv alg)))

(defn verify
  "Verify poly1305 mac for specified data and signature."
  [input ^bytes signature pkey ^bytes iv ^Keyword alg]
  {:pre [(= (count iv) 16)]}
  (let [key (->byte-array pkey)]
    (verify-poly1305-impl input signature key iv alg)))
