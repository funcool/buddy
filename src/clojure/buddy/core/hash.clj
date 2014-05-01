(ns buddy.core.hash
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.core.codecs :refer :all]
            [clojure.java.io :as io])
  (:import org.bouncycastle.crypto.Digest
           org.bouncycastle.crypto.digests.SHA1Digest
           org.bouncycastle.crypto.digests.TigerDigest
           org.bouncycastle.crypto.digests.MD5Digest
           org.bouncycastle.crypto.digests.SHA3Digest
           org.bouncycastle.crypto.digests.SHA256Digest
           org.bouncycastle.crypto.digests.SHA384Digest
           org.bouncycastle.crypto.digests.SHA512Digest
           clojure.lang.IFn
           clojure.lang.Keyword))


(def ^{:doc "Available digests."
       :dynamic true}
  *available-digests* {:sha256   #(SHA256Digest.)
                       :sha384   #(SHA384Digest.)
                       :sha512   #(SHA512Digest.)
                       :sha1     #(SHA1Digest.)
                       :tiger    #(TigerDigest.)
                       :md5      #(MD5Digest.)
                       :sha3-256 #(SHA3Digest. 256)
                       :sha3-384 #(SHA3Digest. 284)
                       :sha3-512 #(SHA3Digest. 512)})

(defn resolve-digest
  "Helper function for make Digest instances
from algorithm parameter."
  [alg]
  (cond
   (instance? Keyword alg) (let [factory (*available-digests* alg)]
                             (factory))
   (instance? IFn alg) (alg)
   (instance? Digest alg) alg))

;; (java.security.Security/addProvider
 ;; (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defprotocol DigestType
  (make-digest [input algorithm] "Low level interface, always returns bytes"))

(alter-meta! #'make-digest assoc :no-doc true :private true)

(extend-protocol DigestType
  (Class/forName "[B")
  (make-digest [^bytes input ^Keyword alg]
    (let [digest (resolve-digest alg)
          buffer (byte-array (.getDigestSize digest))]
      (.update digest input 0 (count input))
      (.doFinal digest buffer 0)
      buffer))

  String
  (make-digest [^String input ^Keyword alg]
    (make-digest (->byte-array input) alg))

  java.io.InputStream
  (make-digest [^java.io.InputStream input ^Keyword alg]
    (let [digest  (resolve-digest alg)
          buffer1 (byte-array 5120)
          buffer2 (byte-array (.getDigestSize digest))]
      (loop []
        (let [readed (.read input buffer1 0 5120)]
          (when-not (= readed -1)
            (.update digest buffer1 0 readed)
            (recur))))
      (.doFinal digest buffer2 0)
      buffer2))

  java.io.File
  (make-digest [^java.io.File input ^Keyword alg]
    (make-digest (io/input-stream input) alg))

  java.net.URL
  (make-digest [^java.net.URL input ^Keyword alg]
    (make-digest (io/input-stream input) alg))

  java.net.URI
  (make-digest [^java.net.URI input ^Keyword alg]
    (make-digest (io/input-stream input) alg)))

(defn digest
  "Generic function for create cryptographic hash."
  [input ^Keyword alg]
  (make-digest input alg))

(def sha256 #(digest % :sha256))
(def sha384 #(digest % :sha384))
(def sha512 #(digest % :sha512))
(def sha3-256 #(digest % :sha3-256))
(def sha3-384 #(digest % :sha3-384))
(def sha3-512 #(digest % :sha3-512))
(def sha1 #(digest % :sha1))
(def md5 #(digest % :md5))

