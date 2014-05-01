(ns buddy.core.kdf
  "Key derivation function interface."
  (:require [buddy.core.hash :as hash])
  (:import org.bouncycastle.crypto.generators.KDF2BytesGenerator
           org.bouncycastle.crypto.generators.HKDFBytesGenerator
           org.bouncycastle.crypto.generators.KDFCounterBytesGenerator
           org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator
           org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator
           org.bouncycastle.crypto.params.HKDFParameters
           org.bouncycastle.crypto.Digest
           org.bouncycastle.crypto.digests.SHA256Digest
           org.bouncycastle.crypto.digests.SHA512Digest
           clojure.lang.IFn
           clojure.lang.Keyword))

(defprotocol KDFType
  "Generic type that unify access to any implementation
of kdf implemented in buddy."
  (generate-bytes! [obj length] "Generate bytes"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; HKDF interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrecord HKDF [digest impl]
  KDFType
  (generate-bytes! [obj length]
    (let [buffer (byte-array length)]
      (.generateBytes impl buffer 0 length)
      buffer)))

(alter-meta! #'->HKDF assoc :no-doc true :private true)
(alter-meta! #'map->HKDF assoc :no-doc true :private true)

(defn hkdf
  "HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented
according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM
Research &amp; P. Eronen, Nokia. It uses a HMac internally to compute de OKM
(output keying material) and is likely to have better security properties
than KDF's based on just a hash function."
  [^bytes keydata ^bytes salt ^bytes info ^Keyword alg]
  (let [params  (HKDFParameters. keydata salt info)
        digest  (hash/resolve-digest alg)
        kdfimpl (HKDFBytesGenerator. digest)]
    (.init kdfimpl params)
    (->HKDF digest kdfimpl)))
