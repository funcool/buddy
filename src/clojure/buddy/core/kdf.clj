(ns buddy.core.kdf
  "Key derivation function interface."
  (:require [buddy.core.hash :as hash])
  (:import org.bouncycastle.crypto.generators.KDF1BytesGenerator
           org.bouncycastle.crypto.generators.KDF2BytesGenerator
           org.bouncycastle.crypto.generators.HKDFBytesGenerator
           org.bouncycastle.crypto.generators.KDFCounterBytesGenerator
           org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator
           org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator
           org.bouncycastle.crypto.params.HKDFParameters
           org.bouncycastle.crypto.params.KDFParameters
           org.bouncycastle.crypto.params.KDFCounterParameters
           org.bouncycastle.crypto.params.KDFFeedbackParameters
           org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters
           org.bouncycastle.crypto.macs.HMac
           org.bouncycastle.crypto.Mac
           clojure.lang.Keyword))

(defprotocol KDFType
  "Generic type that unify access to any implementation
of kdf implemented in buddy."
  (generate-bytes! [obj length] "Generate bytes"))

(defn- generate-bytes-impl
  [impl length]
  (let [buffer (byte-array length)]
    (.generateBytes impl buffer 0 length)
    buffer))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; HKDF interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrecord HKDF [digest impl]
  KDFType
  (generate-bytes! [obj length] (generate-bytes-impl impl length)))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; KDF1/2 interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrecord KDF [digest impl]
  KDFType
  (generate-bytes! [obj length] (generate-bytes-impl impl length)))

(alter-meta! #'->HKDF assoc :no-doc true :private true)
(alter-meta! #'map->HKDF assoc :no-doc true :private true)

(defn kdf1
  "DF2 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033"
  [^bytes keydata ^bytes salt ^Keyword alg]
  (let [params  (KDFParameters. keydata salt)
        digest  (hash/resolve-digest alg)
        kdfimpl (KDF1BytesGenerator. digest)]
    (.init kdfimpl params)
    (->KDF digest kdfimpl)))

(defn kdf2
  "DF2 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033"
  [^bytes keydata ^bytes salt ^Keyword alg]
  (let [params  (KDFParameters. keydata salt)
        digest  (hash/resolve-digest alg)
        kdfimpl (KDF2BytesGenerator. digest)]
    (.init kdfimpl params)
    (->KDF digest kdfimpl)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Counter mode KDF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrecord CMKDF [mac salt r impl]
  KDFType
  (generate-bytes! [obj length] (generate-bytes-impl impl length)))

(alter-meta! #'->CMKDF assoc :no-doc true :private true)
(alter-meta! #'map->CMKDF assoc :no-doc true :private true)

(defn cmkdf
  "Counter mode KDF defined by the publicly available
NIST SP 800-108 specification."
  [^bytes keydata ^bytes salt ^Keyword alg & [{:keys [r] :or {r 32}}]]
  (let [params  (KDFCounterParameters. keydata salt r)
        digest  (hash/resolve-digest alg)
        mac     (HMac. digest)
        kdfimpl (KDFCounterBytesGenerator. mac)]
    (.init kdfimpl params)
    (->CMKDF mac salt r kdfimpl)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Feedback mode KDF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrecord FMKDF [mac salt r impl]
  KDFType
  (generate-bytes! [obj length] (generate-bytes-impl impl length)))

(alter-meta! #'->FMKDF assoc :no-doc true :private true)
(alter-meta! #'map->FMKDF assoc :no-doc true :private true)

(defn fmkdf
  "Counter mode KDF defined by the publicly available
NIST SP 800-108 specification."
  [^bytes keydata ^bytes salt ^Keyword alg & [{:keys [r use-counter] :or {r 32 use-counter true}}]]
  ;; KDFFeedbackParameters takes iv and salt as parameter but
  ;; at this momment, iv is totally ignored:
  ;; https://github.com/bcgit/bc-java/../generators/KDFFeedbackBytesGenerator.java#L137
  (let [params  (if use-counter
                  (KDFFeedbackParameters/createWithCounter keydata salt salt r)
                  (KDFFeedbackParameters/createWithoutCounter keydata salt salt))
        digest  (hash/resolve-digest alg)
        mac     (HMac. digest)
        kdfimpl (KDFFeedbackBytesGenerator. mac)]
    (.init kdfimpl params)
    (->CMKDF mac salt r kdfimpl)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Feedback mode KDF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrecord DPIMKDF [mac salt r impl]
  KDFType
  (generate-bytes! [obj length] (generate-bytes-impl impl length)))

(alter-meta! #'->DPIMKDF assoc :no-doc true :private true)
(alter-meta! #'map->DPIMKDF assoc :no-doc true :private true)

(defn dpimkdf
  "Double-Pipeline Iteration Mode KDF defined by the publicly
available NIST SP 800-108 specification."
  [^bytes keydata ^bytes salt ^Keyword alg & [{:keys [r use-counter] :or {r 32 use-counter true}}]]
  (let [params  (if use-counter
                  (KDFDoublePipelineIterationParameters/createWithCounter keydata salt r)
                  (KDFDoublePipelineIterationParameters/createWithoutCounter keydata salt))
        digest  (hash/resolve-digest alg)
        mac     (HMac. digest)
        kdfimpl (KDFDoublePipelineIterationBytesGenerator. mac)]
    (.init kdfimpl params)
    (->DPIMKDF mac salt r kdfimpl)))
