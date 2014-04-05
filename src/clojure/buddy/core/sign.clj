;; Copyright 2014 Andrey Antukh <niwi@niwi.be>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-24
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-24
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-24

(ns buddy.core.sign
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.core.codecs :refer :all]
            [clojure.java.io :as io])
  (:import (java.security PublicKey PrivateKey)))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(def ^{:doc "Default buffer size for make signature of stream."
       :dynamic true}
  *default-buffer-size* 5120)

(def ^{:doc "List of officially supported algorithms by buddy."
       :dynamic true}
  *supported-algorithms* ["SHA256withRSAandMGF1" ;; rsassa-pss
                          "SHA384withRSAandMGF1"
                          "SHA512withRSAandMGF1"
                          "SHA1withRSAandMGF1"
                          "SHA256withRSA"        ;; rsassa-pkcs
                          "SHA384withRSA"
                          "SHA512withRSA"
                          "SHA256withECDSA"      ;; ecdsa
                          "SHA384withECDSA"
                          "SHA512withECDSA"])

;; (defn seq-contains?
;;   [coll target]
;;   (some #(= target %) coll))

;; (def ^{:doc "Dynamic var with secure random instance."
;;        :static true :dynamic true}
;;   *secure-random* (doto (java.security.SecureRandom.)
;;                     (.nextBytes (byte-array 0))))

(defn- make-signature-for-plain-data
  [^bytes data, pkey, ^String algorithm]
  (let [sig (doto (java.security.Signature/getInstance algorithm "BC")
              (.initSign pkey (java.security.SecureRandom.))
              (.update data))]
    (.sign sig)))

(defn- verify-signature-for-plain-data
  [^bytes data, ^bytes signature, pkey, ^String algorithm]
  (let [sig (doto (java.security.Signature/getInstance algorithm "BC")
              (.initVerify pkey)
              (.update data))]
    (.verify sig signature)))

(defn- make-signature-for-stream
  [^java.io.InputStream stream, pkey, ^String algorithm]
  (let [sig  (doto (java.security.Signature/getInstance algorithm "BC")
               (.initSign pkey (java.security.SecureRandom.)))
        buff (byte-array *default-buffer-size*)]
    (loop []
      (let [readed (.read stream buff 0 *default-buffer-size*)]
        (when-not (= readed -1)
          (.update sig buff 0 readed)
          (recur))))
    (.sign sig)))

(defn- verify-signature-for-stream
  [^java.io.InputStream stream, ^bytes signature, pkey, ^String algorithm]
  (let [sig  (doto (java.security.Signature/getInstance algorithm "BC")
               (.initVerify pkey))
        buff (byte-array *default-buffer-size*)]
    (loop []
      (let [readed (.read stream buff 0 *default-buffer-size*)]
        (when-not (= readed -1)
          (.update sig buff 0 readed)
          (recur))))
    (.verify sig signature)))

(defprotocol Signature
  (make-signature [data key algorithm] "")
  (verify-signature [data signature key algorithm] ""))

(extend-protocol Signature
  (Class/forName "[B")
  (make-signature [^bytes data, pkey, ^String algorithm]
    (make-signature-for-plain-data data pkey algorithm))
  (verify-signature [^bytes data, ^bytes signature, pkey, ^String algorithm]
    (verify-signature-for-plain-data data signature pkey algorithm))

  java.lang.String
  (make-signature [^String data, pkey, ^String algorithm]
    (make-signature-for-plain-data (->byte-array data) pkey algorithm))
  (verify-signature [^String data, ^bytes signature, pkey, ^String algorithm]
    (verify-signature-for-plain-data (->byte-array data) signature pkey algorithm))

  java.io.InputStream
  (make-signature [^java.io.InputStream stream, pkey, ^String algorithm]
    (make-signature-for-stream stream pkey algorithm))
  (verify-signature [^java.io.InputStream stream, ^bytes signature, pkey, ^String algorithm]
    (verify-signature-for-stream stream signature pkey algorithm))

  java.io.File
  (make-signature [^java.io.File stream, pkey, ^String algorithm]
    (make-signature-for-stream (io/input-stream stream) pkey algorithm))
  (verify-signature [^java.io.File stream, ^bytes signature, pkey, ^String algorithm]
    (verify-signature-for-stream (io/input-stream stream) signature pkey algorithm))

  java.net.URL
  (make-signature [^java.net.URL stream, pkey, ^String algorithm]
    (make-signature-for-stream (io/input-stream stream) pkey algorithm))
  (verify-signature [^java.net.URL stream, ^bytes signature, pkey, ^String algorithm]
    (verify-signature-for-stream (io/input-stream stream) signature pkey algorithm))

  java.net.URI
  (make-signature [^java.net.URI stream, pkey, ^String algorithm]
    (make-signature-for-stream (io/input-stream stream) pkey algorithm))
  (verify-signature [^java.net.URI stream, ^bytes signature, pkey, ^String algorithm]
    (verify-signature-for-stream (io/input-stream stream) signature pkey algorithm)))

;; RSASSA-PKCS1-V1_5 + sha2 aliases
(def rsassa-pkcs-sha256 #(make-signature %1 %2 "SHA256withRSA"))
(def rsassa-pkcs-sha384 #(make-signature %1 %2 "SHA384withRSA"))
(def rsassa-pkcs-sha512 #(make-signature %1 %2 "SHA512withRSA"))
(def rsassa-pkcs-sha256-verify #(verify-signature %1 %2 %3 "SHA256withRSA"))
(def rsassa-pkcs-sha384-verify #(verify-signature %1 %2 %3 "SHA384withRSA"))
(def rsassa-pkcs-sha512-verify #(verify-signature %1 %2 %3 "SHA512withRSA"))

;; RSASSA-PSS (With MGF1)
(def rsassa-pss-sha256 #(make-signature %1 %2 "SHA256withRSAandMGF1"))
(def rsassa-pss-sha384 #(make-signature %1 %2 "SHA384withRSAandMGF1"))
(def rsassa-pss-sha512 #(make-signature %1 %2 "SHA512withRSAandMGF1"))
(def rsassa-pss-sha256-verify #(verify-signature %1 %2 %3 "SHA256withRSAandMGF1"))
(def rsassa-pss-sha384-verify #(verify-signature %1 %2 %3 "SHA384withRSAandMGF1"))
(def rsassa-pss-sha512-verify #(verify-signature %1 %2 %3 "SHA512withRSAandMGF1"))

;; ECDSA + sha2 aliases
(def ecdsa-sha256 #(make-signature %1 %2 "SHA256withECDSA"))
(def ecdsa-sha384 #(make-signature %1 %2 "SHA384withECDSA"))
(def ecdsa-sha512 #(make-signature %1 %2 "SHA512withECDSA"))
(def ecdsa-sha256-verify #(verify-signature %1 %2 %3 "SHA256withECDSA"))
(def ecdsa-sha384-verify #(verify-signature %1 %2 %3 "SHA384withECDSA"))
(def ecdsa-sha512-verify #(verify-signature %1 %2 %3 "SHA512withECDSA"))
