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
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-24
;; - http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-24

(ns buddy.core.sign
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.core.codecs :refer :all])
  (:import (java.security Signature SecureRandom PublicKey PrivateKey)))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(def ^:private ^:static
  rsassa-pss-algorithms ["SHA256withRSAandMGF1"
                         "SHA384withRSAandMGF1"
                         "SHA512withRSAandMGF1"
                         "SHA1withRSAandMGF1"])

(def ^:private ^:static
  rsassa-pkcs-algorithms ["SHA256withRSA"
                          "SHA384withRSA"
                          "SHA512withRSA"])

(def ^:private ^:static
  ecdsa-algorithms ["SHA256withECDSA"
                    "SHA384withECDSA"
                    "SHA512withECDSA"])

(defn seq-contains?
  [coll target]
  (some #(= target %) coll))

(defn rsassa-pkcs
  "This section defines the implementation of the RSASSA-PKCS1-V1_5 digital
signature algorithm as defined in Section 8.2 of RFC 3447 [RFC3447]
commonly known as PKCS #1, using SHA-2 hash functions."
  [^String algorithm, value, ^PrivateKey pkey]
  {:pre [(seq-contains? rsassa-pkcs-algorithms algorithm)]}
  (let [sig (doto (Signature/getInstance algorithm "BC")
              (.initSign pkey (java.security.SecureRandom.))
              (.update (->byte-array value)))]
    (.sign sig)))

(defn rsassa-pkcs-verify
  "Function that provides a signature verification  for the RSASSA-PKCS1-V1_5
digital signature algorithm."
  [^String algorithm, value, ^bytes signature, ^PublicKey pkey]
  {:pre [(seq-contains? rsassa-pkcs-algorithms algorithm)]}
  (let [sig (doto (Signature/getInstance algorithm "BC")
              (.initVerify pkey)
              (.update (->byte-array value)))]
    (.verify sig signature)))

(defn ecdsa
  "This function implements the Elliptic Curve Digital Signature Algorithm
(ECDSA) interface. ECDSA provides equivalent security to RSA cryptography
but using shorter key sizes and with greater processing speed."
  [^String algorithm, value pkey]
  {:pre [(seq-contains? ecdsa-algorithms algorithm)]}
  (let [sig (doto (Signature/getInstance algorithm "BC")
              (.initSign pkey)
              (.update (->byte-array value)))]
    (.sign sig)))

(defn ecdsa-verify
  "Function that provides a signature verification for Elliptic Curve
Digital Signature Algorithm (ECDSA)"
  [^String algorithm, value, ^bytes signature, pkey]
  {:pre [(seq-contains? ecdsa-algorithms algorithm)]}
  (let [sig (doto (Signature/getInstance algorithm "BC")
              (.initVerify pkey)
              (.update (->byte-array value)))]
    (.verify sig signature)))

(defn rsassa-pss
  "This section implements the RSASSA-PSS digital signature
algorithm interface as defined in Section 8.1 of RFC 3447 with
MGF1 mark generation function and SHA-2 hash functions."
  [^String algorithm, value pkey]
  {:pre [(seq-contains? rsassa-pss-algorithms algorithm)]}
  (let [sig (doto (Signature/getInstance algorithm "BC")
              (.initSign pkey)
              (.update (->byte-array value)))]
    (.sign sig)))

(defn rsassa-pss-verify
  "Function that provides a signature verification for Elliptic Curve
Digital Signature Algorithm (ECDSA)"
  [^String algorithm, value, ^bytes signature, pkey]
  {:pre [(seq-contains? rsassa-pss-algorithms algorithm)]}
  (let [sig (doto (Signature/getInstance algorithm "BC")
              (.initVerify pkey)
              (.update (->byte-array value)))]
    (.verify sig signature)))

;; RSASSA-PKCS1-V1_5 + sha2 aliases
(def rsassa-pkcs-sha256 (partial rsassa-pkcs "SHA256withRSA"))
(def rsassa-pkcs-sha384 (partial rsassa-pkcs "SHA384withRSA"))
(def rsassa-pkcs-sha512 (partial rsassa-pkcs "SHA512withRSA"))
(def rsassa-pkcs-verify-sha256 (partial rsassa-pkcs-verify "SHA256withRSA"))
(def rsassa-pkcs-verify-sha384 (partial rsassa-pkcs-verify "SHA384withRSA"))
(def rsassa-pkcs-verify-sha512 (partial rsassa-pkcs-verify "SHA512withRSA"))

;; RSASSA-PSS (With MGF1)
(def rsassa-pss-sha256 (partial rsassa-pss "SHA256withRSAandMGF1"))
(def rsassa-pss-sha384 (partial rsassa-pss "SHA384withRSAandMGF1"))
(def rsassa-pss-sha512 (partial rsassa-pss "SHA512withRSAandMGF1"))
(def rsassa-pss-verify-sha256 (partial rsassa-pss-verify "SHA256withRSAandMGF1"))
(def rsassa-pss-verify-sha384 (partial rsassa-pss-verify "SHA384withRSAandMGF1"))
(def rsassa-pss-verify-sha512 (partial rsassa-pss-verify "SHA512withRSAandMGF1"))

;; ECDSA + sha2 aliases
(def ecdsa-sha256 (partial ecdsa "SHA256withECDSA"))
(def ecdsa-sha384 (partial ecdsa "SHA384withECDSA"))
(def ecdsa-sha512 (partial ecdsa "SHA512withECDSA"))
(def ecdsa-verify-sha256 (partial ecdsa-verify "SHA256withECDSA"))
(def ecdsa-verify-sha384 (partial ecdsa-verify "SHA384withECDSA"))
(def ecdsa-verify-sha512 (partial ecdsa-verify "SHA512withECDSA"))
