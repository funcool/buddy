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

(ns buddy.core.sign.impl
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.sign.proto :as proto]
            [clojure.java.io :as io])
  (:import java.security.PublicKey
           java.security.PrivateKey
           java.security.Signature
           clojure.lang.Keyword
           clojure.lang.IFn))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(def ^{:doc "Default buffer size for make signature of stream."
       :dynamic true}
  *default-buffer-size* 5120)

(def ^{:doc "Supported digital signature algorithms"
       :dynamic true}
  *supported-algorithms* {:rsassa-pss-sha256    #(Signature/getInstance "SHA256withRSAandMGF1" "BC")
                          :rsassa-pss-sha384    #(Signature/getInstance "SHA384withRSAandMGF1" "BC")
                          :rsassa-pss-sha512    #(Signature/getInstance "SHA512withRSAandMGF1" "BC")
                          :rsassa-pkcs15-sha256 #(Signature/getInstance "SHA256withRSA" "BC")
                          :rsassa-pkcs15-sha384 #(Signature/getInstance "SHA384withRSA" "BC")
                          :rsassa-pkcs15-sha512 #(Signature/getInstance "SHA512withRSA" "BC")
                          :ecdsa-sha256         #(Signature/getInstance "SHA256withECDSA" "BC")
                          :ecdsa-sha384         #(Signature/getInstance "SHA384withECDSA" "BC")
                          :ecdsa-sha512         #(Signature/getInstance "SHA512withECDSA" "BC")})

(defn- resolve-signer
  "Given dynamic type engine, try resolve it to
valid engine instance. By default accepts keywords
and functions."
  [signer]
  (cond
   (instance? Keyword signer) (let [factory (signer *supported-algorithms*)] (factory))
   (instance? IFn signer) (signer)))

(defn- make-signature-for-plain-data
  [^bytes input, pkey, ^Keyword alg]
  (let [signer (resolve-signer alg)
        srng   (java.security.SecureRandom.)]
    (.initSign signer pkey srng)
    (.update signer input)
    (.sign signer)))

(defn- verify-signature-for-plain-data
  [^bytes input, ^bytes signature, pkey, ^Keyword alg]
  (let [signer (resolve-signer alg)]
    (.initVerify signer pkey)
    (.update signer input)
    (.verify signer signature)))

(defn- make-signature-for-stream
  [^java.io.InputStream stream, pkey, ^Keyword alg]
  (let [signer (resolve-signer alg)
        srng   (java.security.SecureRandom.)
        buff   (byte-array *default-buffer-size*)]
    (.initSign signer pkey srng)
    (loop []
      (let [readed (.read stream buff 0 *default-buffer-size*)]
        (when-not (= readed -1)
          (.update signer buff 0 readed)
          (recur))))
    (.sign signer)))

(defn- verify-signature-for-stream
  [^java.io.InputStream stream, ^bytes signature, pkey, ^Keyword alg]
  (let [signer (resolve-signer alg)
        buff   (byte-array *default-buffer-size*)]
    (.initVerify signer pkey)
    (loop []
      (let [readed (.read stream buff 0 *default-buffer-size*)]
        (when-not (= readed -1)
          (.update signer buff 0 readed)
          (recur))))
    (.verify signer signature)))

(extend-protocol proto/Signature
  (Class/forName "[B")
  (make-signature [^bytes input, pkey, ^Keyword alg]
    (make-signature-for-plain-data input pkey alg))
  (verify-signature [^bytes input, ^bytes signature, pkey, ^Keyword alg]
    (verify-signature-for-plain-data input signature pkey alg))

  java.lang.String
  (make-signature [^String input, pkey, ^Keyword alg]
    (make-signature-for-plain-data (->byte-array input) pkey alg))
  (verify-signature [^String input, ^bytes signature, pkey, ^Keyword alg]
    (verify-signature-for-plain-data (->byte-array input) signature pkey alg))

  java.io.InputStream
  (make-signature [^java.io.InputStream input, pkey, ^Keyword alg]
    (make-signature-for-stream input pkey alg))
  (verify-signature [^java.io.InputInput input, ^bytes signature, pkey, ^Keyword alg]
    (verify-signature-for-stream input signature pkey alg))

  java.io.File
  (make-signature [^java.io.File input, pkey, ^Keyword alg]
    (make-signature-for-stream (io/input-stream input) pkey alg))
  (verify-signature [^java.io.File input, ^bytes signature, pkey, ^Keyword alg]
    (verify-signature-for-stream (io/input-stream input) signature pkey alg))

  java.net.URL
  (make-signature [^java.net.URL input, pkey, ^Keyword alg]
    (make-signature-for-stream (io/input-stream input) pkey alg))
  (verify-signature [^java.net.URL input, ^bytes signature, pkey, ^Keyword alg]
    (verify-signature-for-stream (io/input-stream input) signature pkey alg))

  java.net.URI
  (make-signature [^java.net.URI input, pkey, ^Keyword alg]
    (make-signature-for-stream (io/input-stream input) pkey alg))
  (verify-signature [^java.net.URI input, ^bytes signature, pkey, ^Keyword alg]
    (verify-signature-for-stream (io/input-stream input) signature pkey alg)))

