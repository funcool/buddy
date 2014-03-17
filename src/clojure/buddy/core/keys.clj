;; Copyright 2013 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.core.keys
  (:require [buddy.core.codecs :refer [str->bytes bytes->hex]]
            [clojure.java.io :as io])
  (:import [org.bouncycastle.openssl PasswordFinder PEMReader]
           [java.io StringReader]))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defprotocol ISecretKey
  (key->bytes [key] "Normalize key to byte array")
  (key->str [key] "Normalize key String"))

(extend-protocol ISecretKey
  (Class/forName "[B")
  (key->bytes [it] it)
  (key->str [it] (bytes->hex it))

  String
  (key->bytes [key] (str->bytes key))
  (key->str [key] key))

(defn read-pem->key
  [reader passphrase]
  (if passphrase
    (let [password-finder (reify PasswordFinder
                            (getPassword [this] (.toCharArray passphrase)))]
      (.readObject (PEMReader. reader password-finder)))
    (.readObject (PEMReader. reader))))

(defn private-key
  [^String path & [passphrase]]
  (with-open [reader (io/reader path)]
    (.getPrivate
      (read-pem->key reader passphrase))))

(defn public-key? [k]
  (let [t (type k)]
    (or (= org.bouncycastle.jce.provider.JCERSAPublicKey t)
        (= org.bouncycastle.jce.provider.JDKDSAPublicKey t)
        (= org.bouncycastle.jce.provider.JCEECPublicKey t))))

(defn public-key
  [^String path & [passphrase]]
  (with-open [reader (io/reader path)]
    (let [res (read-pem->key reader passphrase)]
      (if (public-key? res) res
        (.getPublic res)))))

(defn str->public-key
  [^String keydata & [passphrase]]
  (with-open [reader (StringReader. keydata)]
    (let [res (read-pem->key reader passphrase)]
      (if (public-key? res) res
        (.getPublic res)))))
