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
  (:import [org.bouncycastle.openssl PEMParser PEMEncryptedKeyPair PEMKeyPair]
           [org.bouncycastle.openssl.jcajce JcePEMDecryptorProviderBuilder JcaPEMKeyConverter]
           [java.io StringReader]))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defn read-pem->privkey
  [reader ^String passphrase]
  (let [parser    (PEMParser. reader)
        keypair   (.readObject parser)
        converter (doto (JcaPEMKeyConverter.)
                    (.setProvider "BC"))]
    (if (instance? PEMEncryptedKeyPair keypair)
      (let [builder   (JcePEMDecryptorProviderBuilder.)
            decryptor (.build builder (.toCharArray passphrase))]
        (->> (.decryptKeyPair keypair decryptor)
             (.getKeyPair converter)))
      (.getKeyPair converter keypair))))

(defn read-pem->pubkey
  [reader]
  (let [parser    (PEMParser. reader)
        keyinfo   (.readObject parser)
        converter (doto (JcaPEMKeyConverter.)
                    (.setProvider "BC"))]
    (.getPublicKey converter keyinfo)))

(defn private-key
  [^String path & [^String passphrase]]
  (with-open [reader (io/reader path)]
    (.getPrivate
      (read-pem->privkey reader passphrase))))

(defn public-key? [k]
  (let [t (type k)]
    (or (= org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey t)
        (= org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey t)
        (= org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey t))))

(defn public-key
  [^String path]
  (with-open [reader (io/reader path)]
    (read-pem->pubkey reader)))

(defn str->public-key
  [^String keydata]
  (with-open [reader (StringReader. keydata)]
    (read-pem->pubkey reader)))
