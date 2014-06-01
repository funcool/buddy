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

(ns buddy.test-buddy-core-sign
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.keys :refer :all]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.mac.shmac :as shmac]
            [buddy.core.sign.rsapss :as rsapss]
            [buddy.core.sign.rsapkcs15 :as rsapkcs]
            [buddy.core.sign.ecdsa :as ecdsa]
            [buddy.sign.generic :as gsign]
            [clojure.java.io :as io])
  (:import java.util.Arrays))

(deftest low-level-sign
  (let [rsa-privkey (private-key "test/_files/privkey.3des.rsa.pem" "secret")
        rsa-pubkey  (public-key "test/_files/pubkey.3des.rsa.pem")
        ec-privkey  (private-key "test/_files/privkey.ecdsa.pem")
        ec-pubkey   (public-key "test/_files/pubkey.ecdsa.pem")]

    (testing "Multiple sign using rsassa-pkcs"
      (is (Arrays/equals (rsapkcs/rsapkcs15 "foobar" rsa-privkey :sha256)
                         (rsapkcs/rsapkcs15 "foobar" rsa-privkey :sha256))))

    (testing "Sign/Verify using rsassa-pkcs"
      (let [signature (rsapkcs/rsapkcs15 "foobar" rsa-privkey :sha256)]
        (is (true? (rsapkcs/verify "foobar" signature rsa-pubkey :sha256)))))

    (testing "Multiple sign using rsassa-pss"
      (is (false? (Arrays/equals (rsapss/rsapss "foobar" rsa-privkey :sha256)
                                 (rsapss/rsapss "foobar" rsa-privkey :sha256)))))

    (testing "Sign/Verify using rsassa-pss"
      (let [signature (rsapss/rsapss "foobar" rsa-privkey :sha256)]
        (is (true? (rsapss/verify "foobar" signature rsa-pubkey :sha256)))))

    (testing "Multiple sign using ecdsa"
      (is (false? (Arrays/equals (ecdsa/ecdsa "foobar" ec-privkey :sha256)
                                 (ecdsa/ecdsa "foobar" ec-privkey :sha256)))))

    (testing "Sign/Verify using ecdsa"
      (let [signature (ecdsa/ecdsa "foobar" ec-privkey :sha256)]
        (is (true? (ecdsa/verify "foobar" signature ec-pubkey :sha256)))))

    (testing "Sign/Verify input stream"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (ecdsa/ecdsa(io/input-stream path) ec-privkey :sha256)]
        (is (true? (ecdsa/verify (io/input-stream path) sig ec-pubkey :sha256)))))

    (testing "Sign/Verify file"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (ecdsa/ecdsa (java.io.File. path) ec-privkey :sha256)]
        (is (true? (ecdsa/verify (java.io.File. path) sig ec-pubkey :sha256)))))

    (testing "Sign/Verify url"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (ecdsa/ecdsa (.toURL (java.io.File. path)) ec-privkey :sha512)]
        (is (true? (ecdsa/verify (.toURL (java.io.File. path)) sig ec-pubkey :sha512)))))

    (testing "Sign/Verify uri"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (ecdsa/ecdsa (.toURI (java.io.File. path)) ec-privkey :sha512)]
        (is (true? (ecdsa/verify (.toURI (java.io.File. path)) sig ec-pubkey :sha512)))))))
