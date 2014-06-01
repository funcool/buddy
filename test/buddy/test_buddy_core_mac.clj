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

(ns buddy.test-buddy-core-mac
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.keys :refer :all]
            [buddy.core.mac.poly1305 :as poly]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.mac.shmac :as shmac]
            [clojure.java.io :as io])
  (:import buddy.Arrays))

(deftest buddy-core-mac-hmac
  (let [secretkey "my.secret.key"
        path      "test/_files/pubkey.ecdsa.pem"]

    (testing "Multiple sign using hmac sha256"
      (is (Arrays/equals (hmac/hmac "foo" secretkey :sha256)
                         (hmac/hmac "foo" secretkey :sha256))))

    (testing "Sign/Verify string"
      (let [sig (hmac/hmac "foo" secretkey :sha384)]
        (is (true? (hmac/verify "foo" sig secretkey :sha384)))))

    (testing "Sign/Verify input stream"
      (let [sig (hmac/hmac (io/input-stream path) secretkey :sha512)]
        (is (true? (hmac/verify (io/input-stream path) sig secretkey :sha512)))))

    (testing "Sign/Verify file"
      (let [sig (hmac/hmac (java.io.File. path) secretkey :sha512)]
        (is (true? (hmac/verify (java.io.File. path) sig secretkey :sha512)))))

    (testing "Sign/Verify url"
      (let [sig (hmac/hmac (.toURL (java.io.File. path)) secretkey :sha512)]
        (is (true? (hmac/verify (.toURL (java.io.File. path)) sig secretkey :sha512)))))

    (testing "Sign/Verify uri"
      (let [sig (hmac/hmac (.toURI (java.io.File. path)) secretkey :sha512)]
        (is (true? (hmac/verify (.toURI (java.io.File. path)) sig secretkey :sha512)))))

    (testing "Sign/Verify salted hmac with string"
      (let [sig (shmac/shmac "foo" secretkey "salt" :sha256)]
        (is (true? (shmac/verify "foo" sig secretkey "salt" :sha256)))))))

(deftest buddy-core-mac-poly1305
  (let [iv        (byte-array 16) ;; 16 bytes array filled with 0
        plaintext "text"
        secretkey "secret"]
    (testing "Poly1305 encrypt/verify (using string key)"
      (let [mac-bytes1 (poly/poly1305 plaintext secretkey iv :aes)
            mac-bytes2 (poly/poly1305 plaintext secretkey iv :aes)]
      (is (= (Arrays/equals mac-bytes1 mac-bytes2)))))

  (testing "Poly1305 explicit encrypt/verify (using string key)"
    (let [mac-bytes1 (poly/poly1305 plaintext secretkey iv :aes)]
      (is (= (-> mac-bytes1 (bytes->hex)) "98a94ff88861bf9b96bcb7112b506579"))))

  (testing "File mac"
    (let [path       "test/_files/pubkey.ecdsa.pem"
          macbytes   (poly/poly1305 (io/input-stream path) secretkey iv :aes)]
      (is (poly/verify (io/input-stream path) macbytes secretkey iv :aes))))

  (testing "Poly1305-AES enc/verify using key with good iv"
    (let [iv1      (make-random-bytes 16)
          iv2      (make-random-bytes 16)
          macbytes (poly/poly1305 plaintext secretkey iv1 :aes)]
      (is (poly/verify plaintext macbytes secretkey iv1 :aes))
      (is (not (poly/verify plaintext macbytes secretkey iv2 :aes)))))

  (testing "Poly1305-Twofish env/verify"
    (let [iv2 (make-random-bytes 16)
          signature (poly/poly1305 plaintext secretkey iv2 :twofish)]
      (is (poly/verify plaintext signature secretkey iv2 :twofish))
      (is (not (poly/verify plaintext signature secretkey iv :twofish)))))

  (testing "Poly1305-Serpent env/verify"
    (let [iv2 (make-random-bytes 16)
          signature (poly/poly1305 plaintext secretkey iv2 :serpent)]
      (is (poly/verify plaintext signature secretkey iv2 :serpent))
      (is (not (poly/verify plaintext signature secretkey iv :serpent)))))))
