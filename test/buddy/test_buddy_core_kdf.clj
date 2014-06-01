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

(ns buddy.test-buddy-core-kdf
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.keys :refer :all]
            [buddy.core.kdf :as kdf]
            [clojure.java.io :as io])
  (:import buddy.Arrays))

(deftest buddy-core-kdf
  (let [key1 (make-random-bytes 32)
        key2 (make-random-bytes 16)
        salt (make-random-bytes 8)
        info (make-random-bytes 8)]
    (testing "HKDF with sha256 with info"
      (let [generator1 (kdf/hkdf key1 salt info :sha256)
            generator2 (kdf/hkdf key1 salt info :sha256)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))
    (testing "HKDF with sha256 without info"
      (let [generator1 (kdf/hkdf key1 salt nil :sha256)
            generator2 (kdf/hkdf key1 salt nil :sha256)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))))

    (testing "KDF1 with sha512"
      (let [generator1 (kdf/kdf1 key1 salt :sha512)
            generator2 (kdf/kdf1 key1 salt :sha512)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "KDF2 with sha512"
      (let [generator1 (kdf/kdf2 key1 salt :sha512)
            generator2 (kdf/kdf2 key1 salt :sha512)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "CMKDF with sha3-512"
      (let [generator1 (kdf/cmkdf key1 salt :sha3-512)
            generator2 (kdf/cmkdf key1 salt :sha3-512)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "FMKDF with tiger"
      (let [generator1 (kdf/fmkdf key1 salt :tiger)
            generator2 (kdf/fmkdf key1 salt :tiger)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "DPIMKDF with sha3-256"
      (let [generator1 (kdf/dpimkdf key1 salt :sha3-256)
            generator2 (kdf/dpimkdf key1 salt :sha3-256)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))
))
