(ns buddy.test_buddy_core
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.hash :as hash]
            [buddy.core.hmac :refer [salted-hmac-sha256]]
            [buddy.hashers.pbkdf2 :as pbkdf2]
            [buddy.hashers.bcrypt :as bcrypt]
            [buddy.hashers.sha256 :as sha256]
            [buddy.hashers.md5 :as md5]
            [buddy.hashers.scrypt :as scrypt]
            [clojure.java.io :as io])
  (:import (java.util Arrays)))

(deftest codecs-test
  (testing "Hex encode/decode 01"
    (let [some-bytes  (str->bytes "FooBar")
          encoded     (bytes->hex some-bytes)
          decoded     (hex->bytes encoded)
          some-str    (bytes->str decoded)]
      (is (Arrays/equals decoded, some-bytes))
      (is (= some-str "FooBar"))))
  (testing "Hex encode/decode 02"
    (let [mybytes (into-array Byte/TYPE (range 10))
          encoded (bytes->hex mybytes)
          decoded (hex->bytes encoded)]
      (is (Arrays/equals decoded mybytes)))))

(deftest crypto-tests
  (testing "Sha256 digest"
    (let [bt (byte-array 0)
          dg (hash/sha256 bt)]
      (is (= dg "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))))

(deftest hmac-tests
  (testing "hmac-sha256 tests"
    (let [key  "foo"
          data "bar"]
      (is (= (salted-hmac-sha256 data "" key)
             "58f125164e3664184898939740cd369130bca60e1f66a4dbe241f494b6403a5f")))))

(deftest hashers-pbkdf2-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (pbkdf2/make-password plain-password)]
      (is (pbkdf2/check-password plain-password encrypted-password)))))

(deftest hashers-sha256-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (sha256/make-password plain-password)]
      (is (sha256/check-password plain-password encrypted-password)))))

(deftest hashers-md5-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (md5/make-password plain-password)]
      (is (md5/check-password plain-password encrypted-password)))))

(deftest hashers-bcrypt-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (bcrypt/make-password plain-password)]
      (is (bcrypt/check-password plain-password encrypted-password)))))

(deftest hashers-scrypt-tests
  (testing "Test low level api for encrypt/verify 01"
    (let [plain-password      "my-test-password"
          encrypted-password  (scrypt/make-password plain-password)]
      (is (scrypt/check-password plain-password encrypted-password)))))

(deftest core-hash-tests
  (testing "SHA3 support test"
    (let [plain-text "FooBar"
          hashed     (hash/sha3-256 plain-text)]
      (is (= hashed "0a3c119a02a37e50fbaf8a3776559c76de7a969097c05bd0f41f60cf25210745"))))
  (testing "File hashing"
    (let [path       "test/_files/pubkey.ecdsa.pem"
          valid-hash "7aa01e35e65701c9a9d8f71c4cbf056acddc9be17fdff06b4c7af1b0b34ddc29"]
      (is (= (hash/sha256 (io/input-stream path)) valid-hash)))))
