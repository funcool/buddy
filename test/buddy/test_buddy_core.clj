(ns buddy.test_buddy_core
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.hash :as hash]
            [buddy.core.hmac :refer [shmac-sha256]]
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

(deftest password-hashers-tests
  (testing "Test low level api for encrypt/verify pbkdf2"
    (let [plain-password      "my-test-password"
          encrypted-password  (pbkdf2/make-password plain-password)]
      (is (pbkdf2/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify sha256"
    (let [plain-password      "my-test-password"
          encrypted-password  (sha256/make-password plain-password)]
      (is (sha256/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify md5"
    (let [plain-password      "my-test-password"
          encrypted-password  (md5/make-password plain-password)]
      (is (md5/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify bcrypt"
    (let [plain-password      "my-test-password"
          encrypted-password  (bcrypt/make-password plain-password)]
      (is (bcrypt/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify scrypt"
    (let [plain-password      "my-test-password"
          encrypted-password  (scrypt/make-password plain-password)]
      (is (scrypt/check-password plain-password encrypted-password)))))

(deftest core-hash-tests
  (testing "SHA3 support test"
    (let [plain-text "FooBar"
          hashed     (-> (hash/sha3-256 plain-text)
                         (bytes->hex))]
      (is (= hashed "0a3c119a02a37e50fbaf8a3776559c76de7a969097c05bd0f41f60cf25210745"))))
  (testing "File hashing"
    (let [path       "test/_files/pubkey.ecdsa.pem"
          valid-hash "7aa01e35e65701c9a9d8f71c4cbf056acddc9be17fdff06b4c7af1b0b34ddc29"]
      (is (= (bytes->hex (hash/sha256 (io/input-stream path))) valid-hash)))))
