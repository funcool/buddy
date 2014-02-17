(ns buddy.test_buddy_core
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs]
            [buddy.core.hash :refer [sha256]]
            [buddy.hashers.pbkdf2 :as pbkdf2]
            [buddy.hashers.bcrypt :as bcrypt]
            [buddy.hashers.sha256 :as sha256]
            [buddy.hashers.md5 :as md5]
            [buddy.hashers.scrypt :as scrypt])
  (:import (java.util Arrays)))

(deftest codecs-test
  (testing "Hex encode/decode 01"
    (let [some-bytes  (codecs/str->bytes "FooBar")
          encoded     (codecs/bytes->hex some-bytes)
          decoded     (codecs/hex->bytes encoded)
          some-str    (codecs/bytes->str decoded)]
      (is (Arrays/equals decoded, some-bytes))
      (is (= some-str "FooBar"))))
  (testing "Hex encode/decode 02"
    (let [mybytes (into-array Byte/TYPE (range 10))
          encoded (codecs/bytes->hex mybytes)
          decoded (codecs/hex->bytes encoded)]
      (is (Arrays/equals decoded mybytes)))))

(deftest crypto-tests
  (testing "Sha256 digest"
    (let [bt (byte-array 0)
          dg (sha256 bt)]
      (is (= dg "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))))

(deftest pbkdf2-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (pbkdf2/make-password plain-password)]
      (is (pbkdf2/check-password plain-password encrypted-password)))))

(deftest sha256-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (sha256/make-password plain-password)]
      (is (sha256/check-password plain-password encrypted-password)))))

(deftest md5-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (md5/make-password plain-password)]
      (is (md5/check-password plain-password encrypted-password)))))

(deftest bcrypt-tests
  (testing "Test low level api for encrypt/verify"
    (let [plain-password      "my-test-password"
          encrypted-password  (bcrypt/make-password plain-password)]
      (is (bcrypt/check-password plain-password encrypted-password)))))

(deftest scrypt-tests
  (testing "Test low level api for encrypt/verify 01"
    (let [plain-password      "my-test-password"
          encrypted-password  (scrypt/make-password plain-password)]
      (is (scrypt/check-password plain-password encrypted-password)))))

