(ns buddy.test_buddy_crypto_hashers
  (:require [clojure.test :refer :all]
            [buddy.codecs :as crypto]
            [buddy.crypto.hashers.pbkdf2 :as pbkdf2]
            [buddy.crypto.hashers.bcrypt :as bcrypt]
            [buddy.crypto.hashers.sha256 :as sha256]
            [buddy.crypto.hashers.md5 :as md5]
            [buddy.crypto.hashers.scrypt :as scrypt])
  (:import (java.util Arrays)))

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

