(ns buddy.test_buddy_crypto_core
  (:require [clojure.test :refer :all]
            [buddy.codecs :as codecs]
            [buddy.crypto.core :refer :all]
            [buddy.crypto.signing :as signing])
  (:import (java.util Arrays)))

(def secret "test")

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

(deftest sign-tests
  (testing "Signing/Unsigning with default keys"
    (let [signed (signing/sign "foo" secret)]
      (Thread/sleep 1000)
      (is (not= (signing/sign "foo" secret) signed))
      (is (= (signing/unsign signed secret) "foo"))))

  (testing "Signing/Unsigning timestamped"
    (let [signed (signing/sign "foo" secret)]
      (is (= "foo" (signing/unsign signed secret {:max-age 20})))
      (Thread/sleep 700)
      (is (nil? (signing/unsign signed secret {:max-age -1})))))

  (testing "Signing/Unsigning complex clojure data"
    (let [signed (signing/dumps {:foo 2 :bar 1} secret)]
      (is (= {:foo 2 :bar 1} (signing/loads signed secret))))))


(deftest crypto-tests
  (testing "Sha256 digest"
    (let [bt (byte-array 0)
          dg (sha256 bt)
          hx (codecs/bytes->hex dg)]
      (is (= hx "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))))

