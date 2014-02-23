(ns buddy.test_buddy_sign
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.sign.generic :as gsign]))

(def secret "test")

(deftest high-level-sign-tests
  (testing "Signing/Unsigning with default keys"
    (let [signed (gsign/sign "foo" secret)]
      (Thread/sleep 1000)
      (is (not= (gsign/sign "foo" secret) signed))
      (is (= (gsign/unsign signed secret) "foo"))))

  (testing "Signing/Unsigning timestamped"
    (let [signed (gsign/sign "foo" secret)]
      (is (= "foo" (gsign/unsign signed secret {:max-age 20})))
      (Thread/sleep 700)
      (is (nil? (gsign/unsign signed secret {:max-age -1})))))

  (testing "Signing/Unsigning complex clojure data"
    (let [signed (gsign/dumps {:foo 2 :bar 1} secret)]
      (is (= {:foo 2 :bar 1} (gsign/loads signed secret))))))

