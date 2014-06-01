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

(ns buddy.test-buddy-sign
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

(def secret "test")

(deftest buddy-sign-generic
  (testing "Signing/Unsigning with default keys"
    (let [signed (gsign/sign "foo" secret)]
      (Thread/sleep 1000)
      (is (not= (gsign/sign "foo" secret) signed))
      (is (= (gsign/unsign signed secret) "foo"))))

  (testing "Signing/Unsigning timestamped"
    (let [signed  (gsign/sign "foo" secret)
          result1 (gsign/unsign signed secret {:max-age 20})
          _       (Thread/sleep 700)
          result2 (gsign/unsign signed secret {:max-age -1})]
      (is (= "foo" result1))
      (is (nil? result2))))

  (testing "Try sing with invalid alg"
    (is (thrown? AssertionError (gsign/sign "foo" secret {:alg :invalid}))))

  (testing "Use custom algorithm for sign/unsign"
    (let [rsa-privkey (private-key "test/_files/privkey.3des.rsa.pem" "secret")
          rsa-pubkey  (public-key "test/_files/pubkey.3des.rsa.pem")
          signed      (gsign/sign "foo" rsa-privkey {:alg :rs256})]
      (Thread/sleep 20)
      (is (not= (gsign/sign "foo" rsa-privkey {:alg :rs256}) signed))
      (is (= "foo" (gsign/unsign signed rsa-pubkey {:alg :rs256})))
      (Thread/sleep 1000)
      (is (= nil (gsign/unsign signed rsa-pubkey {:alg :rs256 :max-age 1})))))

  (testing "Signing/Unsigning complex clojure data"
    (let [signed (gsign/dumps {:foo 2 :bar 1} secret)]
      (is (= {:foo 2 :bar 1} (gsign/loads signed secret)))))
)

