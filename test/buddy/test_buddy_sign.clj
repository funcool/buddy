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
            [buddy.sign.generic :as gsign]
            [buddy.sign.jws :as jws]
            [clj-time.coerce :as jodac]
            [clj-time.core :as jodat]
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
      (is (= {:foo 2 :bar 1} (gsign/loads signed secret))))))

(deftest buddy-sign-jws
  (let [plainkey "secret"]
    (testing "Pass exp as claim or parameter shoult return same result"
      (let [candidate1 {"iss" "joe" :exp 1300819380}
            candidate2 {"iss" "joe"}
            result1    (jws/sign candidate1 plainkey)
            result2    (jws/sign candidate2 plainkey {:exp 1300819380})]
        (is (= result1 result2))))

    (testing "Unsing simple jws"
      (let [candidate1 {:foo "bar"}
            signed1    (jws/sign candidate1 plainkey)
            unsigned1   (jws/unsign signed1 plainkey)]
        (is (= unsigned1 candidate1))))

    (testing "Unsigning jws with exp"
      (let [candidate1 {:foo "bar"}
            now        (-> (jodat/now) (jws/to-timestamp))
            exp        (+ now 2)
            signed1    (jws/sign candidate1 plainkey {:exp exp})]
        (let [unsigned1 (jws/unsign signed1 plainkey)]
          (is (= unsigned1 (assoc candidate1 :exp exp))))
        (Thread/sleep 2100)
        (let [unsigned1 (jws/unsign signed1 plainkey)]
          (is (nil? unsigned1)))))

    (testing "Unsigning jws with nbf"
      (let [candidate1 {:foo "bar"}
            now        (-> (jodat/now) (jws/to-timestamp))
            nbf        (+ now 2)
            signed1    (jws/sign candidate1 plainkey {:nbf nbf})]
        (let [unsigned1 (jws/unsign signed1 plainkey)]
          (is (= unsigned1 (assoc candidate1 :nbf nbf))))
        (Thread/sleep 2100)
        (let [unsigned1 (jws/unsign signed1 plainkey)]
          (is (nil? unsigned1)))))
))

