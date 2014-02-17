;; Copyright 2013 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.test_buddy_java_pbkdf2_class
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all])
  (:import (buddy.impl.pbkdf2 Pbkdf2)))


(deftest pbkdf2-java-class-tests
  (testing "Test derive key 01"
    (let [v "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
          k (Pbkdf2/deriveKey
             (str->bytes "password")
             (str->bytes "salt")
             1
             32)]
      (is (= (bytes->hex k) v))))
  (testing "Test derive key 02"
    (let [v "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
          k (Pbkdf2/deriveKey
             (str->bytes "password")
             (str->bytes "salt")
             2
             32)]
      (is (= (bytes->hex k) v))))
  (testing "Test derive key 03"
    (let [v "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
          k (Pbkdf2/deriveKey
             (str->bytes "password")
             (str->bytes "salt")
             4096
             32)]
      (is (= (bytes->hex k) v))))
  (testing "Test derive key 04"
    (let [v "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
          k (Pbkdf2/deriveKey
             (str->bytes "passwordPASSWORDpassword")
             (str->bytes "saltSALTsaltSALTsaltSALTsaltSALTsalt")
             4096
             40)]
      (is (= (bytes->hex k) v)))))
