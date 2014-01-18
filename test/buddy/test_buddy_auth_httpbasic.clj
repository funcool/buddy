(ns buddy.test_buddy_auth_httpbasic
  (:require [clojure.test :refer :all]
            [buddy.crypto.core :refer :all]
            [buddy.auth.backends.httpbasic :refer [parse-httpbasic-header]]))

(deftest http-basic-tests
  (testing "Parse httpbasic header from request"
    (let [header  (format "Basic %s" (str->base64 "foo:bar"))
          request {:headers {"authorization" header}}
          parsed  (parse-httpbasic-header request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar"))
      (is (= (:username parsed) "foo")))))
