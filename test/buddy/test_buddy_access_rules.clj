(ns buddy.test_buddy_access_rules
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [buddy.crypto.core :refer :all]
            [buddy.auth.accessrules :refer [compile-rule]]
            [buddy.auth :refer [throw-notauthorized]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-httpbasic-request
  [username, password]
  (if (and username password)
    {:headers {"authorization" (format "Basic %s" (str->base64 (format "%s:%s" username password)))}}
    {:headers {}}))

(defn mkhandler [value] (fn [_] value))

(deftest access-rules
  (testing "Compile simple rule"
    (let [shandler (fn [req] true)
          chandler (compile-rule shandler)]
      (is (true? (chandler nil)))))
  (testing "Compile simple or combinations"
    (let [handler1 (compile-rule {:or [(mkhandler true) (mkhandler false)]})
          handler2 (compile-rule {:or [(mkhandler false) (mkhandler false)]})
          handler3 (compile-rule {:or [(mkhandler true) (mkhandler true)]})]
      (is (true? (handler1 nil)))
      (is (false? (handler2 nil)))
      (is (true? (handler3 nil)))))
  (testing "Compile simple and combinations"
    (let [handler1 (compile-rule {:and [(mkhandler true) (mkhandler false)]})
          handler2 (compile-rule {:and [(mkhandler false) (mkhandler false)]})
          handler3 (compile-rule {:and [(mkhandler true) (mkhandler true)]})]
      (is (false? (handler1 nil)))
      (is (false? (handler2 nil)))
      (is (true? (handler3 nil)))))
  (testing "Compile nesting combinations"
    (let [handler1 (compile-rule {:and [(mkhandler true)
                                        {:or [(mkhandler false) (mkhandler true)]}]})
          handler2 (compile-rule {:and [(mkhandler true)
                                        {:or [(mkhandler false) (mkhandler false)]}]})]
      (is (true? (handler1 nil)))
      (is (false? (handler2 nil))))))
