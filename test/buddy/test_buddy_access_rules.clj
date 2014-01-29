(ns buddy.test_buddy_access_rules
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [buddy.crypto.core :refer :all]
            [buddy.auth.accessrules :refer [compile-rule match-rules apply-rule]]
            [buddy.auth :refer [throw-notauthorized]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-httpbasic-request
  [username, password]
  (if (and username password)
    {:headers {"authorization" (format "Basic %s" (str->base64 (format "%s:%s" username password)))}}
    {:headers {}}))

(defn mkhandler [value] (fn [_] value))

(deftest access-rules-compile
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
      (is (false? (handler2 nil)))))
  (testing "Apply rule"
    (let [rule {:pattern #"^/foo.*"
                :handler {:or [(mkhandler true) (mkhandler false)]}}]
      (is (true? (apply-rule nil rule))))))

(deftest access-rules-match
  (let [rules [{:pattern #"^/foo.*" :val :foo}
               {:pattern #"^/bar.*" :val :bar}
               {:pattern #"^/baz.*" :val :baz}
               {:pattern #"^/(mm|ff)/.*" :val :mm}]]
    (testing "match rule 01"
      (let [req   {:uri "/mm/1"}
            match (match-rules req rules)]
        (is (= (:val match) :mm))))
    (testing "match rule 02"
      (let [req   {:uri "/ff/1"}
            match (match-rules req rules)]
        (is (= (:val match) :mm))))
    (testing "match rule 03"
      (let [req   {:uri "/foo1111"}
            match (match-rules req rules)]
        (is (= (:val match) :foo))))
    (testing "match rule 04"
      (let [req   {:uri "/bar"}
            match (match-rules req rules)]
        (is (= (:val match) :bar))))
    (testing "match rule 05"
      (let [req   {:uri "/baz"}
            match (match-rules req rules)]
        (is (= (:val match) :baz))))
    (testing "match rule 06"
      (let [req   {:uri "/rrr"}
            match (match-rules req rules)]
        (is (nil? match))))))
