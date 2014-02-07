(ns buddy.test_buddy_auth
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [buddy.codecs :refer :all]
            [buddy.crypto.core :refer :all]
            [buddy.crypto.signing :as signing]
            [buddy.auth :refer [throw-notauthorized]]
            [buddy.auth.backends.httpbasic :refer [http-basic-backend parse-httpbasic-header]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.backends.stateless-token :as stoken]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-httpbasic-request
  [username, password]
  (if (and username password)
    {:headers {"authorization" (format "Basic %s" (str->base64 (format "%s:%s" username password)))}}
    {:headers {}}))

(defn httpbasic-auth-fn
  [request parsed-data]
  (let [username (:username parsed-data)]
    (cond
      (= username "foo") :foo)))

(def secret-key "test-secret-key")

(deftest http-basic-parse-test
  (testing "Parse httpbasic header from request"
    (let [header  (format "Basic %s" (str->base64 "foo:bar"))
          request {:headers {"authorization" header}}
          parsed  (parse-httpbasic-header request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar"))
      (is (= (:username parsed) "foo")))))

(deftest stateless-token-test
  (testing "Parse authorization header"
    (let [signed-data     (signing/dumps {:userid 1} secret-key)
          header-content  (format "Bearer %s" signed-data)
          request         {:headers {"authorization" header-content}}
          parsed          (stoken/parse-authorization-header request)]
      (is (= parsed signed-data))))

  (testing "Simple backend authentication 01"
    (let [signed-data     (signing/dumps {:userid 1} secret-key)
          header-content  (format "Bearer %s" signed-data)
          request         {:headers {"authorization" header-content}}
          backend         (stoken/stateless-token-backend secret-key)
          handler         (fn [req] req)
          handler         (wrap-authentication handler backend)
          resp            (handler request)]
      (is (= (:identity resp) {:userid 1}))))
  (testing "Simple backend authentication 02"
    (let [signed-data     (signing/dumps {:userid 1} "wrong-key")
          header-content  (format "Bearer %s" signed-data)
          request         {:headers {"authorization" header-content}}
          backend         (stoken/stateless-token-backend secret-key)
          handler         (fn [req] req)
          handler         (wrap-authentication handler backend)
          resp            (handler request)]
      (is (nil? (:identity resp))))))

(deftest session-auth-test
  (testing "Simple backend authentication 01"
    (let [request {:session {:identity {:userid 1}}}
          backend (session-backend)
          handler (fn [req] req)
          handler (wrap-authentication handler backend)
          resp    (handler request)]
      (is (= (:identity resp) {:userid 1}))))
  (testing "Simple backend authentication 01"
    (let [request {:session {}}
          backend (session-backend)
          handler (fn [req] req)
          handler (wrap-authentication handler backend)
          resp    (handler request)]
      (is (nil? (:identity resp))))))

(deftest authentication-middleware-test-with-httpbasic
  (testing "Auth middleware with http-basic backend 01"
    (let [backend (http-basic-backend :realm "Foo")
          handler (fn [req] req)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "user" "pass")
          resp    (handler req)]
        (is (nil? (:identity resp)))))

  (testing "Auth middleware with http-basic backend 02"
    (let [backend (http-basic-backend :realm "Foo" :authfn httpbasic-auth-fn)
          handler (fn [req] req)
          handler (wrap-authentication handler backend)]
      (let [req   (make-httpbasic-request "user" "pass")
            resp  (handler req)]
        (is (nil? (:identity resp))))
      (let [req   (make-httpbasic-request "foo" "pass")
            resp  (handler req)]
        (is (= (:identity resp) :foo))))))

(deftest authorization-middleware-test-with-httpbasic
  (testing "Authorization middleware tests 01 with httpbasic backend"
    (let [backend (http-basic-backend :realm "Foo" :authfn httpbasic-auth-fn)
          handler (fn [req] (if (nil? (:identity req))
                              (throw-notauthorized {:msg "FooMsg"})
                              req))
          handler (wrap-authorization handler backend)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "user" "pass")
          resp    (handler req)]
      (is (= (:status resp) 401))))
  (testing "Authorization middleware tests 02 with httpbasic backend"
    (let [backend (http-basic-backend :realm "Foo" :authfn httpbasic-auth-fn)
          handler (fn [req] (if (nil? (:identity req))
                              (throw-notauthorized {:msg "FooMsg"})
                              req))
          handler (wrap-authorization handler backend)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "foo" "pass")
          resp    (handler req)]
      (is (= (:identity resp) :foo))))
  (testing "Authorization middleware tests 03 with httpbasic backend"
    (let [backend (http-basic-backend :realm "Foo" :authfn httpbasic-auth-fn)
          handler (fn [req] (throw-notauthorized {:msg "FooMsg"}))
          handler (wrap-authorization handler backend)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "foo" "pass")
          resp    (handler req)]
      (is (= (:status resp) 403)))))
